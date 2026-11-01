// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * VoIP (SIP + RTP) monitoring via cgroup skb hooks on the root cgroup v2.
 *
 * SIP: UDP/TCP packets to/from the configured SIP ports (default 5060 and
 * 5080, FreeSWITCH internal/external profiles) are copied (first 1024 bytes
 * of payload) to a ring buffer; user space parses them into transactions
 * (setup latency, response codes, calls).
 *
 * RTP: media packets are far too frequent to copy (50/s per stream and
 * direction), so UDP packets on the configured RTP port range (default
 * 16384-32768, FreeSWITCH's rtp-start/end-port) that look like RTP are
 * aggregated in-kernel per (cgroup, SSRC, direction): packets, sequence
 * tracking for loss and reordering (RFC 3550 A.1) and interarrival jitter
 * (RFC 3550 A.8) for inbound streams. User space reads the counters.
 *
 * The programs never drop traffic: they always return 1 (allow).
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SIP_MAX 1024
#define RTP_MAX_DROPOUT 3000
#define RTP_MAX_MISORDER 100

/* Set by user space before loading. */
volatile const __u16 sip_ports[4] = {5060, 5080, 0, 0};
volatile const __u16 rtp_lo = 16384;
volatile const __u16 rtp_hi = 32768;

struct sip_event {
	__u64 ts;
	__u64 cgroup;
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u16 len;
	__u8 egress;
	__u8 proto;
	__u8 data[SIP_MAX];
};

struct rtp_key {
	__u64 cgroup;
	__u32 ssrc;
	__u8 egress;
	__u8 pad[3];
};

struct rtp_val {
	__u64 packets;
	__u64 bytes;
	__u64 ooo;          /* late / duplicate packets */
	__u64 resets;       /* sequence jumps treated as a new source */
	__u64 last_arrival; /* ns */
	__u64 jitter_ns;    /* RFC 3550 interarrival jitter */
	__u64 jitter_max_ns;
	__u64 last_seen;
	__u32 cycles;       /* sequence wrap-arounds << 16 */
	__u32 base_seq;
	__u32 last_rtp_ts;
	__u16 max_seq;
	__u16 lport;
	__u16 rport;
	__u8 pt;
	__u8 init;
	__u8 raddr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} sip_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct rtp_key);
	__type(value, struct rtp_val);
} rtp_streams SEC(".maps");

/* RTP clock rate per payload type (Hz); 0 = 8000. Filled from SDP. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, __u32);
} pt_clock SEC(".maps");

const struct sip_event *unused_sip_event __attribute__((unused));
const struct rtp_key *unused_rtp_key __attribute__((unused));
const struct rtp_val *unused_rtp_val __attribute__((unused));

static __always_inline int is_sip_port(__u16 p)
{
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (sip_ports[i] && sip_ports[i] == p)
			return 1;
	}
	return 0;
}

static __always_inline void sip_capture(struct __sk_buff *skb, __u32 off, __u32 plen, __u8 *saddr, __u8 *daddr,
					__u16 sport, __u16 dport, __u8 egress, __u8 proto)
{
	struct sip_event *ev;

	if (plen < 12)
		return;
	ev = bpf_ringbuf_reserve(&sip_events, sizeof(*ev), 0);
	if (!ev)
		return;
	ev->ts = bpf_ktime_get_ns();
	ev->cgroup = bpf_skb_cgroup_id(skb);
	__builtin_memcpy(ev->saddr, saddr, 16);
	__builtin_memcpy(ev->daddr, daddr, 16);
	ev->sport = sport;
	ev->dport = dport;
	ev->egress = egress;
	ev->proto = proto;
	ev->len = plen;
	if (plen > SIP_MAX)
		plen = SIP_MAX;
	plen = ((plen - 1) & (SIP_MAX - 1)) + 1; /* 1..SIP_MAX for the verifier */
	if (bpf_skb_load_bytes(skb, off, ev->data, plen)) {
		bpf_ringbuf_discard(ev, 0);
		return;
	}
	bpf_ringbuf_submit(ev, 0);
}

static __always_inline void rtp_account(struct __sk_buff *skb, __u32 off, __u32 plen, __u8 *raddr, __u16 lport,
					__u16 rport, __u8 egress)
{
	__u8 hdr[12];
	struct rtp_key key = {};
	struct rtp_val *v;
	__u64 now;
	__u16 seq, udelta;
	__u32 ts;
	__u8 pt;

	if (plen < 12 || bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)))
		return;
	if ((hdr[0] >> 6) != 2)
		return; /* not RTP version 2 */
	pt = hdr[1] & 0x7f;
	if (pt >= 72 && pt <= 76)
		return; /* RTCP (SR/RR/SDES/BYE/APP) */
	if (pt > 34 && pt < 96)
		return; /* unassigned: not RTP */
	seq = ((__u16)hdr[2] << 8) | hdr[3];
	ts = ((__u32)hdr[4] << 24) | ((__u32)hdr[5] << 16) | ((__u32)hdr[6] << 8) | hdr[7];

	key.cgroup = bpf_skb_cgroup_id(skb);
	key.ssrc = ((__u32)hdr[8] << 24) | ((__u32)hdr[9] << 16) | ((__u32)hdr[10] << 8) | hdr[11];
	key.egress = egress;
	now = bpf_ktime_get_ns();

	v = bpf_map_lookup_elem(&rtp_streams, &key);
	if (!v) {
		struct rtp_val init = {};

		init.init = 1;
		init.base_seq = seq;
		init.max_seq = seq;
		init.last_arrival = now;
		init.last_rtp_ts = ts;
		init.packets = 1;
		init.bytes = plen;
		init.last_seen = now;
		init.pt = pt;
		init.lport = lport;
		init.rport = rport;
		__builtin_memcpy(init.raddr, raddr, 16);
		bpf_map_update_elem(&rtp_streams, &key, &init, BPF_NOEXIST);
		return;
	}
	v->packets++;
	v->bytes += plen;
	v->last_seen = now;
	v->pt = pt;
	if (egress)
		return; /* loss and jitter are measured by the receiver */

	udelta = seq - v->max_seq;
	if (udelta == 0) {
		v->ooo++; /* duplicate */
		return;
	}
	if (udelta < RTP_MAX_DROPOUT) {
		if (seq < v->max_seq)
			v->cycles += 65536;
		v->max_seq = seq;
	} else if (udelta <= 65535 - RTP_MAX_MISORDER) {
		/* big jump: the source restarted; resynchronise */
		v->resets++;
		v->base_seq = seq;
		v->max_seq = seq;
		v->cycles = 0;
		v->last_arrival = now;
		v->last_rtp_ts = ts;
		return;
	} else {
		v->ooo++; /* late packet: no jitter sample */
		return;
	}

	/* jitter: D = (Rj - Ri) - (Sj - Si), in ns */
	{
		__u32 key_pt = pt;
		__u32 *clk = bpf_map_lookup_elem(&pt_clock, &key_pt);
		__u64 rate = (clk && *clk) ? *clk : 8000;
		__s32 dts = (__s32)(ts - v->last_rtp_ts);
		__u64 arr = now - v->last_arrival;
		__u64 sent, d;

		v->last_arrival = now;
		v->last_rtp_ts = ts;
		if (dts < 0 || (__u32)dts > rate * 2)
			return; /* timestamp jump (silence suppression, DTMF, restart) */
		sent = (__u64)(__u32)dts * 1000000000ULL / rate;
		d = arr > sent ? arr - sent : sent - arr;
		if (d > 1000000000ULL)
			return;
		if (d > v->jitter_ns)
			v->jitter_ns += (d - v->jitter_ns) >> 4;
		else
			v->jitter_ns -= (v->jitter_ns - d) >> 4;
		if (v->jitter_ns > v->jitter_max_ns)
			v->jitter_max_ns = v->jitter_ns;
	}
}

static __always_inline int handle(struct __sk_buff *skb, __u8 egress)
{
	__u32 l4, len = skb->len;
	__u8 proto;
	__u8 saddr[16], daddr[16];
	__u16 sport, dport;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr iph;

		if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)))
			return 1;
		if (iph.frag_off & bpf_htons(0x1fff))
			return 1;
		proto = iph.protocol;
		l4 = iph.ihl * 4;
		ip4_to_16(saddr, iph.saddr);
		ip4_to_16(daddr, iph.daddr);
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;

		if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)))
			return 1;
		proto = ip6.nexthdr;
		l4 = sizeof(ip6);
		__builtin_memcpy(saddr, &ip6.saddr, 16);
		__builtin_memcpy(daddr, &ip6.daddr, 16);
	} else {
		return 1;
	}
	if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
		return 1;

	if (proto == IPPROTO_UDP) {
		struct udphdr udp;
		__u32 plen;

		if (bpf_skb_load_bytes(skb, l4, &udp, sizeof(udp)))
			return 1;
		sport = bpf_ntohs(udp.source);
		dport = bpf_ntohs(udp.dest);
		if (len < l4 + sizeof(udp))
			return 1;
		plen = len - l4 - sizeof(udp);
		if (is_sip_port(sport) || is_sip_port(dport)) {
			sip_capture(skb, l4 + sizeof(udp), plen, saddr, daddr, sport, dport, egress, proto);
			return 1;
		}
		{
			__u16 lport = egress ? sport : dport;
			__u16 rport = egress ? dport : sport;

			if (lport >= rtp_lo && lport <= rtp_hi)
				rtp_account(skb, l4 + sizeof(udp), plen, egress ? daddr : saddr, lport, rport, egress);
		}
		return 1;
	}

	/* SIP over TCP: best effort, one message per segment */
	{
		struct tcphdr tcp;
		__u8 b12;
		__u32 doff;

		if (bpf_skb_load_bytes(skb, l4, &tcp, sizeof(tcp)))
			return 1;
		sport = bpf_ntohs(tcp.source);
		dport = bpf_ntohs(tcp.dest);
		if (!is_sip_port(sport) && !is_sip_port(dport))
			return 1;
		if (bpf_skb_load_bytes(skb, l4 + 12, &b12, 1))
			return 1;
		doff = (b12 >> 4) * 4;
		if (doff < 20 || len <= l4 + doff)
			return 1;
		sip_capture(skb, l4 + doff, len - l4 - doff, saddr, daddr, sport, dport, egress, proto);
	}
	return 1;
}

SEC("cgroup_skb/egress")
int voip_egress(struct __sk_buff *skb)
{
	return handle(skb, 1);
}

SEC("cgroup_skb/ingress")
int voip_ingress(struct __sk_buff *skb)
{
	return handle(skb, 0);
}
