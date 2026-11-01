// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * DNS capture via cgroup skb hooks attached to the root cgroup v2.
 *
 * Every UDP packet to/from port 53 of any socket on the node (any network
 * namespace) is copied (first 512 bytes of payload) into a ring buffer
 * together with the socket's cgroup id. User space parses queries/answers,
 * matches them and computes latency, rcodes, ndots waste and an IP->name cache.
 *
 * The programs never drop traffic: they always return 1 (allow).
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_UDP 17
#define DNS_PORT 53
#define DNS_MAX 512

struct dns_event {
	__u64 ts;
	__u64 cgroup;
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u16 len;
	__u8 egress;
	__u8 family;
	__u8 data[DNS_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} dns_events SEC(".maps");

const struct dns_event *unused_dns_event __attribute__((unused));

static __always_inline int handle(struct __sk_buff *skb, __u8 egress)
{
	struct dns_event *ev;
	struct udphdr udp;
	__u32 l4, plen;
	__u8 family;
	__u8 saddr[16], daddr[16];

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr iph;

		if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)))
			return 1;
		if (iph.protocol != IPPROTO_UDP)
			return 1;
		if (iph.frag_off & bpf_htons(0x1fff))
			return 1;
		l4 = iph.ihl * 4;
		family = AF_INET;
		ip4_to_16(saddr, iph.saddr);
		ip4_to_16(daddr, iph.daddr);
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;

		if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)))
			return 1;
		if (ip6.nexthdr != IPPROTO_UDP)
			return 1;
		l4 = sizeof(ip6);
		family = AF_INET6;
		__builtin_memcpy(saddr, &ip6.saddr, 16);
		__builtin_memcpy(daddr, &ip6.daddr, 16);
	} else {
		return 1;
	}

	if (bpf_skb_load_bytes(skb, l4, &udp, sizeof(udp)))
		return 1;
	if (udp.source != bpf_htons(DNS_PORT) && udp.dest != bpf_htons(DNS_PORT))
		return 1;

	plen = bpf_ntohs(udp.len);
	if (plen <= sizeof(udp))
		return 1;
	plen -= sizeof(udp);
	if (plen > skb->len - l4 - sizeof(udp))
		plen = skb->len - l4 - sizeof(udp);

	ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
	if (!ev)
		return 1;

	ev->ts = bpf_ktime_get_ns();
	ev->cgroup = bpf_skb_cgroup_id(skb);
	__builtin_memcpy(ev->saddr, saddr, 16);
	__builtin_memcpy(ev->daddr, daddr, 16);
	ev->sport = bpf_ntohs(udp.source);
	ev->dport = bpf_ntohs(udp.dest);
	ev->egress = egress;
	ev->family = family;
	ev->len = plen;

	if (plen > DNS_MAX)
		plen = DNS_MAX;
	if (plen < 12) {
		bpf_ringbuf_discard(ev, 0);
		return 1;
	}
	/* bound for the verifier */
	plen &= 0x3ff;
	if (plen > DNS_MAX || plen == 0) {
		bpf_ringbuf_discard(ev, 0);
		return 1;
	}
	if (bpf_skb_load_bytes(skb, l4 + sizeof(udp), ev->data, plen)) {
		bpf_ringbuf_discard(ev, 0);
		return 1;
	}
	bpf_ringbuf_submit(ev, 0);
	return 1;
}

SEC("cgroup_skb/egress")
int dns_egress(struct __sk_buff *skb)
{
	return handle(skb, 1);
}

SEC("cgroup_skb/ingress")
int dns_ingress(struct __sk_buff *skb)
{
	return handle(skb, 0);
}
