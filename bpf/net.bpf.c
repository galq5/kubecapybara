// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * TCP pod-to-pod observability.
 *
 * Aggregates per (client ip, server ip, server port, observing side, local cgroup):
 *   - smoothed RTT histogram (sampled at most every 100ms per socket)
 *   - connect latency histogram (client side)
 *   - bytes, connections, lifetimes (churn)
 *   - refused connections, connect timeouts, SYN retransmits
 *   - retransmits (and "large segment" retransmits as an MTU hint), resets
 *
 * Also emits ring buffer events for listen() calls and for connect attempts
 * made by "young" cgroups (containers that just started) to build startup
 * timelines.
 *
 * Everything essential is built on tracepoints (inet_sock_set_state,
 * tcp_probe, tcp_retransmit_skb, tcp_receive_reset, tcp_send_reset) so it works
 * on kernels without kprobes/ftrace. Byte counters are derived from the
 * per-socket tcp_sock::bytes_acked / bytes_received deltas instead of hooking
 * the hot tcp_sendmsg/tcp_recvmsg paths. Kprobes are only used for optional
 * extras (MTU events, connect() errno).
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define IPPROTO_TCP 6

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_TIME_WAIT 6
#define TCP_CLOSE 7
#define TCP_LISTEN 10
#define TCP_NEW_SYN_RECV 12

#define ROLE_CLIENT 1
#define ROLE_SERVER 2

#define RTT_SAMPLE_NS (100ULL * 1000 * 1000)
#define LARGE_SEGMENT 1200

#define EV_LISTEN 1
#define EV_CONNECT_START 2
#define EV_CONNECT_DONE 3
#define EV_UNLISTEN 4

struct pair_key {
	__u8 saddr[16]; /* client */
	__u8 daddr[16]; /* server */
	__u64 cgroup;   /* cgroup of the local socket */
	__u16 dport;    /* server port */
	__u8 side;      /* ROLE_CLIENT: we observed from the client socket */
	__u8 _pad[5];
};

struct pair_val {
	struct hist rtt;
	struct hist connlat;
	__u64 bytes_tx;
	__u64 bytes_rx;
	__u64 connects;
	__u64 closes;
	__u64 lifetime_us;
	__u64 refused;
	__u64 timeouts;
	__u64 syn_retrans;
	__u64 retrans;
	__u64 retrans_large;
	__u64 rst_sent;
	__u64 rst_rcvd;
	__u64 mtu_reduced;
};

struct sk_info {
	__u64 start_ns;
	__u64 est_ns;
	__u64 last_rtt_ns;
	__u64 last_acked;
	__u64 last_rcvd;
	__u8 role;
	__u8 got_rst;
	__u8 traced;
	__u8 syn_retrans;
	__u8 has_key;
	__u8 _pad[3];
	/* cached once known: some fields (e.g. the local port of accepted
	 * sockets) are already cleared when TCP_CLOSE is reported */
	struct pair_key key;
};

struct conn_err_key {
	__u64 cgroup;
	__s32 err;
	__u32 _pad;
};

struct net_event {
	__u64 ts;
	__u64 cgroup;
	__u32 pid;
	__u32 latency_us;
	__s32 result;
	__u16 port;
	__u8 type;
	__u8 family;
	__u8 addr[16];
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct pair_key);
	__type(value, struct pair_val);
} pairs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pair_val);
} zero_pair SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct sk_info);
} socks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct conn_err_key);
	__type(value, __u64);
} conn_errs SEC(".maps");

/* cgroups that started recently; written by user space (value = expiry ktime ns) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} young SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

/* force BTF emission for user space type generation */
const struct net_event *unused_net_event __attribute__((unused));

static __always_inline void sk_local_remote(struct sock *sk, __u16 family, __u8 *laddr, __u8 *raddr)
{
	if (family == AF_INET) {
		ip4_to_16(laddr, BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
		ip4_to_16(raddr, BPF_CORE_READ(sk, __sk_common.skc_daddr));
	} else {
		BPF_CORE_READ_INTO(laddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(raddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

static __always_inline __u8 heuristic_role(struct sock *sk)
{
	__u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	__u16 rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	return lport < rport ? ROLE_SERVER : ROLE_CLIENT;
}

static __always_inline int build_key(struct sock *sk, __u8 role, struct pair_key *key)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
	__u8 laddr[16], raddr[16];
	__u16 lport, rport;

	if (family != AF_INET && family != AF_INET6)
		return -1;

	__builtin_memset(key, 0, sizeof(*key));
	sk_local_remote(sk, family, laddr, raddr);
	lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	if (role == ROLE_CLIENT) {
		__builtin_memcpy(key->saddr, laddr, 16);
		__builtin_memcpy(key->daddr, raddr, 16);
		key->dport = rport;
	} else {
		__builtin_memcpy(key->saddr, raddr, 16);
		__builtin_memcpy(key->daddr, laddr, 16);
		key->dport = lport;
	}
	key->side = role;
	/* request/timewait socks are not full sockets: no cgroup data */
	if (state != TCP_TIME_WAIT && state != TCP_NEW_SYN_RECV)
		key->cgroup = sock_cgroup_id(sk);
	return 0;
}

static __always_inline struct pair_val *pair_get(struct pair_key *key)
{
	struct pair_val *v;
	__u32 zero = 0;

	v = bpf_map_lookup_elem(&pairs, key);
	if (v)
		return v;
	v = bpf_map_lookup_elem(&zero_pair, &zero);
	if (!v)
		return 0;
	bpf_map_update_elem(&pairs, key, v, BPF_NOEXIST);
	return bpf_map_lookup_elem(&pairs, key);
}

static __always_inline struct sk_info *sk_info_get(struct sock *sk, int create)
{
	__u64 skp = (__u64)sk;
	struct sk_info *info, fresh = {};

	info = bpf_map_lookup_elem(&socks, &skp);
	if (info || !create)
		return info;
	fresh.role = heuristic_role(sk);
	fresh.last_acked = BPF_CORE_READ((struct tcp_sock *)sk, bytes_acked);
	fresh.last_rcvd = BPF_CORE_READ((struct tcp_sock *)sk, bytes_received);
	bpf_map_update_elem(&socks, &skp, &fresh, BPF_NOEXIST);
	return bpf_map_lookup_elem(&socks, &skp);
}

static __always_inline struct pair_val *pair_for_sock(struct sock *sk, __u8 role)
{
	struct pair_key key;

	if (build_key(sk, role, &key))
		return 0;
	return pair_get(&key);
}

static __always_inline struct pair_val *pair_for_info(struct sock *sk, struct sk_info *info)
{
	if (!info->has_key) {
		if (build_key(sk, info->role, &info->key))
			return 0;
		info->has_key = 1;
	}
	return pair_get(&info->key);
}

static __always_inline struct pair_val *pair_for(struct sock *sk, struct sk_info *info)
{
	if (info)
		return pair_for_info(sk, info);
	return pair_for_sock(sk, heuristic_role(sk));
}

static __always_inline void flush_bytes(struct sock *sk, struct sk_info *info, struct pair_val *val)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	__u64 acked = BPF_CORE_READ(tp, bytes_acked);
	__u64 rcvd = BPF_CORE_READ(tp, bytes_received);

	if (acked > info->last_acked)
		__sync_fetch_and_add(&val->bytes_tx, acked - info->last_acked);
	if (rcvd > info->last_rcvd)
		__sync_fetch_and_add(&val->bytes_rx, rcvd - info->last_rcvd);
	info->last_acked = acked;
	info->last_rcvd = rcvd;
}

static __always_inline void emit_listen(struct sock *sk, __u8 type)
{
	struct net_event *ev;
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u8 raddr[16];

	ev = bpf_ringbuf_reserve(&net_events, sizeof(*ev), 0);
	if (!ev)
		return;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ts = bpf_ktime_get_ns();
	ev->type = type;
	ev->family = family;
	/* the closing context may differ from the owner: use the socket's cgroup */
	ev->cgroup = type == EV_LISTEN ? bpf_get_current_cgroup_id() : sock_cgroup_id(sk);
	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->port = BPF_CORE_READ(sk, __sk_common.skc_num);
	sk_local_remote(sk, family, ev->addr, raddr);
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	bpf_ringbuf_submit(ev, 0);
}

static __always_inline void emit_connect(struct sock *sk, __u8 type, __s32 result, __u32 lat_us, __u64 cgroup)
{
	struct net_event *ev;
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u8 laddr[16];

	ev = bpf_ringbuf_reserve(&net_events, sizeof(*ev), 0);
	if (!ev)
		return;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ts = bpf_ktime_get_ns();
	ev->cgroup = cgroup;
	ev->type = type;
	ev->family = family;
	ev->result = result;
	ev->latency_us = lat_us;
	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	sk_local_remote(sk, family, laddr, ev->addr);
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	bpf_ringbuf_submit(ev, 0);
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_state, struct sock *sk, int oldstate, int newstate)
{
	__u64 skp = (__u64)sk;
	__u64 now = bpf_ktime_get_ns();
	struct sk_info *info;
	struct pair_val *val;
	__u16 family;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	if (newstate == TCP_LISTEN) {
		emit_listen(sk, EV_LISTEN);
		return 0;
	}
	if (oldstate == TCP_LISTEN) {
		emit_listen(sk, EV_UNLISTEN);
		return 0;
	}

	if (newstate == TCP_SYN_SENT) {
		struct sk_info fresh = {};
		__u64 cg = bpf_get_current_cgroup_id();
		__u64 *exp = bpf_map_lookup_elem(&young, &cg);

		fresh.start_ns = now;
		fresh.role = ROLE_CLIENT;
		if (exp && *exp > now) {
			fresh.traced = 1;
			emit_connect(sk, EV_CONNECT_START, 0, 0, cg);
		}
		bpf_map_update_elem(&socks, &skp, &fresh, BPF_ANY);
		return 0;
	}

	if (newstate == TCP_SYN_RECV) {
		struct sk_info fresh = {};

		/* No start_ns: the child socket is only created when the final ACK
		 * arrives (the request lives in TCP_NEW_SYN_RECV before), so
		 * SYN_RECV->ESTABLISHED is not the handshake time. Connect latency
		 * is a client-side metric. */
		fresh.role = ROLE_SERVER;
		bpf_map_update_elem(&socks, &skp, &fresh, BPF_ANY);
		return 0;
	}

	if (newstate == TCP_ESTABLISHED) {
		info = sk_info_get(sk, 1);
		if (!info)
			return 0;
		info->est_ns = now;
		val = pair_for_info(sk, info);
		if (!val)
			return 0;
		__sync_fetch_and_add(&val->connects, 1);
		if (info->start_ns) {
			__u64 lat = (now - info->start_ns) / 1000;

			hist_add(&val->connlat, lat);
			if (info->traced)
				emit_connect(sk, EV_CONNECT_DONE, 0, lat, sock_cgroup_id(sk));
		}
		return 0;
	}

	if (newstate == TCP_CLOSE) {
		info = bpf_map_lookup_elem(&socks, &skp);
		if (!info)
			return 0;
		val = pair_for_info(sk, info);
		if (val) {
			if (oldstate == TCP_SYN_SENT) {
				__s32 res = info->got_rst ? -111 /* ECONNREFUSED */ : -110 /* ETIMEDOUT */;

				if (info->got_rst)
					__sync_fetch_and_add(&val->refused, 1);
				else
					__sync_fetch_and_add(&val->timeouts, 1);
				if (info->traced)
					emit_connect(sk, EV_CONNECT_DONE, res, (now - info->start_ns) / 1000,
						     sock_cgroup_id(sk));
			} else if (info->est_ns) {
				flush_bytes(sk, info, val);
				__sync_fetch_and_add(&val->closes, 1);
				__sync_fetch_and_add(&val->lifetime_us, (now - info->est_ns) / 1000);
			}
		}
		bpf_map_delete_elem(&socks, &skp);
	}
	return 0;
}

/* tcp_probe fires at the start of tcp_rcv_established() for every segment
 * received on an established socket. */
SEC("tp_btf/tcp_probe")
int BPF_PROG(on_tcp_probe, struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct sk_info *info;
	struct pair_val *val;
	__u64 now = bpf_ktime_get_ns();
	__u32 srtt;

	info = sk_info_get(sk, 1);
	if (!info)
		return 0;
	if (now - info->last_rtt_ns < RTT_SAMPLE_NS)
		return 0;
	info->last_rtt_ns = now;

	val = pair_for_info(sk, info);
	if (!val)
		return 0;
	flush_bytes(sk, info, val);
	srtt = BPF_CORE_READ(tp, srtt_us) >> 3;
	if (srtt)
		hist_add(&val->rtt, srtt);
	return 0;
}

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(on_retransmit, struct sock *sk, struct sk_buff *skb)
{
	__u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
	__u64 skp = (__u64)sk;
	struct sk_info *info;
	struct pair_val *val;

	info = bpf_map_lookup_elem(&socks, &skp);
	if (state == TCP_SYN_SENT && info)
		info->syn_retrans++;
	val = pair_for(sk, info);
	if (!val)
		return 0;
	if (state == TCP_SYN_SENT) {
		__sync_fetch_and_add(&val->syn_retrans, 1);
		return 0;
	}
	__sync_fetch_and_add(&val->retrans, 1);
	if (BPF_CORE_READ(skb, len) >= LARGE_SEGMENT)
		__sync_fetch_and_add(&val->retrans_large, 1);
	return 0;
}

SEC("tp_btf/tcp_receive_reset")
int BPF_PROG(on_receive_reset, struct sock *sk)
{
	__u64 skp = (__u64)sk;
	struct sk_info *info = bpf_map_lookup_elem(&socks, &skp);
	struct pair_val *val;

	if (info)
		info->got_rst = 1;
	val = pair_for(sk, info);
	if (val)
		__sync_fetch_and_add(&val->rst_rcvd, 1);
	return 0;
}

SEC("tp_btf/tcp_send_reset")
int BPF_PROG(on_send_reset, struct sock *sk, struct sk_buff *skb)
{
	__u64 skp = (__u64)sk;
	struct sk_info *info;
	struct pair_val *val;

	if (!sk)
		return 0;
	info = bpf_map_lookup_elem(&socks, &skp);
	val = pair_for(sk, info);
	if (val)
		__sync_fetch_and_add(&val->rst_sent, 1);
	return 0;
}

SEC("kprobe/tcp_v4_mtu_reduced")
int BPF_KPROBE(on_mtu_reduced, struct sock *sk)
{
	__u64 skp = (__u64)sk;
	struct sk_info *info = bpf_map_lookup_elem(&socks, &skp);
	struct pair_val *val;

	val = pair_for(sk, info);
	if (val)
		__sync_fetch_and_add(&val->mtu_reduced, 1);
	return 0;
}

static __always_inline int count_connect_err(int ret)
{
	struct conn_err_key key = {};
	__u64 one = 1, *cnt;

	if (ret >= 0)
		return 0;
	key.cgroup = bpf_get_current_cgroup_id();
	key.err = ret;
	cnt = bpf_map_lookup_elem(&conn_errs, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else
		bpf_map_update_elem(&conn_errs, &key, &one, BPF_NOEXIST);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(on_v4_connect_ret, int ret)
{
	return count_connect_err(ret);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(on_v6_connect_ret, int ret)
{
	return count_connect_err(ret);
}
