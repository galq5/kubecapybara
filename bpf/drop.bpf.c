// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Packet drops with kernel drop reasons (Linux 5.17+).
 *
 * Counts dropped packets per (src ip, dst ip, dst port, l4 proto, reason).
 * "Not specified" drops are ignored: they are dominated by normal frees and
 * would only add noise.
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

struct drop_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__u32 reason;
	__u16 dport;
	__u8 proto;
	__u8 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct drop_key);
	__type(value, __u64);
} drops SEC(".maps");

SEC("tp_btf/kfree_skb")
int BPF_PROG(on_kfree_skb, struct sk_buff *skb, void *location, enum skb_drop_reason reason)
{
	struct drop_key key = {};
	__u64 one = 1, *cnt;
	unsigned char *head;
	__u16 nh, th, proto;
	__u32 not_specified = 2;

	if (bpf_core_enum_value_exists(enum skb_drop_reason, SKB_DROP_REASON_NOT_SPECIFIED))
		not_specified = bpf_core_enum_value(enum skb_drop_reason, SKB_DROP_REASON_NOT_SPECIFIED);
	if ((__u32)reason <= not_specified)
		return 0;

	head = BPF_CORE_READ(skb, head);
	nh = BPF_CORE_READ(skb, network_header);
	th = BPF_CORE_READ(skb, transport_header);
	proto = bpf_ntohs(BPF_CORE_READ(skb, protocol));
	if (nh == (__u16)~0U)
		return 0;

	if (proto == ETH_P_IP) {
		struct iphdr iph;

		if (bpf_probe_read_kernel(&iph, sizeof(iph), head + nh))
			return 0;
		ip4_to_16(key.saddr, iph.saddr);
		ip4_to_16(key.daddr, iph.daddr);
		key.proto = iph.protocol;
		if (th == (__u16)~0U || th == nh)
			th = nh + iph.ihl * 4;
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr ip6;

		if (bpf_probe_read_kernel(&ip6, sizeof(ip6), head + nh))
			return 0;
		__builtin_memcpy(key.saddr, &ip6.saddr, 16);
		__builtin_memcpy(key.daddr, &ip6.daddr, 16);
		key.proto = ip6.nexthdr;
		if (th == (__u16)~0U || th == nh)
			th = nh + sizeof(ip6);
	} else {
		return 0;
	}

	if (key.proto == 6 || key.proto == 17) {
		__u16 ports[2];

		if (!bpf_probe_read_kernel(ports, sizeof(ports), head + th))
			key.dport = bpf_ntohs(ports[1]);
	}
	key.reason = reason;

	cnt = bpf_map_lookup_elem(&drops, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else
		bpf_map_update_elem(&drops, &key, &one, BPF_NOEXIST);
	return 0;
}
