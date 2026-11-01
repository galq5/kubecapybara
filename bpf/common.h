/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Shared helpers for kubecapybara eBPF programs.
 *
 * Conventions:
 *   - All IP addresses are stored as 16 bytes; IPv4 is stored v4-mapped
 *     (::ffff:a.b.c.d) so the same key works for both families.
 *   - Latency histograms are log2 buckets of microseconds:
 *       slot 0       -> 0us
 *       slot k (k>0) -> [2^(k-1), 2^k) us
 *   - Cgroup IDs are cgroup v2 kernfs IDs (== inode number of the cgroup dir).
 */
#ifndef __CAPY_COMMON_H
#define __CAPY_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

#define HIST_SLOTS 32

struct hist {
	__u64 slots[HIST_SLOTS];
	__u64 count;
	__u64 sum; /* microseconds */
};

static __always_inline __u32 log2_u32(__u32 v)
{
	__u32 r, shift;

	r = (v > 0xFFFF) << 4;
	v >>= r;
	shift = (v > 0xFF) << 3;
	v >>= shift;
	r |= shift;
	shift = (v > 0xF) << 2;
	v >>= shift;
	r |= shift;
	shift = (v > 0x3) << 1;
	v >>= shift;
	r |= shift;
	r |= (v >> 1);
	return r;
}

static __always_inline __u32 log2_u64(__u64 v)
{
	__u32 hi = v >> 32;

	if (hi)
		return log2_u32(hi) + 32;
	return log2_u32((__u32)v);
}

static __always_inline void hist_add(struct hist *h, __u64 us)
{
	__u32 slot = 0;

	if (us)
		slot = log2_u64(us) + 1;
	if (slot >= HIST_SLOTS)
		slot = HIST_SLOTS - 1;
	__sync_fetch_and_add(&h->slots[slot], 1);
	__sync_fetch_and_add(&h->count, 1);
	__sync_fetch_and_add(&h->sum, us);
}

static __always_inline void ip4_to_16(__u8 *dst, __u32 addr_be)
{
	__builtin_memset(dst, 0, 10);
	dst[10] = 0xff;
	dst[11] = 0xff;
	__builtin_memcpy(dst + 12, &addr_be, 4);
}

/* cgroup v2 id of an arbitrary task */
static __always_inline __u64 task_cgroup_id(struct task_struct *t)
{
	return BPF_CORE_READ(t, cgroups, dfl_cgrp, kn, id);
}

/* pid of a task as seen from inside its own pid namespace (1 == container init) */
static __always_inline __u32 task_ns_pid(struct task_struct *t)
{
	struct pid *p = BPF_CORE_READ(t, thread_pid);
	unsigned int level;
	struct upid up = {};

	if (!p)
		return 0;
	level = BPF_CORE_READ(p, level);
	if (level > 32)
		return 0;
	bpf_probe_read_kernel(&up, sizeof(up), &p->numbers[level]);
	return up.nr;
}

/* cgroup v2 id that owns a socket (set at socket creation time) */
static __always_inline __u64 sock_cgroup_id(struct sock *sk)
{
	if (bpf_core_field_exists(sk->sk_cgrp_data.cgroup))
		return BPF_CORE_READ(sk, sk_cgrp_data.cgroup, kn, id);
	return 0;
}

#endif /* __CAPY_COMMON_H */
