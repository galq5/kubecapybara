// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Per-cgroup thread time breakdown ("where does my pod spend its time?").
 *
 * Every thread is always in exactly one state, tracked in `tstates`:
 *   ONCPU   - running
 *   RUNQ    - runnable, waiting for a CPU (scheduler latency)
 *   DISK    - uninterruptible sleep (D state: block I/O, some fs/mm waits)
 *   NET     - sleeping inside a socket / read / write syscall
 *   POLL    - sleeping in epoll/poll/select (event loop waiting)
 *   LOCK    - sleeping in futex (mutexes, condvars, Go runtime parking)
 *   SLEEP   - nanosleep / clock_nanosleep
 *   OTHER   - any other interruptible sleep
 *
 * Transitions happen at sched_switch (leave CPU) and sched_wakeup (become
 * runnable). Time spent in each state is accumulated per cgroup. Run queue
 * latency is additionally recorded in a histogram and attributed to the
 * cgroup that was occupying the CPU ("culprit") for noisy-neighbour analysis.
 *
 * Direct memory reclaim stall time per cgroup is tracked too.
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define K_RUNQ 0
#define K_DISK 1
#define K_NET 2
#define K_POLL 3
#define K_LOCK 4
#define K_SLEEP 5
#define K_OTHER 6
#define K_ONCPU 7
#define NKINDS 8

#define TASK_RUNNING 0
#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2

struct cg_sched {
	__u64 oncpu_ns;
	__u64 off_ns[NKINDS]; /* index by K_* (K_ONCPU unused) */
	struct hist runq;
	__u64 reclaim_ns;
	__u64 reclaim_cnt;
	__u64 wakeups;
};

struct tstate {
	__u64 ts;
	__u32 kind;
	__u32 _pad;
};

struct culprit_key {
	__u64 victim;
	__u64 culprit;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, __u32);
	__type(value, struct tstate);
} tstates SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct cg_sched);
} cg_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cg_sched);
} zero_cg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct culprit_key);
	__type(value, __u64);
} culprits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} reclaim_start SEC(".maps");

static __always_inline struct cg_sched *cg_get(__u64 cg)
{
	struct cg_sched *v;
	__u32 zero = 0;

	v = bpf_map_lookup_elem(&cg_stats, &cg);
	if (v)
		return v;
	v = bpf_map_lookup_elem(&zero_cg, &zero);
	if (!v)
		return 0;
	bpf_map_update_elem(&cg_stats, &cg, v, BPF_NOEXIST);
	return bpf_map_lookup_elem(&cg_stats, &cg);
}

static __always_inline long task_state(struct task_struct *t)
{
	struct task_struct___old {
		long state;
	} __attribute__((preserve_access_index)) *old = (void *)t;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ(old, state);
}

static __always_inline __u32 classify_syscall(long nr)
{
#if defined(__TARGET_ARCH_x86)
	switch (nr) {
	case 0: case 1: case 17: case 18: case 19: case 20: /* read write pread pwrite readv writev */
	case 42: case 43: case 44: case 45: case 46: case 47: /* connect accept sendto recvfrom sendmsg recvmsg */
	case 288: case 299: case 307: /* accept4 recvmmsg sendmmsg */
		return K_NET;
	case 7: case 23: case 232: case 270: case 271: case 281: case 441: /* poll select epoll_wait pselect6 ppoll epoll_pwait epoll_pwait2 */
		return K_POLL;
	case 202: case 449: /* futex futex_waitv */
		return K_LOCK;
	case 35: case 230: /* nanosleep clock_nanosleep */
		return K_SLEEP;
	}
#elif defined(__TARGET_ARCH_arm64)
	switch (nr) {
	case 63: case 64: case 65: case 66: case 67: case 68:
	case 202: case 203: case 206: case 207: case 211: case 212: case 242: case 243: case 269:
		return K_NET;
	case 22: case 72: case 73: case 441:
		return K_POLL;
	case 98: case 449:
		return K_LOCK;
	case 101: case 115:
		return K_SLEEP;
	}
#endif
	return K_OTHER;
}

static __always_inline long task_syscall_nr(struct task_struct *t)
{
	struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(t);

	if (!regs)
		return -1;
#if defined(__TARGET_ARCH_x86)
	return BPF_CORE_READ(regs, orig_ax);
#elif defined(__TARGET_ARCH_arm64)
	return BPF_CORE_READ(regs, syscallno);
#else
	return -1;
#endif
}

static __always_inline void on_wake(struct task_struct *p)
{
	__u32 tid = BPF_CORE_READ(p, pid);
	__u64 now = bpf_ktime_get_ns();
	struct tstate *st, fresh = {};

	if (!tid)
		return;
	st = bpf_map_lookup_elem(&tstates, &tid);
	if (st) {
		if (st->kind == K_ONCPU || st->kind == K_RUNQ)
			return;
		if (st->kind < NKINDS) {
			struct cg_sched *cs = cg_get(task_cgroup_id(p));

			if (cs) {
				__u32 k = st->kind & (NKINDS - 1);

				__sync_fetch_and_add(&cs->off_ns[k], now - st->ts);
				__sync_fetch_and_add(&cs->wakeups, 1);
			}
		}
		st->ts = now;
		st->kind = K_RUNQ;
		return;
	}
	fresh.ts = now;
	fresh.kind = K_RUNQ;
	bpf_map_update_elem(&tstates, &tid, &fresh, BPF_ANY);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_wakeup, struct task_struct *p)
{
	on_wake(p);
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(on_wakeup_new, struct task_struct *p)
{
	on_wake(p);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 prev_tid = BPF_CORE_READ(prev, pid);
	__u32 next_tid = BPF_CORE_READ(next, pid);
	__u64 prev_cg = 0;
	struct tstate *st, fresh = {};
	struct cg_sched *cs;

	/* --- prev leaves the CPU --- */
	if (prev_tid) {
		long state = task_state(prev);
		__u32 kind;

		prev_cg = bpf_get_current_cgroup_id();
		st = bpf_map_lookup_elem(&tstates, &prev_tid);
		if (st && st->kind == K_ONCPU) {
			cs = cg_get(prev_cg);
			if (cs)
				__sync_fetch_and_add(&cs->oncpu_ns, now - st->ts);
		}

		if (state == TASK_RUNNING)
			kind = K_RUNQ;
		else if (state & TASK_UNINTERRUPTIBLE)
			kind = K_DISK;
		else
			kind = classify_syscall(task_syscall_nr(prev));

		fresh.ts = now;
		fresh.kind = kind;
		if (st) {
			st->ts = now;
			st->kind = kind;
		} else {
			bpf_map_update_elem(&tstates, &prev_tid, &fresh, BPF_ANY);
		}
	}

	/* --- next gets the CPU --- */
	if (next_tid) {
		st = bpf_map_lookup_elem(&tstates, &next_tid);
		if (st && st->kind == K_RUNQ) {
			__u64 next_cg = task_cgroup_id(next);
			__u64 delta = now - st->ts;

			cs = cg_get(next_cg);
			if (cs) {
				__sync_fetch_and_add(&cs->off_ns[K_RUNQ], delta);
				hist_add(&cs->runq, delta / 1000);
			}
			if (prev_tid && prev_cg != next_cg && delta > 10000) {
				struct culprit_key ck = { .victim = next_cg, .culprit = prev_cg };
				__u64 *v = bpf_map_lookup_elem(&culprits, &ck);

				if (v)
					__sync_fetch_and_add(v, delta);
				else
					bpf_map_update_elem(&culprits, &ck, &delta, BPF_NOEXIST);
			}
		}
		fresh.ts = now;
		fresh.kind = K_ONCPU;
		if (st) {
			st->ts = now;
			st->kind = K_ONCPU;
		} else {
			bpf_map_update_elem(&tstates, &next_tid, &fresh, BPF_ANY);
		}
	}
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int on_reclaim_begin(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 now = bpf_ktime_get_ns();

	bpf_map_update_elem(&reclaim_start, &tid, &now, BPF_ANY);
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int on_reclaim_end(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *start = bpf_map_lookup_elem(&reclaim_start, &tid);
	struct cg_sched *cs;

	if (!start)
		return 0;
	cs = cg_get(bpf_get_current_cgroup_id());
	if (cs) {
		__sync_fetch_and_add(&cs->reclaim_ns, bpf_ktime_get_ns() - *start);
		__sync_fetch_and_add(&cs->reclaim_cnt, 1);
	}
	bpf_map_delete_elem(&reclaim_start, &tid);
	return 0;
}
