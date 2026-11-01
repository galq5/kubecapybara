// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * On-demand CPU sampling profiler (perf_event, attached per CPU only while a
 * profile is being taken). Samples are filtered by cgroup so only the pod
 * being profiled is recorded.
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_STACK_DEPTH 127

struct sample_key {
	__u64 cgroup;
	__u32 tgid;
	__s32 kstack;
	__s32 ustack;
	char comm[16];
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, struct sample_key);
	__type(value, __u64);
} samples SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");

/* cgroups to sample; written by user space */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} profile_cgroups SEC(".maps");

SEC("perf_event")
int on_sample(struct bpf_perf_event_data *ctx)
{
	__u64 cg = bpf_get_current_cgroup_id();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sample_key key = {};
	__u64 one = 1, *cnt;

	if (!bpf_map_lookup_elem(&profile_cgroups, &cg))
		return 0;
	if ((pid_tgid >> 32) == 0)
		return 0;

	key.cgroup = cg;
	key.tgid = pid_tgid >> 32;
	key.kstack = bpf_get_stackid(ctx, &stacks, 0);
	key.ustack = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
	bpf_get_current_comm(key.comm, sizeof(key.comm));

	cnt = bpf_map_lookup_elem(&samples, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else
		bpf_map_update_elem(&samples, &key, &one, BPF_NOEXIST);
	return 0;
}
