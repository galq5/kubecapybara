// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Process lifecycle events: exec, abnormal exit, fatal signals, OOM kills.
 *
 * Feeds the flight recorder (crash forensics), startup timelines and the
 * security view (interactive exec sessions, unexpected shells).
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EV_EXEC 1
#define EV_EXIT 2
#define EV_SIGNAL 3
#define EV_OOM 4

#define ARGS_MAX 128
#define FILENAME_MAX 128

struct capy_proc_event {
	__u64 ts;
	__u64 cgroup;
	__u64 target_cgroup;
	__u64 extra[4]; /* oom: total_vm, anon_rss, file_rss, shmem_rss (kB) */
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 ns_pid;
	__u32 uid;
	__s32 code; /* exit status (raw wait status) or signal number */
	__u32 target_pid;
	__u32 target_ns_pid;
	__u8 tty;
	__u8 _pad[7];
	char comm[16];
	char pcomm[16];
	char tcomm[16];
	char filename[FILENAME_MAX];
	char args[ARGS_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} capy_proc_events SEC(".maps");

const struct capy_proc_event *unused_capy_proc_event __attribute__((unused));

static __always_inline struct capy_proc_event *new_event(__u32 type)
{
	struct capy_proc_event *ev = bpf_ringbuf_reserve(&capy_proc_events, sizeof(*ev), 0);

	if (!ev)
		return 0;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ts = bpf_ktime_get_ns();
	ev->type = type;
	ev->cgroup = bpf_get_current_cgroup_id();
	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	return ev;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct capy_proc_event *ev = new_event(EV_EXEC);
	struct task_struct *parent;
	const char *fname;
	unsigned long arg_start, arg_end, len;

	if (!ev)
		return 0;
	parent = BPF_CORE_READ(p, real_parent);
	ev->ppid = BPF_CORE_READ(parent, tgid);
	BPF_CORE_READ_STR_INTO(&ev->pcomm, parent, comm);
	ev->ns_pid = task_ns_pid(p);
	ev->tty = BPF_CORE_READ(p, signal, tty) != 0;

	fname = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(ev->filename, sizeof(ev->filename), fname);

	arg_start = BPF_CORE_READ(p, mm, arg_start);
	arg_end = BPF_CORE_READ(p, mm, arg_end);
	len = arg_end - arg_start;
	if (len > ARGS_MAX - 1)
		len = ARGS_MAX - 1;
	len &= (ARGS_MAX - 1);
	if (len > 0)
		bpf_probe_read_user(ev->args, len, (void *)arg_start);

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	struct capy_proc_event *ev;
	int code;

	if (BPF_CORE_READ(p, pid) != BPF_CORE_READ(p, tgid))
		return 0;
	code = BPF_CORE_READ(p, exit_code);
	if (code == 0)
		return 0;
	ev = new_event(EV_EXIT);
	if (!ev)
		return 0;
	ev->code = code;
	ev->ns_pid = task_ns_pid(p);
	ev->ppid = BPF_CORE_READ(p, real_parent, tgid);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tp_btf/signal_generate")
int BPF_PROG(on_signal, int sig, struct kernel_siginfo *info, struct task_struct *task, int group, int result)
{
	struct capy_proc_event *ev;

	/* SIGILL SIGABRT SIGBUS SIGFPE SIGKILL SIGSEGV SIGTERM */
	if (sig != 4 && sig != 6 && sig != 7 && sig != 8 && sig != 9 && sig != 11 && sig != 15)
		return 0;
	if (result != 0) /* only delivered signals */
		return 0;
	ev = new_event(EV_SIGNAL);
	if (!ev)
		return 0;
	ev->code = sig;
	ev->target_pid = BPF_CORE_READ(task, tgid);
	ev->target_ns_pid = task_ns_pid(task);
	ev->target_cgroup = task_cgroup_id(task);
	BPF_CORE_READ_STR_INTO(&ev->tcomm, task, comm);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/oom/mark_victim")
int on_oom(struct trace_event_raw_mark_victim *ctx)
{
	struct capy_proc_event *ev = new_event(EV_OOM);

	if (!ev)
		return 0;
	ev->target_pid = BPF_CORE_READ(ctx, pid);
	if (bpf_core_field_exists(ctx->total_vm)) {
		ev->extra[0] = BPF_CORE_READ(ctx, total_vm);
		ev->extra[1] = BPF_CORE_READ(ctx, anon_rss);
		ev->extra[2] = BPF_CORE_READ(ctx, file_rss);
		ev->extra[3] = BPF_CORE_READ(ctx, shmem_rss);
	}
	bpf_ringbuf_submit(ev, 0);
	return 0;
}
