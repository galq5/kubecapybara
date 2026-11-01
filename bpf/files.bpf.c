// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Slow file operations per cgroup ("which files is my pod waiting on?").
 *
 * read/write/pread64/pwrite64/readv/writev/fsync/fdatasync are timed
 * between syscall entry and exit. Only operations slower than
 * threshold_ns on regular files are reported, with the file name, its
 * parent directory and the filesystem type (nfs4, ext4, xfs, overlay...).
 * Opt-in (agent flag --files) because it hooks every read/write syscall.
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define OP_READ 1
#define OP_WRITE 2
#define OP_FSYNC 3
#define S_IFMT 00170000
#define S_IFREG 0100000
#define NAME_MAX_ 64

/* set by user space after load */
volatile __u64 threshold_ns = 10000000;

struct sys_enter_ctx {
	__u64 _common;
	__s64 nr;
	__u64 args[6];
};

struct sys_exit_ctx {
	__u64 _common;
	__s64 nr;
	__s64 ret;
};

struct fstart {
	__u64 ts;
	__u32 fd;
	__u8 op;
	__u8 _pad[3];
};

struct file_event {
	__u64 ts;
	__u64 cgroup;
	__u64 dur_ns;
	__s64 ret;
	__u32 pid;
	__u32 fd;
	__u8 op;
	__u8 _pad[7];
	char name[NAME_MAX_];
	char parent[NAME_MAX_];
	char fstype[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, struct fstart);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} file_events SEC(".maps");

const struct file_event *unused_file_event __attribute__((unused));

static __always_inline int enter(struct sys_enter_ctx *ctx, __u8 op)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fstart st = { .ts = bpf_ktime_get_ns(), .fd = (__u32)ctx->args[0], .op = op };

	bpf_map_update_elem(&starts, &id, &st, BPF_ANY);
	return 0;
}

static __always_inline int leave(struct sys_exit_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fstart *st = bpf_map_lookup_elem(&starts, &id);
	struct task_struct *task;
	struct fdtable *fdt;
	struct file **fds, *f = 0;
	struct dentry *d;
	struct file_event *ev;
	__u64 dur;
	__u32 fd;
	__u8 op;

	if (!st)
		return 0;
	dur = bpf_ktime_get_ns() - st->ts;
	fd = st->fd;
	op = st->op;
	bpf_map_delete_elem(&starts, &id);
	if (dur < threshold_ns)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || fd >= BPF_CORE_READ(fdt, max_fds))
		return 0;
	fds = BPF_CORE_READ(fdt, fd);
	if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || !f)
		return 0;
	if ((BPF_CORE_READ(f, f_inode, i_mode) & S_IFMT) != S_IFREG)
		return 0; /* sockets, pipes, ttys: not file I/O */

	ev = bpf_ringbuf_reserve(&file_events, sizeof(*ev), 0);
	if (!ev)
		return 0;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ts = bpf_ktime_get_ns();
	ev->cgroup = bpf_get_current_cgroup_id();
	ev->dur_ns = dur;
	ev->ret = ctx->ret;
	ev->pid = id >> 32;
	ev->fd = fd;
	ev->op = op;
	d = BPF_CORE_READ(f, f_path.dentry);
	bpf_probe_read_kernel_str(ev->name, sizeof(ev->name), BPF_CORE_READ(d, d_name.name));
	bpf_probe_read_kernel_str(ev->parent, sizeof(ev->parent), BPF_CORE_READ(d, d_parent, d_name.name));
	bpf_probe_read_kernel_str(ev->fstype, sizeof(ev->fstype), BPF_CORE_READ(f, f_inode, i_sb, s_type, name));
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

#define HOOK(sc, op)                                                          \
	SEC("tracepoint/syscalls/sys_enter_" #sc)                              \
	int enter_##sc(struct sys_enter_ctx *ctx) { return enter(ctx, op); }   \
	SEC("tracepoint/syscalls/sys_exit_" #sc)                               \
	int exit_##sc(struct sys_exit_ctx *ctx) { return leave(ctx); }

HOOK(read, OP_READ)
HOOK(pread64, OP_READ)
HOOK(readv, OP_READ)
HOOK(write, OP_WRITE)
HOOK(pwrite64, OP_WRITE)
HOOK(writev, OP_WRITE)
HOOK(fsync, OP_FSYNC)
HOOK(fdatasync, OP_FSYNC)
