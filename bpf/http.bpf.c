// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Plaintext HTTP/1.x request/response latency without sidecars.
 *
 * Hooks read/recvfrom (exit) and write/sendto/writev (enter). When a buffer
 * starts with an HTTP method we remember the request line per (tgid, fd);
 * when a buffer on the same fd starts with "HTTP/" we emit an event with the
 * request line, the status line and the latency.
 *
 *   server role: request read()   -> response write()
 *   client role: request write()  -> response read()
 *
 * TLS traffic is invisible to this collector. Because it hooks every
 * read/write syscall on the node it is opt-in (agent flag --l7).
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ROLE_CLIENT 1
#define ROLE_SERVER 2
#define REQ_MAX 96
#define RESP_MAX 16

/* layout shared by syscalls:sys_enter_* tracepoints: args start at offset 16 */
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

struct read_args {
	__u64 buf;
	__u32 fd;
	__u32 _pad;
};

struct conn_key {
	__u32 tgid;
	__u32 fd;
};

struct pending_req {
	__u64 ts;
	__u8 role;
	__u8 _pad[7];
	char req[REQ_MAX];
};

struct http_event {
	__u64 ts;
	__u64 cgroup;
	__u64 latency_ns;
	__u32 pid;
	__u8 role;
	__u8 _pad[3];
	char req[REQ_MAX];
	char resp[RESP_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct read_args);
} reads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct conn_key);
	__type(value, struct pending_req);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pending_req);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} http_events SEC(".maps");

const struct http_event *unused_http_event __attribute__((unused));

static __always_inline int is_request(const char *b)
{
	if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ')
		return 1;
	if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T')
		return 1;
	if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ')
		return 1;
	if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E')
		return 1;
	if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C')
		return 1;
	if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D')
		return 1;
	if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I')
		return 1;
	return 0;
}

static __always_inline int is_response(const char *b)
{
	return b[0] == 'H' && b[1] == 'T' && b[2] == 'T' && b[3] == 'P' && b[4] == '/';
}

static __always_inline void on_data(__u32 fd, __u64 buf, __s64 len, int is_read)
{
	__u32 zero = 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct conn_key key = { .tgid = pid_tgid >> 32, .fd = fd };
	struct pending_req *req;
	__u32 n;

	if (len < 8 || !buf)
		return;
	req = bpf_map_lookup_elem(&scratch, &zero);
	if (!req)
		return;
	n = len > REQ_MAX ? REQ_MAX : (__u32)len;
	n &= 0x7f;
	if (n > REQ_MAX)
		n = REQ_MAX;
	__builtin_memset(req->req, 0, REQ_MAX);
	if (bpf_probe_read_user(req->req, n, (void *)buf))
		return;

	if (is_request(req->req)) {
		req->ts = bpf_ktime_get_ns();
		req->role = is_read ? ROLE_SERVER : ROLE_CLIENT;
		bpf_map_update_elem(&pending, &key, req, BPF_ANY);
		return;
	}
	if (is_response(req->req)) {
		struct pending_req *p = bpf_map_lookup_elem(&pending, &key);
		struct http_event *ev;

		if (!p)
			return;
		/* server answers with write(), client receives with read() */
		if ((p->role == ROLE_SERVER && is_read) || (p->role == ROLE_CLIENT && !is_read))
			return;
		ev = bpf_ringbuf_reserve(&http_events, sizeof(*ev), 0);
		if (ev) {
			ev->ts = bpf_ktime_get_ns();
			ev->cgroup = bpf_get_current_cgroup_id();
			ev->latency_ns = ev->ts - p->ts;
			ev->pid = key.tgid;
			ev->role = p->role;
			__builtin_memcpy(ev->req, p->req, REQ_MAX);
			__builtin_memcpy(ev->resp, req->req, RESP_MAX);
			bpf_ringbuf_submit(ev, 0);
		}
		bpf_map_delete_elem(&pending, &key);
	}
}

static __always_inline int enter_read(struct sys_enter_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_args a = { .fd = (__u32)ctx->args[0], .buf = ctx->args[1] };

	bpf_map_update_elem(&reads, &id, &a, BPF_ANY);
	return 0;
}

static __always_inline int exit_read(struct sys_exit_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_args *a = bpf_map_lookup_elem(&reads, &id);

	if (!a)
		return 0;
	if (ctx->ret > 0)
		on_data(a->fd, a->buf, ctx->ret, 1);
	bpf_map_delete_elem(&reads, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int enter_read_tp(struct sys_enter_ctx *ctx) { return enter_read(ctx); }

SEC("tracepoint/syscalls/sys_exit_read")
int exit_read_tp(struct sys_exit_ctx *ctx) { return exit_read(ctx); }

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int enter_recvfrom_tp(struct sys_enter_ctx *ctx) { return enter_read(ctx); }

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int exit_recvfrom_tp(struct sys_exit_ctx *ctx) { return exit_read(ctx); }

SEC("tracepoint/syscalls/sys_enter_write")
int enter_write_tp(struct sys_enter_ctx *ctx)
{
	on_data((__u32)ctx->args[0], ctx->args[1], (__s64)ctx->args[2], 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int enter_sendto_tp(struct sys_enter_ctx *ctx)
{
	on_data((__u32)ctx->args[0], ctx->args[1], (__s64)ctx->args[2], 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int enter_writev_tp(struct sys_enter_ctx *ctx)
{
	struct iovec iov = {};

	if (bpf_probe_read_user(&iov, sizeof(iov), (void *)ctx->args[1]))
		return 0;
	on_data((__u32)ctx->args[0], (__u64)iov.iov_base, (__s64)iov.iov_len, 0);
	return 0;
}
