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
 * The same hooks also time plaintext database requests made by clients:
 * PostgreSQL (simple 'Q' and extended 'P'/'B' messages), MySQL (COM_QUERY)
 * and Redis (RESP arrays). The latency is from the request write() to the
 * first read() on the same connection.
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

#define PROTO_HTTP 1
#define PROTO_POSTGRES 2
#define PROTO_REDIS 3
#define PROTO_MYSQL 4
#define PROTO_CASSANDRA 5 /* CQL native protocol v3-v5 frames, matched by stream id */
#define PROTO_KAFKA 6     /* matched by correlation id */
#define PROTO_MONGO 7     /* OP_MSG, matched by requestID/responseTo */
#define PROTO_MEMCACHED 8 /* text protocol, sequential */

/* requests of multiplexed protocols, keyed by their request id */
struct mux_key {
	__u32 tgid;
	__u32 fd;
	__u32 id;
	__u32 proto;
};

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
	__u8 proto;
	__u8 off; /* offset of the request inside req[] (coalesced CQL frames) */
	__u8 _pad[5];
	char req[REQ_MAX];
};

struct http_event {
	__u64 ts;
	__u64 cgroup;
	__u64 latency_ns;
	__u32 pid;
	__u8 role;
	__u8 proto;
	__u8 off;
	__u8 _pad;
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
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct mux_key);
	__type(value, struct pending_req);
} pending_mux SEC(".maps");

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

/* database client requests (only checked for writes). The length fields of
 * the protocols must agree with the size of the write to keep unrelated
 * binary writes (other protocols, files) out. */
static __always_inline __u8 db_proto(const char *b, __s64 len)
{
	__u8 b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4];
	__u32 plen;

	/* PostgreSQL: type byte + big endian int32 length that fits in the write
	 * (several messages, e.g. Parse+Bind+Execute+Sync, may follow) */
	plen = ((__u32)b1 << 24) | ((__u32)b2 << 16) | ((__u32)b3 << 8) | b4;
	if ((b0 == 'Q' || b0 == 'P' || b0 == 'B') && b1 == 0 && plen >= 4 && (__s64)plen + 1 <= len)
		return PROTO_POSTGRES;
	/* Redis RESP array: "*<n>\r\n$" */
	if (b0 == '*' && b1 >= '1' && b1 <= '9' && (b2 == '\r' || (b2 >= '0' && b2 <= '9')))
		return PROTO_REDIS;
	/* MySQL: 3 byte LE payload length, sequence 0, COM_QUERY; one packet */
	plen = (__u32)b0 | ((__u32)b1 << 8) | ((__u32)b2 << 16);
	if (b3 == 0 && b4 == 0x03 && plen >= 1 && (__s64)plen + 4 == len)
		return PROTO_MYSQL;
	/* Memcached text protocol */
	if ((b0 == 'g' && b1 == 'e' && b2 == 't') || (b0 == 's' && b1 == 'e' && b2 == 't' && b3 == ' ') ||
	    (b0 == 'a' && b1 == 'd' && b2 == 'd' && b3 == ' ') || (b0 == 'd' && b1 == 'e' && b2 == 'l' && b3 == 'e') ||
	    (b0 == 'i' && b1 == 'n' && b2 == 'c' && b3 == 'r') || (b0 == 'd' && b1 == 'e' && b2 == 'c' && b3 == 'r') ||
	    (b0 == 't' && b1 == 'o' && b2 == 'u' && b3 == 'c') || (b0 == 'c' && b1 == 'a' && b2 == 's' && b3 == ' '))
		return PROTO_MEMCACHED;
	return 0;
}

static __always_inline __u32 be32(const char *b)
{
	return ((__u32)(__u8)b[0] << 24) | ((__u32)(__u8)b[1] << 16) | ((__u32)(__u8)b[2] << 8) | (__u8)b[3];
}

static __always_inline __u32 le32(const char *b)
{
	return ((__u32)(__u8)b[3] << 24) | ((__u32)(__u8)b[2] << 16) | ((__u32)(__u8)b[1] << 8) | (__u8)b[0];
}

/* multiplexed protocol requests: returns the protocol and sets *id */
static __always_inline __u8 mux_request(const char *b, __s64 len, __u32 *id)
{
	__u8 b0 = b[0], op = b[4];

	/* CQL: version 3-5 request, opcode QUERY/PREPARE/EXECUTE/BATCH, body length fits */
	if (b0 >= 3 && b0 <= 5 && (op == 0x07 || op == 0x09 || op == 0x0A || op == 0x0D) &&
	    (__s64)be32(b + 5) + 9 <= len) {
		*id = ((__u32)(__u8)b[2] << 8) | (__u8)b[3];
		return PROTO_CASSANDRA;
	}
	/* MongoDB OP_MSG: messageLength == write size, responseTo 0, opCode 2013 */
	if ((__s64)le32(b) == len && le32(b + 8) == 0 && le32(b + 12) == 2013) {
		*id = le32(b + 4);
		return PROTO_MONGO;
	}
	/* Kafka: size == write - 4, sane api key and version */
	if ((__s64)be32(b) + 4 == len && b[4] == 0 && (__u8)b[5] <= 80 && b[6] == 0 && (__u8)b[7] <= 20) {
		*id = be32(b + 8);
		return PROTO_KAFKA;
	}
	return 0;
}

static __always_inline void emit(struct pending_req *p, struct pending_req *resp, __u32 tgid)
{
	struct http_event *ev = bpf_ringbuf_reserve(&http_events, sizeof(*ev), 0);

	if (!ev)
		return;
	ev->ts = bpf_ktime_get_ns();
	ev->cgroup = bpf_get_current_cgroup_id();
	ev->latency_ns = ev->ts - p->ts;
	ev->pid = tgid;
	ev->role = p->role;
	ev->proto = p->proto;
	ev->off = p->off;
	__builtin_memcpy(ev->req, p->req, REQ_MAX);
	__builtin_memcpy(ev->resp, resp->req, RESP_MAX);
	bpf_ringbuf_submit(ev, 0);
}

static __always_inline void on_data(__u32 fd, __u64 buf, __s64 len, int is_read)
{
	__u32 zero = 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct conn_key key = { .tgid = pid_tgid >> 32, .fd = fd };
	struct pending_req *req;
	__u32 n;

	/* DB replies can be tiny (redis "+OK\r\n") */
	if (len < 1 || !buf)
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
		req->proto = PROTO_HTTP;
		bpf_map_update_elem(&pending, &key, req, BPF_ANY);
		return;
	}
	if (is_response(req->req)) {
		struct pending_req *p = bpf_map_lookup_elem(&pending, &key);

		if (!p || p->proto != PROTO_HTTP)
			return;
		/* server answers with write(), client receives with read() */
		if ((p->role == ROLE_SERVER && is_read) || (p->role == ROLE_CLIENT && !is_read))
			return;
		emit(p, req, key.tgid);
		bpf_map_delete_elem(&pending, &key);
		return;
	}
	if (!is_read) {
		__u32 id = 0;
		__u8 proto = mux_request(req->req, len, &id);

		if (proto) {
			struct mux_key mk = { .tgid = key.tgid, .fd = fd, .id = id, .proto = proto };

			req->ts = bpf_ktime_get_ns();
			req->role = ROLE_CLIENT;
			req->proto = proto;
			req->off = 0;
			bpf_map_update_elem(&pending_mux, &mk, req, BPF_ANY);
			if (proto == PROTO_CASSANDRA) {
				/* drivers coalesce frames: register the following ones that
				 * start inside the captured bytes too */
				__u32 off = 0, plen = be32(req->req + 5);
				int i;

				for (i = 0; i < 3; i++) {
					char *f;

					if (plen > REQ_MAX)
						break;
					off += 9 + plen;
					if (off > REQ_MAX - 9)
						break;
					f = req->req + (off & 0x7f);
					if (off + 9 > REQ_MAX || ((__u8)f[0] < 3 || (__u8)f[0] > 5))
						break;
					plen = be32(f + 5);
					if (plen > 0xffffff)
						break;
					mk.id = ((__u32)(__u8)f[2] << 8) | (__u8)f[3];
					req->off = off;
					bpf_map_update_elem(&pending_mux, &mk, req, BPF_ANY);
				}
			}
			return;
		}
		proto = db_proto(req->req, len);
		if (proto) {
			req->ts = bpf_ktime_get_ns();
			req->role = ROLE_CLIENT;
			req->proto = proto;
			bpf_map_update_elem(&pending, &key, req, BPF_ANY);
		}
		return;
	}
	/* first bytes read after a sequential database request: the reply */
	{
		struct pending_req *p = bpf_map_lookup_elem(&pending, &key);

		if (p && p->proto != PROTO_HTTP) {
			emit(p, req, key.tgid);
			bpf_map_delete_elem(&pending, &key);
			return;
		}
	}
	/* replies of multiplexed protocols: try each header layout */
	{
		struct mux_key mk = { .tgid = key.tgid, .fd = fd };
		struct pending_req *p;
		const char *b = req->req;

		if (((__u8)b[0] & 0x80) && ((__u8)b[0] & 0x7f) >= 3 && ((__u8)b[0] & 0x7f) <= 5) {
			mk.proto = PROTO_CASSANDRA;
			mk.id = ((__u32)(__u8)b[2] << 8) | (__u8)b[3];
		} else if (le32(b + 12) == 2013 || le32(b + 12) == 1) {
			mk.proto = PROTO_MONGO;
			mk.id = le32(b + 8);
		} else {
			mk.proto = PROTO_KAFKA;
			mk.id = be32(b + 4);
		}
		p = bpf_map_lookup_elem(&pending_mux, &mk);
		if (!p)
			return;
		emit(p, req, key.tgid);
		bpf_map_delete_elem(&pending_mux, &mk);
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
