// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Block I/O latency and throughput per cgroup.
 *
 * block_bio_queue fires when a bio is submitted, usually in the context of
 * the submitting task, so the current cgroup is the one issuing the I/O
 * (buffered writeback is attributed to the flusher threads - i.e. the host -
 * which is a known limitation). block_rq_complete closes the measurement
 * using the first bio of the completed request.
 */
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define REQ_OP_MASK 0xff
#define REQ_OP_WRITE 1

struct bio_start {
	__u64 ts;
	__u64 cgroup;
	__u32 bytes;
	__u8 write;
	__u8 _pad[3];
};

struct cg_io {
	__u64 rd_bytes;
	__u64 wr_bytes;
	__u64 rd_ops;
	__u64 wr_ops;
	struct hist lat;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct bio_start);
} bios SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct cg_io);
} io_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cg_io);
} zero_io SEC(".maps");

static __always_inline void record(struct cg_io *io, struct bio_start *st, __u32 bytes)
{
	if (st->write) {
		__sync_fetch_and_add(&io->wr_bytes, bytes);
		__sync_fetch_and_add(&io->wr_ops, 1);
	} else {
		__sync_fetch_and_add(&io->rd_bytes, bytes);
		__sync_fetch_and_add(&io->rd_ops, 1);
	}
	hist_add(&io->lat, (bpf_ktime_get_ns() - st->ts) / 1000);
}

SEC("tp_btf/block_bio_queue")
int BPF_PROG(on_bio_queue, struct bio *bio)
{
	__u64 key = (__u64)bio;
	struct bio_start st = {};

	st.ts = bpf_ktime_get_ns();
	st.cgroup = bpf_get_current_cgroup_id();
	st.bytes = BPF_CORE_READ(bio, bi_iter.bi_size);
	st.write = (BPF_CORE_READ(bio, bi_opf) & REQ_OP_MASK) == REQ_OP_WRITE;
	bpf_map_update_elem(&bios, &key, &st, BPF_ANY);
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(on_rq_complete, struct request *rq, blk_status_t error, unsigned int nr_bytes)
{
	__u64 key = (__u64)BPF_CORE_READ(rq, bio);
	struct bio_start *st;
	struct cg_io *io;
	__u32 zero = 0;

	if (!key)
		return 0;
	st = bpf_map_lookup_elem(&bios, &key);
	if (!st)
		return 0;
	io = bpf_map_lookup_elem(&io_stats, &st->cgroup);
	if (!io) {
		struct cg_io *z = bpf_map_lookup_elem(&zero_io, &zero);

		if (z)
			bpf_map_update_elem(&io_stats, &st->cgroup, z, BPF_NOEXIST);
		io = bpf_map_lookup_elem(&io_stats, &st->cgroup);
	}
	if (io)
		record(io, st, nr_bytes ? nr_bytes : st->bytes);
	bpf_map_delete_elem(&bios, &key);
	return 0;
}
