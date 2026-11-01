// Package bpf contains the compiled eBPF objects and their generated Go
// bindings. Regenerate with `make generate` (requires clang).
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 -type pair_key -type pair_val -type conn_err_key -type net_event Net ../../bpf/net.bpf.c -- -I../../bpf/headers -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 -type drop_key Drop ../../bpf/drop.bpf.c -- -I../../bpf/headers -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 -type dns_event Dns ../../bpf/dns.bpf.c -- -I../../bpf/headers -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 -type cg_sched -type culprit_key Sched ../../bpf/sched.bpf.c -- -I../../bpf/headers -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 -type cg_io Io ../../bpf/io.bpf.c -- -I../../bpf/headers -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 -type capy_proc_event Proc ../../bpf/proc.bpf.c -- -I../../bpf/headers -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 -type http_event Http ../../bpf/http.bpf.c -- -I../../bpf/headers -I../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 -type sample_key Profile ../../bpf/profile.bpf.c -- -I../../bpf/headers -I../../bpf
