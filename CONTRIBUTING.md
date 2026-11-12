# Contributing to kubecapybara

Bug reports, fixes and new collectors or doctor rules are welcome. Open an
issue first for anything larger than a bug fix, so the approach can be agreed
before you write the code.

## Building and testing

You need Go (the version in `go.mod`). Nothing else is required for the Go
code: the compiled eBPF objects are committed in `internal/bpf/`.

```bash
make build       # agent, CLI, controller and hub into bin/
make test        # go vet + unit tests
make lint        # gofmt + go vet (CI runs this)
go test -race ./...
```

Try a change end to end on one Linux machine, without a cluster:

```bash
sudo ./bin/capybara-agent --listen 127.0.0.1:9876 --l7 --files --voip
./bin/kubectl-capybara --agent http://127.0.0.1:9876 --no-k8s doctor
```

The agent needs root, cgroup v2, BTF (`/sys/kernel/btf/vmlinux`) and, for the
syscall based collectors (`--l7`, `--files`), tracefs mounted at
`/sys/kernel/tracing`. `curl 127.0.0.1:9876/v1/status` shows which collectors
started and why the others did not.

## Changing eBPF programs

The sources are in `bpf/`, the generated bindings and objects in
`internal/bpf/`. After editing a `.bpf.c` file:

```bash
make generate    # needs clang and the libbpf headers (libbpf-dev)
make test-bpf    # as root: verifier check in the running kernel + live tests
```

Commit the regenerated `internal/bpf/*_bpfel.go` and `.o` files together with
the C change. Keep these properties:

* Aggregate in kernel maps; send ring buffer events only for rare things
  (process lifecycle, listens, DNS and SIP packets), never per packet or per
  syscall on a hot path.
* A program must never change what the kernel does with a packet or a
  syscall: cgroup skb programs always return 1.
* Prefer tracepoints and BTF raw tracepoints over kprobes, and read kernel
  structures with CO-RE (`BPF_CORE_READ`, `bpf_core_field_exists`) so one
  object runs on every supported kernel (5.8+).
* A collector that cannot attach must fail on its own: return the error from
  `Start` and the agent reports it in `/v1/status` while the rest keeps
  running.

Kernel behaviour is easy to get subtly wrong (for example, an accepted
connection is reported as `LISTEN -> SYN_RECV`). When a fix depends on what
the kernel really does, add a live test next to
`internal/agent/net_live_test.go`: it skips itself without root and runs in
the `bpf` CI job.

## Go code

* `gofmt`, `go vet` and the tests must pass; add a test that fails without
  your fix.
* Everything parsed from the wire (DNS, SIP, HTTP, database protocols) is
  untrusted and may be truncated: never index past what you checked. The
  readers of ring buffers run outside the collection loop's `recover`, so a
  panic there stops the agent.
* Timestamps from `bpf_ktime_get_ns` are unsigned and events from different
  CPUs can arrive out of order: guard every subtraction.
* Doctor rules live in `internal/analysis`. Give a rule a stable id and a
  description in the `rules` table, a hint that says what to do, and a test
  with a fixture. Start evidence lines with the pod or workload they are
  about (`ns/pod: ...`): that is how findings are grouped into problems.
  Limits a user may want to change go into the `Thresholds` table and are
  read with `v.th("name")`; write `<pod>`, `<deployment>` or `<workload>` in
  a hint where a command needs a name.
* Label values exported on `/metrics` go through `labels()`, which escapes
  them for the Prometheus text format.

## Pull requests

* One logical change per pull request, with a description of the problem and
  how you verified the fix.
* Update the README, the chart (`charts/kubecapybara`) and the plain manifest
  (`deploy/kubernetes/capybara.yaml`) when you add a flag or change behaviour
  users see.
* By contributing you agree that your work is licensed under the
  [Apache License 2.0](LICENSE); the eBPF C sources are dual licensed
  `GPL-2.0-only OR BSD-2-Clause`, as their SPDX headers say.

## Security issues

Please do not open a public issue for a vulnerability: see
[SECURITY.md](SECURITY.md).
