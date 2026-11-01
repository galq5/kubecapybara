VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/galq5/kubecapybara-agent
BPFTOOL ?= bpftool
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build agent cli generate vmlinux test test-bpf image deploy lint clean

all: build

build: agent cli

agent:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/capybara-agent ./cmd/capybara-agent

cli:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kubectl-capybara ./cmd/kubectl-capybara

# Recompile eBPF programs (needs clang and libbpf headers).
generate:
	cd internal/bpf && go generate ./...

# Regenerate bpf/headers/vmlinux.h from the running kernel's BTF.
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

test:
	go vet ./...
	go test ./...

# Load every eBPF object into the running kernel (verifier check). Needs root.
test-bpf:
	sudo -E env "PATH=$$PATH" go test -count=1 -v ./internal/bpf/

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

deploy:
	kubectl apply -f deploy/kubernetes/capybara.yaml

install-cli: cli
	install -m 0755 bin/kubectl-capybara $(HOME)/.local/bin/kubectl-capybara

clean:
	rm -rf bin dist
