VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/galq5/kubecapybara-agent
BPFTOOL ?= bpftool
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build agent cli controller hub generate vmlinux test test-bpf image deploy lint clean

all: build

build: agent cli controller hub

agent:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/capybara-agent ./cmd/capybara-agent

cli:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kubectl-capybara ./cmd/kubectl-capybara

controller:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/capybara-controller ./cmd/capybara-controller

hub:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/capybara-hub ./cmd/capybara-hub

# Recompile eBPF programs (needs clang and libbpf headers).
generate:
	cd internal/bpf && go generate ./...

# Regenerate bpf/headers/vmlinux.h from the running kernel's BTF.
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

test:
	go vet ./...
	go test ./...

# Kernel tests, as root: load every eBPF object into the running kernel
# (verifier check) and run the live collector tests against real sockets.
test-bpf:
	sudo -E env "PATH=$$PATH" go test -count=1 -v ./internal/bpf/
	sudo -E env "PATH=$$PATH" go test -count=1 -v -run TestListenerSurvivesAccept ./internal/agent/

# Formatting and static checks (also run by CI).
lint:
	@unformatted=$$(gofmt -l cmd internal hack); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go vet ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

deploy:
	kubectl apply -f deploy/kubernetes/capybara.yaml

install-cli: cli
	install -m 0755 bin/kubectl-capybara $(HOME)/.local/bin/kubectl-capybara

clean:
	rm -rf bin dist
