# The eBPF objects are pre-compiled and committed (internal/bpf/*.o), so the
# image build only needs the Go toolchain. Run `make generate` after changing
# anything under bpf/.
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/capybara-agent ./cmd/capybara-agent

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/capybara-agent /capybara-agent
ENTRYPOINT ["/capybara-agent"]
