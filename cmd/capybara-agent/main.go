// Command capybara-agent is the per-node kubecapybara eBPF agent. It runs as
// a privileged DaemonSet and serves aggregated observability data over HTTP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/galq5/kubecapybara/internal/agent"
)

var version = "dev"

func main() {
	var (
		cfg     agent.Config
		disable string
		debug   bool
		showVer bool
	)
	hostname, _ := os.Hostname()
	flag.StringVar(&cfg.Node, "node", envOr("NODE_NAME", hostname), "node name reported to clients")
	flag.StringVar(&cfg.Listen, "listen", ":9876", "HTTP API listen address")
	flag.DurationVar(&cfg.Interval, "interval", 5*time.Second, "collection interval")
	flag.DurationVar(&cfg.FineRetention, "fine-retention", 15*time.Minute, "how long to keep full resolution windows")
	flag.DurationVar(&cfg.Retention, "retention", 6*time.Hour, "how long to keep 1-minute rollups")
	flag.StringVar(&cfg.CgroupRoot, "cgroup-root", "", "cgroup v2 mount point (autodetected)")
	flag.StringVar(&cfg.HostPrefix, "host-prefix", "", "prefix where the host filesystem is mounted, used for cgroup autodetection (e.g. /host)")
	flag.StringVar(&cfg.ProcRoot, "proc", "/proc", "host procfs (run with hostPID)")
	flag.BoolVar(&cfg.EnableL7, "l7", false, "enable HTTP/1.x request tracing (hooks read/write syscalls)")
	flag.StringVar(&disable, "disable", "", "comma separated collectors to disable (net,drops,dns,sched,io,proc,cgroupfs,node,profile)")
	flag.StringVar(&cfg.ClusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster DNS domain")
	var tokenFile string
	flag.StringVar(&tokenFile, "token-file", "", "file with the API token (default: $CAPYBARA_TOKEN); empty disables API authentication")
	flag.BoolVar(&debug, "debug", false, "debug logging")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.Parse()

	if showVer {
		fmt.Println(version)
		return
	}
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	cfg.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	cfg.Version = version
	cfg.Token = strings.TrimSpace(os.Getenv("CAPYBARA_TOKEN"))
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			cfg.Log.Error("reading token file", "err", err)
			os.Exit(1)
		}
		cfg.Token = strings.TrimSpace(string(b))
	}
	cfg.Disable = map[string]bool{}
	for _, d := range strings.Split(disable, ",") {
		if d = strings.TrimSpace(d); d != "" {
			cfg.Disable[d] = true
		}
	}

	a, err := agent.New(cfg)
	if err != nil {
		cfg.Log.Error("init", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		cfg.Log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
