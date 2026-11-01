// Command capybara-hub aggregates kubecapybara agents for large clusters:
// clients make one request per refresh to the hub instead of one per agent
// through the API server, and metadata comes from informers instead of
// repeated LIST calls.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/galq5/kubecapybara/internal/hub"
)

var version = "dev"

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		listen        = flag.String("listen", ":9877", "API address")
		kubeconfig    = flag.String("kubeconfig", "", "kubeconfig path (default: in-cluster config)")
		agentNS       = flag.String("agent-namespace", envOr("POD_NAMESPACE", "capybara"), "namespace where the agent DaemonSet runs")
		agentSelector = flag.String("agent-selector", "app.kubernetes.io/name=capybara-agent", "label selector of agent pods")
		agentPort     = flag.Int("agent-port", 9876, "agent API port")
		clusterDomain = flag.String("cluster-domain", "cluster.local", "cluster DNS domain")
		concurrency   = flag.Int("concurrency", 64, "parallel agent requests")
		agentTimeout  = flag.Duration("agent-timeout", 20*time.Second, "timeout of one agent request")
		cacheTTL      = flag.Duration("cache-ttl", 5*time.Second, "reuse a fan-out result for this long (the agent interval)")
		metaRefresh   = flag.Duration("meta-refresh", 10*time.Second, "rebuild metadata from the informer caches at most this often")
		defaultTop    = flag.Int("default-top", 0, "keep only the top N flows/entities when a request does not say (0: all)")
		showVersion   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := restConfig(*kubeconfig)
	if err != nil {
		log.Error("kubernetes config", "err", err)
		os.Exit(1)
	}
	cfg.QPS, cfg.Burst = 20, 40
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error("kubernetes client", "err", err)
		os.Exit(1)
	}
	h, err := hub.New(hub.Config{
		AgentNamespace: *agentNS, AgentSelector: *agentSelector, AgentPort: *agentPort,
		Token: strings.TrimSpace(os.Getenv("CAPYBARA_TOKEN")), ClusterDomain: *clusterDomain,
		Concurrency: *concurrency, AgentTimeout: *agentTimeout, CacheTTL: *cacheTTL,
		MetaRefresh: *metaRefresh, DefaultTop: *defaultTop,
	}, cs, log)
	if err != nil {
		log.Error("hub", "err", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	srv := &http.Server{Addr: *listen, Handler: h.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			cancel()
		}
	}()
	log.Info("capybara-hub starting", "version", version, "listen", *listen, "agents", *agentNS+"/"+*agentSelector,
		"auth", os.Getenv("CAPYBARA_TOKEN") != "")
	start := time.Now()
	if err := h.Start(ctx); err != nil {
		log.Error("hub", "err", err)
		os.Exit(1)
	}
	log.Info("informer caches synced", "took", time.Since(start).Round(time.Millisecond))
	<-ctx.Done()
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	_ = srv.Shutdown(sctx)
}

func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
}
