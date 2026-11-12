// Command capybara-controller evaluates the kubecapybara doctor periodically,
// keeps CapyFinding custom resources in sync (kubectl get capyfindings -A)
// and sends Slack / webhook notifications when findings fire or resolve.
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

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/client"
	"github.com/galq5/kubecapybara/internal/controller"
)

var version = "dev"

func main() {
	var (
		kubeconfig    = flag.String("kubeconfig", "", "kubeconfig path (default: in-cluster config)")
		interval      = flag.Duration("interval", time.Minute, "how often to evaluate the doctor")
		window        = flag.Duration("window", 5*time.Minute, "time window analysed at each evaluation")
		baseline      = flag.Duration("baseline", time.Hour, "baseline window used to detect regressions (0 disables)")
		namespace     = flag.String("namespace", envOr("POD_NAMESPACE", "capybara"), "namespace for findings not tied to a pod")
		agentNS       = flag.String("agent-namespace", envOr("POD_NAMESPACE", "capybara"), "namespace where the agent DaemonSet runs")
		agentSelector = flag.String("agent-selector", "app.kubernetes.io/name=capybara-agent", "label selector of agent pods")
		agentPort     = flag.Int("agent-port", 9876, "agent API port")
		tokenSecret   = flag.String("agent-token-secret", "capybara-agent-token", "Secret holding the agent API token")
		clusterDomain = flag.String("cluster-domain", "cluster.local", "cluster DNS domain")
		cluster       = flag.String("cluster-name", os.Getenv("CAPYBARA_CLUSTER_NAME"), "cluster name shown in notifications")
		sloFile       = flag.String("slo-file", os.Getenv("CAPYBARA_SLO_FILE"), "YAML file with SLO definitions")
		doctorFile    = flag.String("doctor-config", os.Getenv("CAPYBARA_DOCTOR_CONFIG"), "YAML file muting doctor rules and overriding their thresholds")
		minSev        = flag.String("min-severity", "warn", "lowest severity stored and notified: info, warn or crit")
		resolveAfter  = flag.Duration("resolve-after", 10*time.Minute, "resolve a finding after it has not been seen for this long")
		keepResolved  = flag.Duration("keep-resolved", time.Hour, "delete resolved findings after this long")
		costPerGB     = flag.Float64("cost-per-gb", 0.01, "inter-zone transfer price in USD per GB per direction")
		hubURL        = flag.String("hub", "", "read agent data from capybara-hub at this URL instead of every agent")
		top           = flag.Int("top", 0, "with --hub: only evaluate the N busiest connections/pods plus the N with the most errors (0: all)")
		once          = flag.Bool("once", false, "reconcile once and exit")
		showVersion   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log, *kubeconfig, controller.Config{
		Namespace: *namespace, Cluster: *cluster, Interval: *interval, Window: *window, Baseline: *baseline,
		ResolveAfter: *resolveAfter, KeepResolved: *keepResolved,
		Options: analysis.Options{ClusterDomain: *clusterDomain, CostPerGB: *costPerGB},
	}, *minSev, *sloFile, *doctorFile, *agentNS, *agentSelector, *agentPort, *tokenSecret, *hubURL, *top, *once); err != nil {
		log.Error("controller stopped", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseSeverity(s string) (analysis.Severity, error) {
	switch strings.ToLower(s) {
	case "info":
		return analysis.SevInfo, nil
	case "warn", "warning":
		return analysis.SevWarn, nil
	case "crit", "critical":
		return analysis.SevCrit, nil
	}
	return 0, fmt.Errorf("unknown severity %q (info, warn or crit)", s)
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

func run(log *slog.Logger, kubeconfig string, cfg controller.Config, minSev, sloFile, doctorFile, agentNS, selector string, port int, tokenSecret, hubURL string, top int, once bool) error {
	sev, err := parseSeverity(minSev)
	if err != nil {
		return err
	}
	cfg.MinSeverity = sev
	if cfg.Interval <= 0 || cfg.Window <= 0 {
		return fmt.Errorf("--interval and --window must be positive")
	}
	if sloFile != "" {
		if cfg.SLOs, err = analysis.LoadSLOs(sloFile); err != nil {
			return err
		}
	}
	if doctorFile != "" {
		if cfg.Options.Doctor, err = analysis.LoadDoctorConfig(doctorFile); err != nil {
			return err
		}
	}
	rc, err := restConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}
	rc.QPS, rc.Burst = 20, 40
	rc.Timeout = 2 * time.Minute
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return err
	}

	var notifiers controller.Multi
	if u := os.Getenv("CAPYBARA_WEBHOOK_URL"); u != "" {
		notifiers = append(notifiers, &controller.Webhook{URL: u})
	}
	if u := os.Getenv("CAPYBARA_SLACK_WEBHOOK_URL"); u != "" {
		notifiers = append(notifiers, &controller.Webhook{URL: u, Slack: true})
	}

	var src client.Source = client.NewKubeSource(cs, agentNS, selector, port, cfg.Options.ClusterDomain, tokenSecret)
	if hubURL != "" {
		src = &client.HubSource{URL: hubURL, CS: cs, Namespace: agentNS, TokenSecret: tokenSecret, Top: top}
	}
	c := controller.New(cfg, src, dyn, notifiers, log)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Info("capybara-controller started", "version", version, "interval", cfg.Interval, "window", cfg.Window,
		"source", src.Describe(), "notifiers", len(notifiers), "slos", len(cfg.SLOs), "min-severity", cfg.MinSeverity.String(), "muted-rules", len(cfg.Options.Doctor.Mute))
	if once {
		return c.RunOnce(ctx)
	}
	return c.Run(ctx)
}
