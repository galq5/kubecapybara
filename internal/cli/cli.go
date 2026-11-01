// Package cli implements the kubectl-capybara command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/client"
	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
	"github.com/galq5/kubecapybara/internal/render"
	"github.com/galq5/kubecapybara/internal/tui"
)

type options struct {
	hub           string
	top           int
	refresh       time.Duration
	kubeconfig    string
	kubeContext   string
	namespace     string
	agentNS       string
	agentSelector string
	agentPort     int
	agents        []string
	fromFile      string
	window        time.Duration
	baseline      time.Duration
	clusterDomain string
	costPerGB     float64
	output        string
	noColor       bool
	noK8s         bool
	filter        string

	agentToken       string
	agentTokenSecret string
	sloFile          string
	slos             []analysis.SLO

	src client.Source
	cs  kubernetes.Interface

	baseCache *analysis.View
	baseAt    time.Time
}

// NewRoot builds the root command.
func NewRoot(version string) *cobra.Command {
	o := &options{}
	root := &cobra.Command{
		Use:   "kubectl-capybara",
		Short: "eBPF observability for Kubernetes: pod-to-pod latency, DNS, CPU time, crashes, rollouts",
		Long: `kubecapybara answers the questions you ask every day:

  why is my pod slow?          kubectl capybara pod <pod>
  what is broken right now?    kubectl capybara doctor
  did my deploy break things?  kubectl capybara rollout <deployment>
  why did it crash?            kubectl capybara why-crash <pod>
  why does it start slowly?    kubectl capybara startup <pod>
  what does it talk to?        kubectl capybara edges -f <name>

Run without arguments for the interactive dashboard.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.runTop(cmd.Context())
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "version" {
				return nil
			}
			return o.init()
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&o.kubeconfig, "kubeconfig", "", "path to the kubeconfig file")
	pf.StringVar(&o.kubeContext, "context", "", "kubeconfig context to use")
	pf.StringVarP(&o.namespace, "namespace", "n", "", "only show workloads in this namespace")
	pf.StringVar(&o.agentNS, "agent-namespace", "capybara", "namespace where the agent DaemonSet runs")
	pf.StringVar(&o.agentSelector, "agent-selector", "app.kubernetes.io/name=capybara-agent", "label selector of agent pods")
	pf.IntVar(&o.agentPort, "agent-port", 9876, "agent API port")
	pf.StringSliceVar(&o.agents, "agent", nil, "talk to agents directly (http://host:9876), repeatable; bypasses the API server proxy")
	pf.StringVar(&o.agentToken, "agent-token", os.Getenv("CAPYBARA_AGENT_TOKEN"), "agent API token for --agent (default $CAPYBARA_AGENT_TOKEN)")
	pf.StringVar(&o.agentTokenSecret, "agent-token-secret", "capybara-agent-token", "Secret in the agent namespace holding the agent API token (key \"token\")")
	pf.StringVar(&o.fromFile, "from-file", "", "read data from a snapshot bundle instead of live agents")
	pf.DurationVarP(&o.window, "window", "w", time.Minute, "time window to analyse")
	pf.DurationVar(&o.baseline, "baseline", time.Hour, "baseline window before --window used to detect regressions (0 disables)")
	pf.StringVar(&o.clusterDomain, "cluster-domain", "cluster.local", "cluster DNS domain")
	pf.Float64Var(&o.costPerGB, "cost-per-gb", 0.01, "inter-zone transfer price in USD per GB per direction")
	pf.StringVarP(&o.output, "output", "o", "text", "output format: text or json")
	pf.BoolVar(&o.noColor, "no-color", false, "disable colors")
	pf.BoolVar(&o.noK8s, "no-k8s", false, "do not query the Kubernetes API for names (with --agent)")
	pf.StringVarP(&o.filter, "filter", "f", "", "only show rows containing this text")
	pf.StringVar(&o.hub, "hub", "auto", "capybara-hub: auto (use it when deployed in the agent namespace), off (query every agent), or a URL")
	pf.IntVar(&o.top, "top", 0, "with capybara-hub: only fetch the N busiest connections/pods plus the N with the most errors (0: all)")
	pf.DurationVar(&o.refresh, "refresh", 5*time.Second, "dashboard refresh interval")
	pf.StringVar(&o.sloFile, "slo-file", os.Getenv("CAPYBARA_SLO_FILE"), "YAML file with SLO definitions (default $CAPYBARA_SLO_FILE)")

	root.AddCommand(
		o.cmdTop(), o.cmdDoctor(), o.cmdEdges(), o.cmdPods(), o.cmdPod(), o.cmdDNS(), o.cmdHTTP(), o.cmdNodes(),
		o.cmdEvents(), o.cmdRollout(), o.cmdStartup(), o.cmdWhyCrash(), o.cmdSecurity(), o.cmdCost(),
		o.cmdNetpol(), o.cmdProfile(), o.cmdSnapshot(), o.cmdVersion(version),
		o.cmdRightsize(), o.cmdServices(), o.cmdOOM(), o.cmdDB(), o.cmdFiles(),
		o.cmdOutliers(), o.cmdSLO(), o.cmdPools(), o.cmdIncident(), o.cmdProfileDiff(),
		o.cmdControlPlane(), o.cmdCounters(), o.cmdMap(), o.cmdVoIP(),
	)
	return root
}

// Execute runs the CLI.
func Execute(version string) {
	rest.SetDefaultWarningHandler(rest.NoWarnings{})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	root := NewRoot(version)
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func (o *options) style() render.Style {
	color := !o.noColor && os.Getenv("NO_COLOR") == "" && isatty.IsTerminal(os.Stdout.Fd())
	return render.Style{Color: color}
}

func (o *options) kubeClient() (kubernetes.Interface, error) {
	if o.cs != nil {
		return o.cs, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if o.kubeconfig != "" {
		rules.ExplicitPath = o.kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: o.kubeContext}).ClientConfig()
	if err != nil {
		return nil, err
	}
	cfg.QPS, cfg.Burst = 50, 100
	cfg.Timeout = 3 * time.Minute
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	o.cs = cs
	return cs, nil
}

func (o *options) init() error {
	if o.output != "text" && o.output != "json" {
		return fmt.Errorf("unsupported output %q (text or json)", o.output)
	}
	if o.sloFile != "" {
		slos, err := analysis.LoadSLOs(o.sloFile)
		if err != nil {
			return err
		}
		o.slos = slos
	}
	switch {
	case o.fromFile != "":
		fs, err := client.NewFileSource(o.fromFile)
		if err != nil {
			return err
		}
		o.src = fs
	case len(o.agents) > 0:
		ds := &client.DirectSource{URLs: o.agents, Token: o.agentToken}
		if !o.noK8s {
			if cs, err := o.kubeClient(); err == nil {
				var (
					failed bool
					cached *k8smeta.Meta
				)
				ds.ChangesFn = func(ctx context.Context, since time.Time) ([]k8smeta.Change, error) {
					if failed {
						return nil, nil
					}
					m, _ := ds.MetaFn(ctx)
					return k8smeta.LoadChanges(ctx, cs, m, since)
				}
				ds.EventsFn = func(ctx context.Context, ns, uid string) ([]k8smeta.PodEvent, error) {
					if failed {
						return nil, nil
					}
					c, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					return k8smeta.LoadPodEvents(c, cs, ns, uid)
				}
				ds.MetaFn = func(ctx context.Context) (*k8smeta.Meta, error) {
					if failed {
						return nil, nil
					}
					if cached != nil && time.Since(cached.Loaded) < 30*time.Second {
						return cached, nil
					}
					c, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					m, err := k8smeta.Load(c, cs, o.clusterDomain)
					if err != nil {
						failed = true
						return nil, nil
					}
					cached = m
					return m, nil
				}
			}
		}
		o.src = ds
	case strings.HasPrefix(o.hub, "http://") || strings.HasPrefix(o.hub, "https://"):
		hs := &client.HubSource{URL: o.hub, Token: o.agentToken, Namespace: o.agentNS, TokenSecret: o.agentTokenSecret,
			ScopeNamespace: o.namespace, Top: o.top}
		if cs, err := o.kubeClient(); err == nil && !o.noK8s {
			hs.CS = cs // reads the token Secret when --agent-token is not set
		}
		o.src = hs
	default:
		cs, err := o.kubeClient()
		if err != nil {
			return fmt.Errorf("loading kubeconfig: %w (use --agent URL or --from-file to run without a cluster)", err)
		}
		if o.hub != "off" {
			if o.hub != "auto" {
				return fmt.Errorf("--hub must be auto, off or a URL, not %q", o.hub)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			svc, port, err := client.DiscoverHub(ctx, cs, o.agentNS)
			cancel()
			if err == nil && svc != "" {
				o.src = &client.HubSource{CS: cs, Namespace: o.agentNS, Service: svc, Port: port,
					Token: o.agentToken, TokenSecret: o.agentTokenSecret, ScopeNamespace: o.namespace, Top: o.top}
				return nil
			}
		}
		o.src = client.NewKubeSource(cs, o.agentNS, o.agentSelector, o.agentPort, o.clusterDomain, o.agentTokenSecret)
	}
	return nil
}

func (o *options) aopts() analysis.Options {
	return analysis.Options{ClusterDomain: o.clusterDomain, CostPerGB: o.costPerGB}
}

func (o *options) timeRange() (time.Time, time.Time) {
	if fs, ok := o.src.(*client.FileSource); ok {
		b := fs.Bundle()
		return b.From, b.To
	}
	to := time.Now()
	return to.Add(-o.window), to
}

// load fetches the current view and, when withBase, the baseline view.
func (o *options) load(ctx context.Context, withBase bool) (*tui.Result, error) {
	from, to := o.timeRange()
	snaps, errs := o.src.Snapshots(ctx, from, to, false)
	res := &tui.Result{}
	for _, e := range errs {
		res.Warnings = append(res.Warnings, e.Error())
	}
	if len(snaps) == 0 {
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
		return nil, errors.New("no data received from agents")
	}
	meta, err := o.src.Meta(ctx)
	if err != nil {
		res.Warnings = append(res.Warnings, "kubernetes metadata unavailable: "+err.Error())
	}
	res.View = analysis.Build(snaps, meta, o.aopts())
	if withBase && o.baseline > 0 {
		res.Base = o.baselineView(ctx, from, meta)
	}
	res.Findings = analysis.DoctorWith(res.View, res.Base, o.slos)
	if len(o.slos) > 0 {
		res.SLOs = analysis.EvaluateSLOs(res.View, res.Base, o.slos)
	}
	return res, nil
}

// baselineCacheTTL bounds how often the (large, slowly changing) baseline is
// re-fetched by the dashboard.
const baselineCacheTTL = time.Minute

// baselineView returns the view of the baseline window ending at from. It
// uses lite snapshots, is cached for a minute and its time range is the
// range actually covered by agent data (clamped to the requested one), so
// rates are not diluted when agents have less history than requested.
func (o *options) baselineView(ctx context.Context, from time.Time, meta *k8smeta.Meta) *analysis.View {
	if o.baseCache != nil && time.Since(o.baseAt) < baselineCacheTTL {
		return o.baseCache
	}
	bf := from.Add(-o.baseline)
	bs, _ := o.src.Snapshots(ctx, bf, from, true)
	if len(bs) == 0 || !hasData(bs) {
		return nil
	}
	b := analysis.Build(bs, meta, o.aopts())
	if b.From.Before(bf) {
		b.From = bf
	}
	if b.To.IsZero() || b.To.After(from) {
		b.To = from
	}
	o.baseCache, o.baseAt = b, time.Now()
	return b
}

func hasData(snaps []*model.Snapshot) bool {
	for _, s := range snaps {
		if len(s.Pairs) > 0 || len(s.Entities) > 0 {
			return true
		}
	}
	return false
}

func (o *options) warn(res *tui.Result) {
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
}

func (o *options) jsonOut(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (o *options) filt() render.Filter {
	return render.Filter{Text: o.filter, Namespace: o.namespace}
}

// resolvePod finds a pod by name, ns/name, UID prefix or entity ID.
func (o *options) resolvePod(v *analysis.View, query string) (string, *k8smeta.Pod, error) {
	if strings.HasPrefix(query, "pod:") {
		uid := strings.TrimPrefix(query, "pod:")
		return query, v.Meta.Pods[uid], nil
	}
	if pods := v.Meta.FindPods(o.namespace, query); len(pods) > 0 {
		if len(pods) > 1 && pods[0].Name != query && !strings.HasSuffix(query, "/"+pods[0].Name) {
			fmt.Fprintf(os.Stderr, "note: %d pods match %q, using the newest: %s/%s\n", len(pods), query, pods[0].Namespace, pods[0].Name)
		}
		return "pod:" + pods[0].UID, pods[0], nil
	}
	// no metadata: match entity IDs / short names
	for id, e := range v.Entities {
		if strings.HasPrefix(strings.TrimPrefix(id, "pod:"), query) || e.Endpoint.Display() == query || e.Endpoint.Name == query {
			return id, e.Pod, nil
		}
	}
	return "", nil, fmt.Errorf("pod %q not found", query)
}

func (o *options) runTop(ctx context.Context) error {
	if o.output == "json" || !isatty.IsTerminal(os.Stdout.Fd()) {
		return o.runDoctorText(ctx)
	}
	interval := o.refresh
	if interval < time.Second {
		interval = time.Second
	}
	if _, ok := o.src.(*client.FileSource); ok {
		interval = time.Hour
	}
	return tui.Run(func(ctx context.Context) (*tui.Result, error) { return o.load(ctx, true) },
		tui.Options{Source: o.src.Describe(), Namespace: o.namespace, Interval: interval, Window: o.window})
}

func (o *options) runDoctorText(ctx context.Context) error {
	res, err := o.load(ctx, true)
	if err != nil {
		return err
	}
	o.warn(res)
	if o.output == "json" {
		return o.jsonOut(os.Stdout, res.Findings)
	}
	st := o.style()
	render.Header(os.Stdout, st, res.View, o.src.Describe())
	fmt.Println()
	render.Doctor(os.Stdout, st, res.Findings, o.filt())
	return nil
}
