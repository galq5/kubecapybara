package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/client"
	"github.com/galq5/kubecapybara/internal/render"
	"github.com/galq5/kubecapybara/internal/tui"
)

func (o *options) cmdTop() *cobra.Command {
	return &cobra.Command{
		Use:   "top",
		Short: "Interactive dashboard (default command)",
		RunE:  func(cmd *cobra.Command, _ []string) error { return o.runTop(cmd.Context()) },
	}
}

func (o *options) cmdDoctor() *cobra.Command {
	return &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"diag"},
		Short:   "Diagnose what is wrong right now (ranked findings with hints)",
		RunE:    func(cmd *cobra.Command, _ []string) error { return o.runDoctorText(cmd.Context()) },
	}
}

// simple runs a renderer over a freshly loaded view.
func (o *options) simple(ctx context.Context, base bool, js func(*tui.Result) any, text func(render.Style, *tui.Result) error) error {
	res, err := o.load(ctx, base)
	if err != nil {
		return err
	}
	o.warn(res)
	if o.output == "json" {
		return o.jsonOut(os.Stdout, js(res))
	}
	return text(o.style(), res)
}

func (o *options) cmdEdges() *cobra.Command {
	var sortBy string
	var limit int
	c := &cobra.Command{
		Use:     "edges",
		Aliases: []string{"map", "net", "network"},
		Short:   "Pod-to-pod TCP: RTT, connect latency, throughput, retransmits, refused/timeouts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return r.View.Edges }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.Edges(os.Stdout, st, r.View, o.filt(), sortBy, limit)
				return nil
			})
		},
	}
	c.Flags().StringVar(&sortBy, "sort", "traffic", "sort by: traffic, rtt, connect, errors, retrans, bytes, conns")
	c.Flags().IntVar(&limit, "limit", 50, "maximum rows (0 = all)")
	return c
}

func (o *options) cmdPods() *cobra.Command {
	return &cobra.Command{
		Use:   "pods",
		Short: "Per-pod CPU, run queue, time breakdown, memory, throttling, DNS and HTTP summary",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return render.PodRows(r.View, o.filt()) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.Pods(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdPod() *cobra.Command {
	return &cobra.Command{
		Use:   "pod <name>",
		Short: "Why is my pod slow? Time breakdown, dependencies, DNS, HTTP and events of one pod",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := o.load(cmd.Context(), false)
			if err != nil {
				return err
			}
			o.warn(res)
			id, _, err := o.resolvePod(res.View, args[0])
			if err != nil {
				return err
			}
			if o.output == "json" {
				out, in := res.View.EdgesOf(id)
				return o.jsonOut(os.Stdout, map[string]any{"entity": res.View.Entity(id), "outgoing": out, "incoming": in, "events": res.View.EventsOf(id)})
			}
			render.Pod(os.Stdout, o.style(), res.View, id)
			return nil
		},
	}
}

func (o *options) cmdDNS() *cobra.Command {
	return &cobra.Command{
		Use:   "dns",
		Short: "DNS latency, failures, ndots waste per client and per DNS server replica",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.TopDNSNames(r.View, 100) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.DNS(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdHTTP() *cobra.Command {
	return &cobra.Command{
		Use:   "http",
		Short: "HTTP/1.x rate, errors and latency per route (agent --l7)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return r.View.Entities }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.HTTP(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdNodes() *cobra.Command {
	return &cobra.Command{
		Use:     "nodes",
		Aliases: []string{"neighbors", "noisy"},
		Short:   "Noisy neighbours per node: who uses and steals CPU, disk and network; conntrack; drops",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.NodeReports(r.View) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.Nodes(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdEvents() *cobra.Command {
	var types []string
	var limit int
	c := &cobra.Command{
		Use:   "events",
		Short: "Flight recorder events: exec, exit, signals, OOM, DNS and connect failures, HTTP 5xx",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tm := map[string]bool{}
			for _, t := range types {
				tm[t] = true
			}
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return r.View.Events }, func(st render.Style, r *tui.Result) error {
				render.Events(os.Stdout, st, r.View, o.filt(), tm, limit)
				return nil
			})
		},
	}
	c.Flags().StringSliceVar(&types, "type", nil, "event types (exec, exec_session, suspicious_shell, exit, signal, oom, listen, connect, conn_fail, dns_fail, http_5xx)")
	c.Flags().IntVar(&limit, "limit", 200, "maximum events")
	return c
}

func (o *options) cmdRollout() *cobra.Command {
	var watch bool
	c := &cobra.Command{
		Use:   "rollout <deployment>",
		Short: "Did my deploy break anything? Compare the new ReplicaSet with the old ones",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ns, name := splitNS(o.namespace, args[0])
			workload, err := parseWorkload(name)
			if err != nil {
				return err
			}
			kind, name, _ := strings.Cut(workload, "/")
			if kind != "Deployment" {
				return fmt.Errorf("rollout comparison supports Deployments, got %s", kind)
			}
			for {
				res, err := o.load(cmd.Context(), false)
				if err != nil {
					return err
				}
				if ns == "" {
					ns = guessNamespace(res.View, name)
				}
				rep, err := analysis.Rollout(res.View, ns, name)
				if err != nil {
					return err
				}
				if o.output == "json" {
					return o.jsonOut(os.Stdout, rep)
				}
				if watch {
					fmt.Print("\033[H\033[2J")
				}
				render.Rollout(os.Stdout, o.style(), rep)
				if !watch {
					return nil
				}
				select {
				case <-cmd.Context().Done():
					return nil
				case <-time.After(10 * time.Second):
				}
			}
		},
	}
	c.Flags().BoolVar(&watch, "watch", false, "refresh every 10s while the rollout progresses")
	return c
}

// workloadKinds maps kubectl-style kind prefixes to Kubernetes kinds.
var workloadKinds = map[string]string{
	"deployment": "Deployment", "deployments": "Deployment", "deploy": "Deployment",
	"statefulset": "StatefulSet", "statefulsets": "StatefulSet", "sts": "StatefulSet",
	"daemonset": "DaemonSet", "daemonsets": "DaemonSet", "ds": "DaemonSet",
	"job": "Job", "jobs": "Job", "cronjob": "CronJob", "cronjobs": "CronJob", "cj": "CronJob",
	"replicaset": "ReplicaSet", "rs": "ReplicaSet",
}

// splitNS parses "name", "kind/name", "ns/name" and "ns/kind/name". It
// returns the namespace (defNS when absent) and the rest ("kind/name" or
// "name").
func splitNS(defNS, s string) (string, string) {
	parts := strings.Split(s, "/")
	switch len(parts) {
	case 2:
		if _, isKind := workloadKinds[strings.ToLower(parts[0])]; isKind {
			return defNS, s
		}
		return parts[0], parts[1]
	case 3:
		return parts[0], parts[1] + "/" + parts[2]
	}
	return defNS, s
}

// parseWorkload turns "kind/name" or "name" into "Kind/name" (default
// Deployment).
func parseWorkload(s string) (string, error) {
	kind, name, ok := strings.Cut(s, "/")
	if !ok {
		return "Deployment/" + s, nil
	}
	k, known := workloadKinds[strings.ToLower(kind)]
	if !known {
		return "", fmt.Errorf("unknown workload kind %q", kind)
	}
	return k + "/" + name, nil
}

func guessNamespace(v *analysis.View, deploy string) string {
	return guessWorkloadNamespace(v, "Deployment/"+deploy)
}

func guessWorkloadNamespace(v *analysis.View, workload string) string {
	for _, p := range v.Meta.Pods {
		if p.Workload == workload {
			return p.Namespace
		}
	}
	return "default"
}

func (o *options) cmdStartup() *cobra.Command {
	return &cobra.Command{
		Use:   "startup <pod>",
		Short: "Why does my pod start slowly? Startup timeline with DNS, connects, listen and probes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.window = maxDur(o.window, 15*time.Minute)
			res, err := o.load(cmd.Context(), false)
			if err != nil {
				return err
			}
			_, pod, err := o.resolvePod(res.View, args[0])
			if err != nil {
				return err
			}
			if pod == nil {
				return fmt.Errorf("startup analysis needs Kubernetes metadata for %s", args[0])
			}
			rep := analysis.Startup(res.View, pod)
			if evs, err := o.src.PodEvents(cmd.Context(), pod.Namespace, pod.UID); err == nil && len(evs) > 0 {
				analysis.AddPodEvents(rep, evs)
			}
			if o.output == "json" {
				return o.jsonOut(os.Stdout, rep)
			}
			render.Startup(os.Stdout, o.style(), rep)
			return nil
		},
	}
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (o *options) cmdWhyCrash() *cobra.Command {
	return &cobra.Command{
		Use:     "why-crash <pod>",
		Aliases: []string{"crash"},
		Short:   "Why did it crash? Flight recorder: events and resources right before the container died",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.window = maxDur(o.window, 6*time.Hour)
			res, err := o.load(cmd.Context(), false)
			if err != nil {
				return err
			}
			id, _, err := o.resolvePod(res.View, args[0])
			if err != nil {
				return err
			}
			if o.output == "json" {
				return o.jsonOut(os.Stdout, analysis.CrashesOf(res.View, id))
			}
			render.Crashes(os.Stdout, o.style(), res.View, id)
			return nil
		},
	}
}

func (o *options) cmdSecurity() *cobra.Command {
	return &cobra.Command{
		Use:   "security",
		Short: "Exec sessions, shells spawned by apps, undeclared listening ports, internet egress",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any {
				return map[string]any{"undeclaredPorts": analysis.UndeclaredPorts(r.View), "egress": analysis.ExternalEgress(r.View)}
			}, func(st render.Style, r *tui.Result) error {
				render.Security(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdCost() *cobra.Command {
	return &cobra.Command{
		Use:   "cost",
		Short: "Cross-zone traffic per workload pair and its estimated monthly cost",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.CrossZoneCosts(r.View) }, func(st render.Style, r *tui.Result) error {
				render.Cost(os.Stdout, st, r.View)
				return nil
			})
		},
	}
}

func (o *options) cmdNetpol() *cobra.Command {
	return &cobra.Command{
		Use:   "netpol <workload>",
		Short: "Generate a NetworkPolicy from observed traffic (e.g. deployment/payments)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.window < 10*time.Minute {
				o.window = time.Hour
			}
			res, err := o.load(cmd.Context(), false)
			if err != nil {
				return err
			}
			ns, w := splitNS(o.namespace, args[0])
			workload, err := parseWorkload(w)
			if err != nil {
				return err
			}
			if ns == "" {
				ns = guessWorkloadNamespace(res.View, workload)
			}
			y, err := analysis.SuggestNetworkPolicy(res.View, ns, workload)
			if err != nil {
				return err
			}
			fmt.Print(y)
			return nil
		},
	}
}

func (o *options) cmdProfile() *cobra.Command {
	var (
		dur    time.Duration
		hz     int
		folded string
		n      int
	)
	c := &cobra.Command{
		Use:   "profile <pod>",
		Short: "On-demand CPU profile of a pod (top functions, folded stacks for flame graphs)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := o.load(cmd.Context(), false)
			if err != nil {
				return err
			}
			id, pod, err := o.resolvePod(res.View, args[0])
			if err != nil {
				return err
			}
			node := ""
			if pod != nil {
				node = pod.Node
			} else if e := res.View.Entity(id); e != nil {
				node = e.Endpoint.Node
			}
			fmt.Fprintf(os.Stderr, "profiling %s on node %s for %s…\n", id, node, dur)
			prof, err := o.src.Profile(cmd.Context(), node, id, int(dur.Seconds()), hz)
			if err != nil {
				return err
			}
			if folded != "" {
				if err := os.WriteFile(folded, []byte(analysis.Folded(prof)), 0o644); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "folded stacks written to %s (flamegraph.pl %s > flame.svg, or open in speedscope.app)\n", folded, folded)
			}
			if o.output == "json" {
				return o.jsonOut(os.Stdout, prof)
			}
			render.Profile(os.Stdout, o.style(), prof, n)
			return nil
		},
	}
	c.Flags().DurationVarP(&dur, "duration", "d", 10*time.Second, "profile duration (max 2m)")
	c.Flags().IntVar(&hz, "hz", 99, "sampling frequency")
	c.Flags().StringVar(&folded, "folded", "", "write folded stacks to this file")
	c.Flags().IntVar(&n, "top", 25, "number of functions to show")
	return c
}

func (o *options) cmdSnapshot() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "snapshot",
		Short: "Save the current window (and baseline) with cluster metadata to a file for sharing",
		Long:  "Writes a self-contained bundle. Open it later with: kubectl capybara --from-file <file> [doctor|top|...]",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			from, to := o.timeRange()
			snaps, errs := o.src.Snapshots(ctx, from, to, false)
			for _, e := range errs {
				fmt.Fprintln(os.Stderr, "warning:", e)
			}
			if len(snaps) == 0 {
				return fmt.Errorf("no data received from agents")
			}
			b := client.Bundle{Created: time.Now(), From: from, To: to, Snapshots: snaps}
			if o.baseline > 0 {
				b.Baseline, _ = o.src.Snapshots(ctx, from.Add(-o.baseline), from, true)
			}
			b.Meta, _ = o.src.Meta(ctx)
			if out == "" {
				out = fmt.Sprintf("capybara-snapshot-%s.json", time.Now().Format("20060102-150405"))
			}
			f, err := os.Create(out)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := o.jsonOut(f, b); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "snapshot of %d node(s) written to %s\n", len(snaps), out)
			return nil
		},
	}
	c.Flags().StringVar(&out, "file", "", "output file (default capybara-snapshot-<time>.json)")
	return c
}

func (o *options) cmdVersion(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run:   func(*cobra.Command, []string) { fmt.Println(version) },
	}
}

func (o *options) cmdRightsize() *cobra.Command {
	price := analysis.DefaultPricing
	c := &cobra.Command{
		Use:     "rightsize",
		Aliases: []string{"rightsizing", "requests"},
		Short:   "Compare measured CPU/memory with requests and limits: recommendations and savings",
		Long:    "Use a long window (e.g. -w 6h): recommendations are based on the peak observed in the window.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// sizing from one minute of data is meaningless: default to 6h
			if f := cmd.Flag("window"); f == nil || !f.Changed {
				o.window = 6 * time.Hour
			}
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.Rightsize(r.View, price) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.Rightsize(os.Stdout, st, r.View, o.filt(), price)
				return nil
			})
		},
	}
	c.Flags().Float64Var(&price.CorePerHour, "cost-per-core-hour", price.CorePerHour, "USD per vCPU hour")
	c.Flags().Float64Var(&price.GiBPerHour, "cost-per-gib-hour", price.GiBPerHour, "USD per GiB of memory per hour")
	return c
}

func (o *options) cmdServices() *cobra.Command {
	return &cobra.Command{
		Use:     "services",
		Aliases: []string{"svc", "balance"},
		Short:   "How evenly each Service spreads connections over its backends",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.ServiceBalances(r.View) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.Services(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdOOM() *cobra.Command {
	return &cobra.Command{
		Use:   "oom",
		Short: "Pods trending towards their memory limit, with time to OOM",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f := cmd.Flag("window"); f == nil || !f.Changed {
				o.window = 10 * time.Minute
			}
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.OOMRisks(r.View) }, func(st render.Style, r *tui.Result) error {
				render.OOMRisks(os.Stdout, st, r.View)
				return nil
			})
		},
	}
}

func (o *options) cmdDB() *cobra.Command {
	return &cobra.Command{
		Use:     "db",
		Aliases: []string{"queries", "sql"},
		Short:   "Slowest and failing Postgres/MySQL/Redis statements per pod (agent --l7, plaintext only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return r.View.Entities }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.DB(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdFiles() *cobra.Command {
	return &cobra.Command{
		Use:   "files",
		Short: "Which files pods wait on: slow reads, writes and fsyncs with filesystem type (agent --files)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return r.View.Entities }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.Files(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}
