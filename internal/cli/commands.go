package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/client"
	"github.com/galq5/kubecapybara/internal/model"
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
	var list bool
	c := &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"diag"},
		Short:   "Diagnose what is wrong right now: findings grouped per workload, likely causes first, with hints",
		Long: `Runs every doctor rule over the window and groups what it finds by the
workload (or node) it is about: the findings of one workload are usually one
problem seen from several angles. Within a problem the likely causes come
first (crashes and memory, then CPU and disk, then dependencies, then the
symptoms). Findings not seen in the baseline window are marked "new".

Recommendations (cost, hygiene) are listed apart from the problems.
--flat prints the plain ranked list; -o json always does.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if list {
				listRules(os.Stdout)
				return nil
			}
			return o.runDoctorText(cmd.Context())
		},
	}
	c.Flags().BoolVar(&o.flat, "flat", false, "one ranked list of findings instead of problems per workload")
	c.Flags().BoolVar(&list, "list-rules", false, "list the doctor rules and thresholds (for --mute and --doctor-config) and exit")
	return c
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
		Aliases: []string{"net", "network"},
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
	var perPod bool
	c := &cobra.Command{
		Use:   "http",
		Short: "HTTP/1.x rate, errors and latency per route and workload (agent --l7)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return r.View.Entities }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.HTTP(os.Stdout, st, r.View, o.filt(), perPod)
				return nil
			})
		},
	}
	c.Flags().BoolVar(&perPod, "per-pod", false, "one row per pod instead of merging the replicas of a workload")
	return c
}

func (o *options) cmdNodes() *cobra.Command {
	return &cobra.Command{
		Use:     "nodes",
		Aliases: []string{"neighbors", "noisy"},
		Short:   "Noisy neighbours per node: who uses and steals CPU, disk and network; conntrack; drops",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.NodeReports(r.View) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.Nodes(os.Stdout, st, r.View, o.filt(), 0)
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
	var (
		by     string
		label  string
		egress float64
	)
	price := analysis.DefaultPricing
	c := &cobra.Command{
		Use:   "cost",
		Short: "Cost per namespace or team (requests, actual use, waste, cross-zone, internet egress), rightsizing and cross-zone pairs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f := cmd.Flag("window"); f == nil || !f.Changed {
				o.window = time.Hour
			}
			if label != "" {
				by = "team"
			}
			return o.simple(cmd.Context(), false, func(r *tui.Result) any {
				return map[string]any{"groups": analysis.CostByGroup(r.View, label, price, egress), "crossZone": analysis.CrossZoneCosts(r.View)}
			}, func(st render.Style, r *tui.Result) error {
				render.Section(os.Stdout, st, "Cost per "+by)
				render.CostByGroup(os.Stdout, st, analysis.CostByGroup(r.View, label, price, egress), by, o.filt())
				render.Cost(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
	c.Flags().StringVar(&by, "by", "namespace", "group by namespace (or team with --team-label)")
	c.Flags().StringVar(&label, "team-label", "", "pod label holding the team name (e.g. team); pods without it fall back to their namespace")
	c.Flags().Float64Var(&egress, "egress-cost-per-gb", 0.09, "USD per GB sent to the internet")
	c.Flags().Float64Var(&price.CorePerHour, "cost-per-core-hour", price.CorePerHour, "USD per vCPU hour")
	c.Flags().Float64Var(&price.GiBPerHour, "cost-per-gib-hour", price.GiBPerHour, "USD per GiB of memory per hour")
	return c
}

func (o *options) cmdMap() *cobra.Command {
	var format string
	c := &cobra.Command{
		Use:   "map",
		Short: "Export the dependency map (workload to workload) as Mermaid or Graphviz, coloured by health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f := cmd.Flag("window"); f == nil || !f.Changed {
				o.window = 15 * time.Minute
			}
			res, err := o.load(cmd.Context(), false)
			if err != nil {
				return err
			}
			o.warn(res)
			edges, health := analysis.DependencyMap(res.View, res.Findings)
			if o.filter != "" {
				var kept []analysis.MapEdge
				for _, e := range edges {
					if strings.Contains(e.From, o.filter) || strings.Contains(e.To, o.filter) {
						kept = append(kept, e)
					}
				}
				edges = kept
			}
			switch format {
			case "mermaid":
				fmt.Print(analysis.Mermaid(edges, health))
			case "dot":
				fmt.Print(analysis.Dot(edges, health))
			case "json":
				return o.jsonOut(os.Stdout, map[string]any{"edges": edges, "health": health})
			default:
				return fmt.Errorf("unknown format %q (mermaid, dot, json)", format)
			}
			return nil
		},
	}
	c.Flags().StringVar(&format, "format", "mermaid", "mermaid, dot or json")
	return c
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
	var perPod bool
	c := &cobra.Command{
		Use:     "db",
		Aliases: []string{"queries", "sql"},
		Short:   "Slowest and failing database statements per workload: Postgres, MySQL, Redis, Cassandra, Kafka, MongoDB, Memcached (agent --l7, plaintext only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return r.View.Entities }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.DB(os.Stdout, st, r.View, o.filt(), perPod)
				return nil
			})
		},
	}
	c.Flags().BoolVar(&perPod, "per-pod", false, "one row per pod instead of merging the replicas of a workload")
	return c
}

func (o *options) cmdVoIP() *cobra.Command {
	return &cobra.Command{
		Use:     "voip",
		Aliases: []string{"sip", "rtp", "calls"},
		Short:   "SIP calls (answer ratio, failures, post-dial delay) and RTP quality (loss, jitter, one-way audio) per pod (agent --voip)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.VoIP(r.View) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.VoIP(os.Stdout, st, r.View, o.filt())
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

func (o *options) cmdOutliers() *cobra.Command {
	return &cobra.Command{
		Use:     "outliers",
		Aliases: []string{"replicas"},
		Short:   "Replicas much worse than their siblings (latency, errors, RTT, CPU wait...)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f := cmd.Flag("window"); f == nil || !f.Changed {
				o.window = 5 * time.Minute
			}
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.Outliers(r.View) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.Outliers(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdSLO() *cobra.Command {
	return &cobra.Command{
		Use:   "slo",
		Short: "Error budget burn rates of SLOs defined in --slo-file",
		Long: `SLOs are defined in a YAML file (--slo-file or $CAPYBARA_SLO_FILE):

  slos:
    - name: checkout
      workload: shop/Deployment/checkout   # or: service: shop/checkout
      availability: 99.5                   # % of requests without 5xx
      latency: 300ms                       # threshold...
      latencyObjective: 99                 # ...met by 99% of requests

Burn rates are computed for --window (default 5m here) and the --baseline
window (default 1h). HTTP/1.x data requires the agent's --l7 flag.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f := cmd.Flag("window"); f == nil || !f.Changed {
				o.window = 5 * time.Minute
			}
			res, err := o.load(cmd.Context(), true)
			if err != nil {
				return err
			}
			o.warn(res)
			st := analysis.EvaluateSLOs(res.View, res.Base, o.slos)
			if o.output == "json" {
				return o.jsonOut(os.Stdout, st)
			}
			render.SLOs(os.Stdout, o.style(), st)
			return nil
		},
	}
}

func (o *options) cmdPools() *cobra.Command {
	return &cobra.Command{
		Use:     "pools",
		Aliases: []string{"connections"},
		Short:   "Connection pools: open and idle connections per client and dependency, connect storms",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := o.load(cmd.Context(), true)
			if err != nil {
				return err
			}
			o.warn(res)
			if o.output == "json" {
				return o.jsonOut(os.Stdout, analysis.Pools(res.View, res.Base))
			}
			render.Header(os.Stdout, o.style(), res.View, o.src.Describe())
			render.Pools(os.Stdout, o.style(), res.View, res.Base, o.filt())
			return nil
		},
	}
}

func (o *options) cmdIncident() *cobra.Command {
	var (
		since time.Duration
		steps int
	)
	c := &cobra.Command{
		Use:   "incident",
		Short: "Timeline of what changed and what broke: rollouts, scaling, evictions, crashes, metric jumps with likely causes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if steps < 3 {
				steps = 3
			}
			to := time.Now()
			from := to.Add(-since)
			o.window = since
			whole, err := o.load(ctx, false)
			if err != nil {
				return err
			}
			o.warn(whole)
			meta := whole.View.Meta
			step := since / time.Duration(steps)
			views := make([]*analysis.View, steps)
			errs := make([]error, steps)
			var wg sync.WaitGroup
			sem := make(chan struct{}, 4)
			for i := 0; i < steps; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					f := from.Add(time.Duration(i) * step)
					snaps, es := o.src.Snapshots(ctx, f, f.Add(step), true)
					if len(snaps) == 0 {
						if len(es) > 0 {
							errs[i] = es[0]
						}
						return
					}
					v := analysis.Build(snaps, meta, o.aopts())
					v.From, v.To = f, f.Add(step)
					views[i] = v
				}(i)
			}
			wg.Wait()
			var vs []*analysis.View
			for i, v := range views {
				if v != nil {
					vs = append(vs, v)
				} else if errs[i] != nil {
					fmt.Fprintln(os.Stderr, "warning:", errs[i])
				}
			}
			changes, err := o.src.Changes(ctx, from)
			if err != nil {
				fmt.Fprintln(os.Stderr, "warning: cluster changes unavailable:", err)
			}
			items := analysis.Incident(vs, whole.View, changes)
			if o.output == "json" {
				return o.jsonOut(os.Stdout, items)
			}
			st := o.style()
			fmt.Printf("%s %s → %s (%d steps of %s)\n\n", st.Title("incident timeline"), from.Format("15:04:05"), to.Format("15:04:05"), len(vs), step.Round(time.Second))
			render.Incident(os.Stdout, st, items)
			return nil
		},
	}
	c.Flags().DurationVar(&since, "since", 30*time.Minute, "how far back to look (agents keep 6h; Kubernetes events usually 1h)")
	c.Flags().IntVar(&steps, "steps", 15, "number of time buckets used to detect metric changes")
	return c
}

func (o *options) cmdProfileDiff() *cobra.Command {
	var (
		dur  time.Duration
		hz   int
		pods []string
		n    int
	)
	c := &cobra.Command{
		Use:   "profile-diff [deployment]",
		Short: "Compare CPU profiles of the new and the previous revision of a deployment (or two pods with --pods a,b)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			res, err := o.load(ctx, false)
			if err != nil {
				return err
			}
			v := res.View
			type target struct {
				id, node, name string
			}
			var a, b target
			switch {
			case len(pods) == 2:
				for i, q := range pods {
					id, pod, err := o.resolvePod(v, q)
					if err != nil {
						return err
					}
					t := target{id: id, name: q}
					if pod != nil {
						t.node, t.name = pod.Node, pod.Namespace+"/"+pod.Name
					}
					if i == 0 {
						a = t
					} else {
						b = t
					}
				}
			case len(args) == 1:
				ns, name := splitNS(o.namespace, args[0])
				wl, err := parseWorkload(name)
				if err != nil {
					return err
				}
				_, dname, _ := strings.Cut(wl, "/")
				if ns == "" {
					ns = guessNamespace(v, dname)
				}
				rep, err := analysis.Rollout(v, ns, dname)
				if err != nil {
					return err
				}
				if len(rep.Groups) < 2 {
					return fmt.Errorf("deployment %s/%s runs a single revision: use --pods a,b to compare two pods", ns, dname)
				}
				pick := func(g *analysis.RolloutGroup) target {
					p := g.Pods[0]
					return target{id: "pod:" + p.UID, node: p.Node, name: fmt.Sprintf("%s (rev %s)", p.Name, g.Revision)}
				}
				a, b = pick(rep.Groups[1]), pick(rep.Groups[0])
			default:
				return fmt.Errorf("give a deployment or --pods old,new")
			}
			secs := int(dur.Seconds())
			fmt.Fprintf(os.Stderr, "profiling %s and %s for %s…\n", a.name, b.name, dur)
			var pa, pb *model.Profile
			var ea, eb error
			if a.node != b.node { // one profile per node at a time: parallel only across nodes
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); pa, ea = o.src.Profile(ctx, a.node, a.id, secs, hz) }()
				go func() { defer wg.Done(); pb, eb = o.src.Profile(ctx, b.node, b.id, secs, hz) }()
				wg.Wait()
			} else {
				pa, ea = o.src.Profile(ctx, a.node, a.id, secs, hz)
				if ea == nil {
					pb, eb = o.src.Profile(ctx, b.node, b.id, secs, hz)
				}
			}
			if err := errors.Join(ea, eb); err != nil {
				return err
			}
			if o.output == "json" {
				return o.jsonOut(os.Stdout, analysis.ProfileDiff(pa, pb))
			}
			render.ProfileDiff(os.Stdout, o.style(), pa, pb, a.name, b.name, n)
			return nil
		},
	}
	c.Flags().DurationVarP(&dur, "duration", "d", 15*time.Second, "duration of each profile")
	c.Flags().IntVar(&hz, "hz", 99, "sampling frequency")
	c.Flags().StringSliceVar(&pods, "pods", nil, "compare two pods: --pods old-pod,new-pod")
	c.Flags().IntVar(&n, "top", 25, "number of functions to show")
	return c
}

func (o *options) cmdControlPlane() *cobra.Command {
	return &cobra.Command{
		Use:     "controlplane",
		Aliases: []string{"cp", "etcd"},
		Short:   "Health of etcd, API server, scheduler, controller manager and cluster DNS pods",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.simple(cmd.Context(), false, func(r *tui.Result) any { return analysis.ControlPlane(r.View) }, func(st render.Style, r *tui.Result) error {
				render.Header(os.Stdout, st, r.View, o.src.Describe())
				render.ControlPlane(os.Stdout, st, r.View, o.filt())
				return nil
			})
		},
	}
}

func (o *options) cmdCounters() *cobra.Command {
	var dur time.Duration
	c := &cobra.Command{
		Use:     "counters <pod>",
		Aliases: []string{"ipc"},
		Short:   "Hardware counters of a pod vs its node: instructions per cycle, cache misses (noisy neighbours on shared caches)",
		Args:    cobra.ExactArgs(1),
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
			}
			c, err := o.src.Counters(cmd.Context(), node, id, int(dur.Seconds()))
			if err != nil {
				return err
			}
			if o.output == "json" {
				return o.jsonOut(os.Stdout, c)
			}
			render.Counters(os.Stdout, o.style(), c)
			return nil
		},
	}
	c.Flags().DurationVarP(&dur, "duration", "d", 5*time.Second, "measurement duration (max 60s)")
	return c
}
