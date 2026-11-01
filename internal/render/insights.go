package render

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/model"
)

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// Sparkline renders values as a unicode sparkline of at most width runes
// (values are averaged into buckets). Empty input gives "".
func Sparkline(vals []float64, width int) string {
	if len(vals) == 0 || width <= 0 {
		return ""
	}
	if len(vals) > width {
		b := make([]float64, width)
		for i := range b {
			lo, hi := i*len(vals)/width, (i+1)*len(vals)/width
			var s float64
			for _, v := range vals[lo:hi] {
				s += v
			}
			b[i] = s / float64(hi-lo)
		}
		vals = b
	}
	min, max := math.Inf(1), math.Inf(-1)
	for _, v := range vals {
		min, max = math.Min(min, v), math.Max(max, v)
	}
	var sb strings.Builder
	for _, v := range vals {
		i := 0
		if max > min {
			i = int((v - min) / (max - min) * float64(len(sparkRunes)-1))
		}
		sb.WriteRune(sparkRunes[i])
	}
	return sb.String()
}

// SeriesSparks returns CPU and memory sparklines for an entity.
func SeriesSparks(v *analysis.View, id string, width int) (cpu, mem string) {
	ser := v.Series[id]
	if len(ser) < 2 {
		return "", ""
	}
	c := make([]float64, len(ser))
	m := make([]float64, len(ser))
	for i, s := range ser {
		c[i], m[i] = s.CPUMilli, float64(s.MemCurrent)
	}
	return Sparkline(c, width), Sparkline(m, width)
}

// Rightsize prints sizing recommendations.
func Rightsize(w io.Writer, st Style, v *analysis.View, f Filter, price analysis.Pricing) {
	rows := analysis.Rightsize(v, price)
	if len(rows) == 0 {
		fmt.Fprintln(w, st.Dim("no pods with Kubernetes metadata in this window"))
		return
	}
	if v.Seconds() < 3600 {
		fmt.Fprintln(w, st.Warn(fmt.Sprintf("! only %s of data: peaks are probably understated, use -w 1h (or longer) before changing requests",
			time.Duration(v.Seconds()*float64(time.Second)).Round(time.Second))))
	}
	t := &Table{Headers: []string{"WORKLOAD", "PODS", "CPU REQ", "CPU AVG", "CPU PEAK", "→ CPU", "MEM REQ", "MEM LIMIT", "MEM PEAK", "→ MEM", "$/MONTH", "VERDICT"},
		Right: map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 10: true}, MaxCol: 52}
	var total float64
	for _, r := range rows {
		if !f.match(r.Workload) || (f.Namespace != "" && !strings.HasPrefix(r.Workload, f.Namespace+"/")) {
			continue
		}
		peak := fmt.Sprintf("%.0fm", r.CPUPeak)
		if !r.PeakKnown {
			peak += "*"
		}
		verdict := r.Verdict
		switch r.Verdict {
		case "over":
			verdict = st.Warn("over-provisioned")
			total += r.MonthlyUSD
		case "under":
			verdict = st.Crit("under-provisioned")
		case "no-requests":
			verdict = st.Dim("no requests set")
		case "no-data":
			verdict = st.Dim("no CPU/memory data")
		default:
			verdict = st.OK("ok")
		}
		money := "-"
		if r.MonthlyUSD >= 0.01 {
			money = analysis.Money(r.MonthlyUSD)
		} else if r.MonthlyUSD <= -0.01 {
			money = "+" + analysis.Money(-r.MonthlyUSD)
		}
		memRec := "-"
		if r.MemRec > 0 {
			memRec = mib(r.MemRec)
		}
		t.AddRow(r.Workload, fmt.Sprint(r.Pods), milli(r.CPUReq), fmt.Sprintf("%.0fm", r.CPUAvg), peak, fmt.Sprintf("%dm", r.CPURec),
			mibOrDash(r.MemReq), mibOrDash(r.MemLim), mibOrDash(int64(r.MemPeak)), memRec, money, verdict)
	}
	t.Render(w, st)
	fmt.Fprintf(w, "\n%s  (CPU → 1.2× peak, memory → 1.25× peak; $%.3f/vCPU-h, $%.4f/GiB-h; * = window average, no 5s samples)\n",
		st.Title(fmt.Sprintf("potential savings ≈ %s/month", analysis.Money(total))), price.CorePerHour, price.GiBPerHour)
}

func milli(m int64) string {
	if m == 0 {
		return "-"
	}
	return fmt.Sprintf("%dm", m)
}

func mib(b int64) string { return fmt.Sprintf("%dMi", b>>20) }

func mibOrDash(b int64) string {
	if b <= 0 {
		return "-"
	}
	return mib(b)
}

// OOMRisks prints pods projected to reach their memory limit.
func OOMRisks(w io.Writer, st Style, v *analysis.View) {
	risks := analysis.OOMRisks(v)
	if len(risks) == 0 {
		fmt.Fprintln(w, st.Dim("no pod is trending towards its memory limit"))
		return
	}
	t := &Table{Headers: []string{"POD", "MEMORY", "LIMIT", "GROWTH", "LIMIT IN", "FIT"}, Right: map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true}}
	for _, r := range risks {
		eta := r.ETA.Round(time.Minute).String()
		if r.ETA < 15*time.Minute {
			eta = st.Crit(eta)
		} else if r.ETA < time.Hour {
			eta = st.Warn(eta)
		}
		t.AddRow(r.Endpoint.Display(), analysis.Bytes(float64(r.Current)), analysis.Bytes(float64(r.Limit)),
			analysis.Bytes(r.BytesPerSec*60)+"/min", eta, fmt.Sprintf("R²=%.2f", r.R2))
	}
	t.Render(w, st)
}

// Denials prints traffic blocked by packet filtering.
func Denials(w io.Writer, st Style, v *analysis.View, f Filter) {
	ds := analysis.PolicyDenials(v)
	if len(ds) == 0 {
		fmt.Fprintln(w, st.Dim("no packets dropped by NetworkPolicies / firewall rules"))
		return
	}
	t := &Table{Headers: []string{"FROM", "TO", "PORT", "PACKETS", "REASON"}, Right: map[int]bool{2: true, 3: true}, MaxCol: 50}
	for _, d := range ds {
		if !f.match(d.Src.Display(), d.Dst.Display()) {
			continue
		}
		t.AddRow(d.Src.Display(), d.Dst.Display(), fmt.Sprintf("%d/%s", d.Port, d.Proto), fmt.Sprint(d.Count), d.Reason)
	}
	t.Render(w, st)
}

// NodeHeatmap prints the node-to-node RTT matrix with coloured cells.
func NodeHeatmap(w io.Writer, st Style, v *analysis.View) {
	m := analysis.BuildNodeMatrix(v)
	if len(m.Nodes) == 0 {
		return
	}
	slow := m.SlowNodes()
	nameW := 6
	for _, n := range m.Nodes {
		nameW = max(nameW, len(n))
	}
	if nameW > 24 {
		nameW = 24
	}
	cell := 9
	short := func(s string) string {
		if len(s) > nameW {
			return s[:nameW-1] + "…"
		}
		return s
	}
	fmt.Fprintf(w, "%-*s", nameW+2, "RTT p50")
	for i := range m.Nodes {
		fmt.Fprintf(w, "%*s", cell, fmt.Sprintf("[%d]", i+1))
	}
	fmt.Fprintln(w)
	for i, a := range m.Nodes {
		label := fmt.Sprintf("[%d] %s", i+1, short(a))
		if _, ok := slow[a]; ok {
			label = st.Crit(label)
		}
		fmt.Fprintf(w, "%s%s", label, strings.Repeat(" ", max(1, nameW+6-len(fmt.Sprintf("[%d] %s", i+1, short(a))))))
		for _, b := range m.Nodes {
			h := m.Cell(a, b)
			txt := "·"
			if h.Count > 0 {
				txt = analysis.Dur(h.P50())
			}
			pad := strings.Repeat(" ", max(0, cell-len([]rune(txt))))
			switch p := h.P50(); {
			case h.Count == 0:
				txt = st.Dim(txt)
			case p > 5000:
				txt = st.Crit(txt)
			case p > 1000:
				txt = st.Warn(txt)
			default:
				txt = st.OK(txt)
			}
			fmt.Fprint(w, pad+txt)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, st.Dim("rows/columns: client and server node; diagonal = traffic within a node; red row = slow node"))
}

// Services prints how evenly Services spread load over their backends.
func Services(w io.Writer, st Style, v *analysis.View, f Filter) {
	sbs := analysis.ServiceBalances(v)
	if len(sbs) == 0 {
		fmt.Fprintln(w, st.Dim("no Service with two or more active backends in this window"))
		return
	}
	for _, sb := range sbs {
		if !f.match(sb.Service) || (f.Namespace != "" && !strings.HasPrefix(sb.Service, f.Namespace+"/")) {
			continue
		}
		unit := "new connections"
		if sb.ByBytes {
			unit = "bytes (few new connections: long-lived)"
		}
		head := fmt.Sprintf("svc/%s  %d backends  imbalance ×%.1f  by %s", sb.Service, len(sb.Backends), sb.Imbalance, unit)
		if sb.Imbalance >= 2 {
			head = st.Warn(head)
		} else {
			head = st.Title(head)
		}
		fmt.Fprintln(w, head)
		fair := 1 / float64(len(sb.Backends))
		for _, b := range sb.Backends {
			ready := ""
			if !b.Ready {
				ready = st.Dim(" (not ready)")
			}
			fmt.Fprintf(w, "  %-44s %s %6s  %s conns  %s%s\n", truncate(b.Pod.Display(), 44), Bar(b.Share/math.Max(fair*2, b.Share), 24),
				analysis.Pct(b.Share), analysis.Rate(v.PerSec(b.Conns))+"/s", analysis.Bytes(v.PerSec(b.Bytes))+"/s", ready)
		}
		fmt.Fprintln(w)
	}
}

// EdgeDetail prints everything known about one edge, with histograms.
func EdgeDetail(w io.Writer, st Style, v *analysis.View, e *analysis.Edge) {
	s := e.Stats
	fmt.Fprintf(w, "%s → %s:%d   %s\n", st.Title(e.Client.Display()), st.Title(e.Server.Display()), e.Port, st.Dim("observed from: "+e.Side+" side, nodes "+strings.Join(e.Nodes, ",")))
	if e.CrossZone {
		fmt.Fprintf(w, "cross-zone: %s → %s\n", e.Client.Zone, e.Server.Zone)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "connections %s/s (%d)  closes %d  avg lifetime %s\n", analysis.Rate(v.PerSec(s.Connects)), s.Connects, s.Closes, avgLife(s))
	fmt.Fprintf(w, "throughput  tx %s/s  rx %s/s\n", analysis.Bytes(v.PerSec(s.BytesTx)), analysis.Bytes(v.PerSec(s.BytesRx)))
	fmt.Fprintf(w, "errors      refused %d  timeouts %d  SYN retransmits %d  resets sent %d / received %d\n", s.Refused, s.Timeouts, s.SynRetrans, s.RstSent, s.RstRcvd)
	fmt.Fprintf(w, "loss        retransmits %d (%d full-size)  MTU reductions %d  zero-window stalls ≈%s\n", s.Retrans, s.RetransLarge, s.MTUReduced,
		(time.Duration(s.ZeroWindow) * 100 * time.Millisecond).String())
	if s.RTT.Count > 0 {
		Section(w, st, fmt.Sprintf("RTT  p50 %s  p90 %s  p99 %s  (%d samples)", analysis.Dur(s.RTT.P50()), analysis.Dur(s.RTT.P90()), analysis.Dur(s.RTT.P99()), s.RTT.Count))
		HistBars(w, st, s.RTT)
	}
	if s.Connect.Count > 0 {
		Section(w, st, fmt.Sprintf("connect latency  p50 %s  p99 %s  (%d)", analysis.Dur(s.Connect.P50()), analysis.Dur(s.Connect.P99()), s.Connect.Count))
		HistBars(w, st, s.Connect)
	}
}

func avgLife(s *model.Pair) string {
	if s.Closes == 0 {
		return "-"
	}
	return analysis.Dur(float64(s.LifetimeUs) / float64(s.Closes))
}

// HistBars draws a log2 latency histogram as horizontal bars.
func HistBars(w io.Writer, st Style, h model.Hist) {
	var maxV uint64
	first, last := -1, 0
	for i, c := range h.B {
		if c > 0 {
			if first < 0 {
				first = i
			}
			last = i
			if c > maxV {
				maxV = c
			}
		}
	}
	if first < 0 {
		return
	}
	for i := first; i <= last; i++ {
		lo := 0.0
		if i > 0 {
			lo = math.Ldexp(1, i-1)
		}
		hi := math.Ldexp(1, i)
		fmt.Fprintf(w, "  %8s – %-8s %s %d\n", analysis.Dur(math.Max(lo, 1)), analysis.Dur(hi), st.Accent(Bar(float64(h.B[i])/float64(maxV), 30)), h.B[i])
	}
}

// DB prints client-side database statements per pod.
func DB(w io.Writer, st Style, v *analysis.View, f Filter) {
	type row struct {
		e *analysis.EntityView
		q *model.DBQuery
	}
	var rows []row
	for _, e := range v.Entities {
		if !f.ns(e.Endpoint) {
			continue
		}
		for _, q := range e.Stats.DB {
			if f.match(e.Endpoint.Display(), q.Query, q.Proto) {
				rows = append(rows, row{e, q})
			}
		}
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, st.Dim("no plaintext Postgres/MySQL/Redis traffic observed (agent --l7; TLS connections are not visible)"))
		return
	}
	// rank by total time spent waiting for the statement
	sort.Slice(rows, func(i, j int) bool { return rows[i].q.Lat.Sum > rows[j].q.Lat.Sum })
	t := &Table{Headers: []string{"CLIENT", "DB", "STATEMENT", "QPS", "ERRORS", "p50", "p99", "TIME/s"},
		Right: map[int]bool{3: true, 4: true, 5: true, 6: true, 7: true}, MaxCol: 70}
	for _, r := range rows {
		q := r.q
		errs := analysis.Pct(float64(q.Errors) / float64(q.Count))
		if q.Errors > 0 {
			errs = st.Warn(errs)
		}
		p99 := analysis.Dur(q.Lat.P99())
		if q.Lat.P99() > 500e3 {
			p99 = st.Warn(p99)
		}
		t.AddRow(r.e.Endpoint.Display(), q.Proto, q.Query, analysis.Rate(v.PerSec(q.Count)), errs,
			analysis.Dur(q.Lat.P50()), p99, analysis.Dur(float64(q.Lat.Sum)/v.Seconds()))
	}
	t.Render(w, st)
	fmt.Fprintln(w, st.Dim("TIME/s = time spent waiting for this statement per second (where the database time goes)"))
}

// Files prints slow file operations per pod.
func Files(w io.Writer, st Style, v *analysis.View, f Filter) {
	type row struct {
		e  *analysis.EntityView
		fs *model.FileStats
	}
	var rows []row
	for _, e := range v.Entities {
		if !f.ns(e.Endpoint) {
			continue
		}
		for _, x := range e.Stats.Files {
			if f.match(e.Endpoint.Display(), x.Path, x.FSType) {
				rows = append(rows, row{e, x})
			}
		}
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, st.Dim("no slow file operations (agent --files, threshold --file-threshold)"))
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].fs.WaitNs > rows[j].fs.WaitNs })
	t := &Table{Headers: []string{"POD", "FILE", "FS", "SLOW OPS", "READ/WRITE/FSYNC", "WAITED", "MAX"},
		Right: map[int]bool{3: true, 5: true, 6: true}, MaxCol: 64}
	for _, r := range rows {
		x := r.fs
		mx := analysis.Dur(float64(x.MaxNs) / 1e3)
		if x.MaxNs > 500e6 {
			mx = st.Warn(mx)
		}
		t.AddRow(r.e.Endpoint.Display(), x.Path, x.FSType, fmt.Sprint(x.Ops()), fmt.Sprintf("%d/%d/%d", x.Reads, x.Writes, x.Fsyncs),
			analysis.Dur(float64(x.WaitNs)/1e3), mx)
	}
	t.Render(w, st)
}

// Outliers prints replicas much worse than their siblings.
func Outliers(w io.Writer, st Style, v *analysis.View, f Filter) {
	outs := analysis.Outliers(v)
	if len(outs) == 0 {
		fmt.Fprintln(w, st.Dim("no outlier replicas (workloads need 3+ active pods)"))
		return
	}
	t := &Table{Headers: []string{"WORKLOAD", "POD", "NODE", "METRIC", "POD VALUE", "SIBLINGS (MEDIAN)", "×"},
		Right: map[int]bool{4: true, 5: true, 6: true}, MaxCol: 48}
	for _, o := range outs {
		if !f.match(o.Workload, o.Pod.Display(), o.Metric) || !f.ns(o.Pod) {
			continue
		}
		t.AddRow(o.Workload, o.Pod.Display(), o.Pod.Node, o.Metric, st.Warn(o.Format(o.Value)),
			fmt.Sprintf("%s (%d)", o.Format(o.Median), o.Siblings), fmt.Sprintf("%.1f", o.Factor()))
	}
	t.Render(w, st)
	for n, wls := range analysis.OutlierNodes(outs) {
		fmt.Fprintf(w, "%s node %s hosts outliers of %s: suspect the node, not the apps\n", st.Crit("!"), n, strings.Join(wls, ", "))
	}
}

// SLOs prints burn rates of service level objectives.
func SLOs(w io.Writer, st Style, statuses []analysis.SLOStatus) {
	if len(statuses) == 0 {
		fmt.Fprintln(w, st.Dim("no SLOs defined (--slo-file slos.yaml, see `kubectl capybara slo --help`)"))
		return
	}
	t := &Table{Headers: []string{"SLO", "TARGET", "REQUESTS", "AVAILABILITY", "UNDER LATENCY", "BURN NOW", "BURN BASELINE", "BUDGET GONE IN"},
		Right: map[int]bool{2: true, 3: true, 4: true, 5: true, 6: true, 7: true}}
	for _, s := range statuses {
		target := ""
		if s.Availability > 0 {
			target = fmt.Sprintf("%.2f%%", s.Availability)
		}
		if s.Latency > 0 {
			if target != "" {
				target += ", "
			}
			target += fmt.Sprintf("%.1f%% < %s", s.LatencyObjective, s.Latency)
		}
		avail, under, burn, base, gone := "-", "-", "-", "-", "-"
		if s.Requests > 0 {
			avail = fmt.Sprintf("%.3f%%", 100*(1-float64(s.Errors)/float64(s.Requests)))
			if s.Latency > 0 {
				under = fmt.Sprintf("%.2f%%", 100*(1-s.Slow/float64(s.Requests)))
			}
			burn = fmt.Sprintf("%.1fx", s.Burn())
			switch {
			case s.Burn() >= 14.4:
				burn = st.Crit(burn)
			case s.Burn() >= 6:
				burn = st.Warn(burn)
			case s.Burn() <= 1:
				burn = st.OK(burn)
			}
			if s.Burn() > 0 {
				gone = (time.Duration(float64(30*24*time.Hour) / s.Burn())).Round(time.Hour).String()
			}
		}
		if s.HasBase {
			base = fmt.Sprintf("%.1fx", s.BaseBurn())
		}
		t.AddRow(s.Name, target, fmt.Sprint(s.Requests), avail, under, burn, base, gone)
	}
	t.Render(w, st)
	fmt.Fprintln(w, st.Dim("burn 1x = spending the error budget exactly over 30 days; ≥14.4x in both windows pages, ≥6x warns"))
}

// Pools prints connection pools per client workload and dependency.
func Pools(w io.Writer, st Style, v *analysis.View, base *analysis.View, f Filter) {
	pools := analysis.Pools(v, base)
	if len(pools) == 0 {
		fmt.Fprintln(w, st.Dim("no client connections observed"))
		return
	}
	t := &Table{Headers: []string{"CLIENT", "DEPENDENCY", "PORT", "PODS", "OPEN", "IDLE", "PER POD", "NEW CONN/s", "BASELINE/s"},
		Right: map[int]bool{2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true}, MaxCol: 48}
	for _, p := range pools {
		if !f.match(p.Client, p.Server) || (f.Namespace != "" && !strings.HasPrefix(p.Client, f.Namespace+"/")) {
			continue
		}
		idle := fmt.Sprint(p.Idle)
		if p.Idle >= 50*uint64(max(p.Pods, 1)) {
			idle = st.Warn(idle)
		}
		rate := analysis.Rate(p.ConnPerSec)
		if p.BaseRate > 0 && p.ConnPerSec >= 20 && p.ConnPerSec > 5*p.BaseRate {
			rate = st.Crit(rate)
		}
		baseRate := "-"
		if base != nil {
			baseRate = analysis.Rate(p.BaseRate)
		}
		t.AddRow(p.Client, p.Server, fmt.Sprint(p.Port), fmt.Sprint(p.Pods), fmt.Sprint(p.Open), idle,
			fmt.Sprintf("%.0f", float64(p.Open)/float64(max(p.Pods, 1))), rate, baseRate)
	}
	t.Render(w, st)
	fmt.Fprintln(w, st.Dim("idle = no data received for 30s; open/idle are the highest values in the window"))
}

// Incident prints an incident timeline.
func Incident(w io.Writer, st Style, items []analysis.TimelineItem) {
	if len(items) == 0 {
		fmt.Fprintln(w, st.Dim("nothing happened in this range"))
		return
	}
	for _, it := range items {
		kind := st.Dim(fmt.Sprintf("%-6s", it.Kind))
		text := it.Text
		switch it.Severity {
		case model.SevCrit:
			text = st.Crit(text)
		case model.SevWarn:
			text = st.Warn(text)
		}
		fmt.Fprintf(w, "%s %s %-40s %s\n", it.Time.Format("15:04:05"), kind, truncate(it.Subject, 40), text)
		if it.Cause != "" {
			fmt.Fprintf(w, "%s %s %s\n", strings.Repeat(" ", 15), st.Accent("↳ likely cause,"), it.Cause)
		}
	}
}

// ProfileDiff prints the functions whose CPU share changed the most.
func ProfileDiff(w io.Writer, st Style, before, now *model.Profile, beforeName, nowName string, n int) {
	fmt.Fprintf(w, "%s %s (%d samples)  →  %s (%d samples)\n\n", st.Title("profile diff"), beforeName, before.Samples, nowName, now.Samples)
	t := &Table{Headers: []string{"SELF BEFORE", "SELF NOW", "CHANGE", "TOTAL BEFORE", "TOTAL NOW", "FUNCTION"},
		Right: map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true}, MaxCol: 90}
	for i, d := range analysis.ProfileDiff(before, now) {
		if i >= n {
			break
		}
		change := fmt.Sprintf("%+.1f pp", 100*(d.Now-d.Before))
		switch {
		case d.Now-d.Before > 0.02:
			change = st.Crit(change)
		case d.Now-d.Before < -0.02:
			change = st.OK(change)
		}
		t.AddRow(analysis.Pct(d.Before), analysis.Pct(d.Now), change, analysis.Pct(d.TotalBefore), analysis.Pct(d.TotalNow), d.Name)
	}
	t.Render(w, st)
	fmt.Fprintln(w, st.Dim("shares of CPU samples; pp = percentage points. Java/Node frames need a perf map (/tmp/perf-<pid>.map) to show method names"))
}

// ControlPlane prints control plane component health.
func ControlPlane(w io.Writer, st Style, v *analysis.View) {
	cs := analysis.ControlPlane(v)
	if len(cs) == 0 {
		fmt.Fprintln(w, st.Dim("no control plane pods observed (managed control planes run outside the cluster; CoreDNS is shown when present)"))
		return
	}
	t := &Table{Headers: []string{"ROLE", "POD", "NODE", "RESTARTS", "WAIT CPU", "THROTTLED", "MEM", "DISK p99", "SLOW FSYNC", "STATUS"},
		Right: map[int]bool{3: true, 4: true, 5: true, 6: true, 7: true, 8: true}, MaxCol: 60}
	for _, c := range cs {
		status := st.OK("ok")
		if len(c.Problems) > 0 {
			status = st.Warn(strings.Join(c.Problems, "; "))
		}
		fsync := "-"
		if c.FsyncSlow > 0 {
			fsync = fmt.Sprintf("%d (max %s)", c.FsyncSlow, analysis.Dur(c.FsyncP99))
		}
		t.AddRow(c.Role, c.Endpoint.Display(), c.Endpoint.Node, fmt.Sprint(c.Restarts), analysis.Pct(c.CPUWait), analysis.Pct(c.Throttled),
			analysis.Pct(c.MemPct), analysis.Dur(c.DiskP99), fsync, status)
	}
	t.Render(w, st)
	fmt.Fprintln(w, st.Dim("etcd fsync latency needs the agent's --files flag (disk p99 is used otherwise)"))
}

// Counters prints hardware counters of a pod vs its node.
func Counters(w io.Writer, st Style, c *model.Counters) {
	fmt.Fprintf(w, "%s %s on %s over %s\n\n", st.Title("hardware counters"), c.Entity, c.Node, c.Duration)
	t := &Table{Headers: []string{"", "POD", "WHOLE NODE"}, Right: map[int]bool{1: true, 2: true}}
	t.AddRow("instructions per cycle", fmt.Sprintf("%.2f", c.IPC()), fmt.Sprintf("%.2f", c.NodeIPC()))
	t.AddRow("cache miss rate", analysis.Pct(c.MissRate()), analysis.Pct(c.NodeMissRate()))
	t.AddRow("cycles", fmt.Sprint(c.Cycles), fmt.Sprint(c.NodeCycles))
	t.AddRow("instructions", fmt.Sprint(c.Instructions), fmt.Sprint(c.NodeInstructions))
	t.Render(w, st)
	if c.NodeIPC() > 0 && c.IPC() < 0.5*c.NodeIPC() {
		fmt.Fprintln(w, st.Warn("\n! the pod executes far fewer instructions per cycle than the node average: memory stalls or a noisy neighbour on shared caches"))
	}
}
