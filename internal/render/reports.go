package render

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/model"
)

// Filter restricts reports to matching rows (substring, case-insensitive)
// and to a namespace.
type Filter struct {
	Text      string
	Namespace string
	entity    string
}

func (f Filter) match(parts ...string) bool {
	if f.Text == "" {
		return true
	}
	t := strings.ToLower(f.Text)
	for _, p := range parts {
		if strings.Contains(strings.ToLower(p), t) {
			return true
		}
	}
	return false
}

func (f Filter) ns(e analysis.Endpoint) bool {
	if f.entity != "" {
		return e.ID == f.entity
	}
	return f.Namespace == "" || e.Namespace == f.Namespace
}

// only restricts a filter to one entity.
func (f Filter) only(id string) Filter {
	f.entity = id
	return f
}

func sev(st Style, s analysis.Severity) string {
	switch s {
	case analysis.SevCrit:
		return st.Crit("CRIT")
	case analysis.SevWarn:
		return st.Warn("WARN")
	}
	return st.Info("INFO")
}

// Header prints the window and source summary.
func Header(w io.Writer, st Style, v *analysis.View, source string) {
	nodes := len(v.Nodes)
	pods := 0
	for _, e := range v.Entities {
		if e.Endpoint.Kind == analysis.KindPod {
			pods++
		}
	}
	fmt.Fprintf(w, "%s  %s → %s (%s)  %d node(s), %d active pod(s), %d flows  %s\n",
		st.Title("kubecapybara"), v.From.Format("15:04:05"), v.To.Format("15:04:05"),
		v.To.Sub(v.From).Round(time.Second), nodes, pods, len(v.Edges), st.Dim(source))
}

// Doctor prints findings.
func Doctor(w io.Writer, st Style, findings []analysis.Finding, f Filter) {
	if len(findings) == 0 {
		fmt.Fprintln(w, st.OK("✔ no problems detected in this window"))
		return
	}
	counts := map[analysis.Severity]int{}
	for _, fd := range findings {
		counts[fd.Severity]++
	}
	fmt.Fprintf(w, "%d finding(s): %s %d  %s %d  %s %d\n\n", len(findings),
		st.Crit("crit"), counts[analysis.SevCrit], st.Warn("warn"), counts[analysis.SevWarn], st.Info("info"), counts[analysis.SevInfo])
	for _, fd := range findings {
		if !f.match(append([]string{fd.Title, fd.Category}, fd.Detail...)...) {
			continue
		}
		fmt.Fprintf(w, "%s %s %s\n", sev(st, fd.Severity), st.Dim("["+fd.Category+"]"), fd.Title)
		for _, d := range fd.Detail {
			fmt.Fprintf(w, "       • %s\n", d)
		}
		if fd.Hint != "" {
			fmt.Fprintf(w, "       %s %s\n", st.Accent("→"), fd.Hint)
		}
		fmt.Fprintln(w)
	}
}

// Edges prints the pod-to-pod network table.
func Edges(w io.Writer, st Style, v *analysis.View, f Filter, sortBy string, limit int) {
	edges := FilterEdges(v, f)
	SortEdges(edges, sortBy)
	t := &Table{
		Headers: []string{"CLIENT", "SERVER", "PORT", "RTT p50", "RTT p99", "CONN p99", "CONN/s", "TX/s", "RX/s", "RETR/s", "REFUSED", "TIMEOUT", "SEEN"},
		Right:   map[int]bool{2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 10: true, 11: true},
		MaxCol:  48,
	}
	for i, e := range edges {
		if limit > 0 && i >= limit {
			break
		}
		s := e.Stats
		refused := fmt.Sprint(s.Refused)
		if s.Refused > 0 {
			refused = st.Warn(refused)
		}
		timeouts := fmt.Sprint(s.Timeouts)
		if s.Timeouts > 0 {
			timeouts = st.Warn(timeouts)
		}
		retr := analysis.Rate(v.PerSec(s.Retrans))
		if s.Retrans > 10 {
			retr = st.Warn(retr)
		}
		server := e.Server.Display()
		if e.CrossZone {
			server += st.Dim(" ⇄" + e.Server.Zone)
		}
		t.AddRow(e.Client.Display(), server, fmt.Sprint(e.Port),
			analysis.Dur(s.RTT.P50()), analysis.Dur(s.RTT.P99()), analysis.Dur(s.Connect.P99()),
			analysis.Rate(v.PerSec(s.Connects)), analysis.Bytes(v.PerSec(s.BytesTx)), analysis.Bytes(v.PerSec(s.BytesRx)),
			retr, refused, timeouts, st.Dim(e.Side))
	}
	t.Render(w, st)
	if limit > 0 && len(edges) > limit {
		fmt.Fprintf(w, "%s\n", st.Dim(fmt.Sprintf("… %d more (use --limit 0 or a filter)", len(edges)-limit)))
	}
}

// FilterEdges returns the edges matching a filter.
func FilterEdges(v *analysis.View, f Filter) []*analysis.Edge {
	edges := make([]*analysis.Edge, 0, len(v.Edges))
	for _, e := range v.Edges {
		if !(f.ns(e.Client) || f.ns(e.Server)) {
			continue
		}
		if !f.match(e.Client.Display(), e.Server.Display(), fmt.Sprint(e.Port), e.Client.Workload, e.Server.Workload) {
			continue
		}
		edges = append(edges, e)
	}
	return edges
}

// SortEdges sorts edges by traffic, rtt, connect, errors, retrans, bytes or conns.
func SortEdges(edges []*analysis.Edge, by string) {
	key := func(e *analysis.Edge) float64 {
		s := e.Stats
		switch by {
		case "rtt":
			return s.RTT.P99()
		case "connect":
			return s.Connect.P99()
		case "bytes":
			return float64(s.BytesTx + s.BytesRx)
		case "retrans":
			return float64(s.Retrans)
		case "errors":
			return float64(s.Refused + s.Timeouts + s.RstRcvd)
		case "conns":
			return float64(s.Connects)
		}
		return float64(s.Connects + s.RTT.Count)
	}
	sort.SliceStable(edges, func(i, j int) bool { return key(edges[i]) > key(edges[j]) })
}

// Pods prints the per-pod resource / time breakdown table.
func Pods(w io.Writer, st Style, v *analysis.View, f Filter) {
	t := &Table{
		Headers: []string{"POD", "NODE", "CPU", "RUNQ p99", "WAIT CPU", "DISK", "NET/RPC", "LOCK", "MEM", "THROTTLED", "DNS q/s", "DNS err", "HTTP rps", "5xx"},
		Right:   map[int]bool{2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 10: true, 11: true, 12: true, 13: true},
		MaxCol:  50,
	}
	for _, e := range PodRows(v, f) {
		s := e.Stats
		cpu, runq, waitCPU, disk, netw, lock := "-", "-", "-", "-", "-", "-"
		if sc := s.Sched; sc != nil {
			cpu = fmt.Sprintf("%.3f", v.CoresUsed(sc))
			runq = analysis.Dur(sc.RunQ.P99())
			total := float64(sc.TotalNs())
			share := func(k string) string { return analysis.Pct(float64(sc.OffNs[k]) / total) }
			waitCPU, disk, netw, lock = share(model.StateRunQ), share(model.StateDisk), share(model.StateNet), share(model.StateLock)
			if sc.RunQ.P99() > 20e3 {
				runq = st.Warn(runq)
			}
		}
		mem, thr := "-", "-"
		if r := s.Res; r != nil && (r.MemCurrent > 0 || r.MemMax > 0) {
			mem = analysis.Bytes(float64(r.MemCurrent))
			if r.MemMax > 0 {
				pct := float64(r.MemCurrent) / float64(r.MemMax)
				mem += " " + analysis.Pct(pct)
				if pct > 0.9 {
					mem = st.Warn(mem)
				}
			}
		}
		if r := s.Res; r != nil {
			if r.Periods > 0 {
				thr = analysis.Pct(float64(r.Throttled) / float64(r.Periods))
				if float64(r.Throttled)/float64(r.Periods) > 0.25 {
					thr = st.Warn(thr)
				}
			}
		}
		dnsq, dnserr := "-", "-"
		if d := s.DNS; d != nil {
			dnsq = analysis.Rate(v.PerSec(d.Queries))
			bad := d.RCodes["SERVFAIL"] + d.RCodes["REFUSED"] + d.Timeouts
			dnserr = fmt.Sprint(bad)
			if bad > 0 {
				dnserr = st.Warn(dnserr)
			}
		}
		rps, errs := "-", "-"
		var req, e5 uint64
		for _, ep := range s.HTTP {
			if ep.Role == "server" {
				req += ep.Count
				e5 += ep.Errors()
			}
		}
		if req > 0 {
			rps = analysis.Rate(v.PerSec(req))
			errs = analysis.Pct(float64(e5) / float64(req))
			if e5 > 0 {
				errs = st.Warn(errs)
			}
		}
		t.AddRow(e.Endpoint.Display(), e.Endpoint.Node, cpu, runq, waitCPU, disk, netw, lock, mem, thr, dnsq, dnserr, rps, errs)
	}
	t.Render(w, st)
}

// PodRows returns pod entities matching a filter, busiest first.
func PodRows(v *analysis.View, f Filter) []*analysis.EntityView {
	var out []*analysis.EntityView
	for _, e := range v.PodEntities() {
		if !f.ns(e.Endpoint) || !f.match(e.Endpoint.Display(), e.Endpoint.Workload, e.Endpoint.Node) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		var a, b uint64
		if out[i].Stats.Sched != nil {
			a = out[i].Stats.Sched.OnCPUNs
		}
		if out[j].Stats.Sched != nil {
			b = out[j].Stats.Sched.OnCPUNs
		}
		return a > b
	})
	return out
}

// Pod prints a detailed report for one pod.
func Pod(w io.Writer, st Style, v *analysis.View, id string) {
	e := v.Entity(id)
	if e == nil {
		fmt.Fprintf(w, "no data for %s in this window (is the pod idle or on a node without an agent?)\n", id)
		return
	}
	ep := e.Endpoint
	fmt.Fprintf(w, "%s  %s\n", st.Title(ep.Display()), st.Dim(fmt.Sprintf("%s  node %s  zone %s  ip %s", ep.Workload, ep.Node, orDash(ep.Zone), orDash(ep.IP))))
	if p := e.Pod; p != nil {
		for _, c := range p.Containers {
			state := c.State
			if c.StateReason != "" {
				state += " (" + c.StateReason + ")"
			}
			line := fmt.Sprintf("  container %-20s %-24s restarts %d", c.Name, state, c.Restarts)
			if c.LastReason != "" {
				line += fmt.Sprintf("  last exit: %s, %s", analysis.ExplainExit(c.LastExitCode, c.LastReason), analysis.Ago(c.LastFinished))
			}
			fmt.Fprintln(w, line)
		}
	}
	s := e.Stats
	if sc := s.Sched; sc != nil {
		Section(w, st, fmt.Sprintf("Where the time goes (thread time, %.3f cores on CPU)", v.CoresUsed(sc)))
		for _, b := range analysis.TimeBreakdown(sc) {
			fmt.Fprintf(w, "  %-24s %s %6s  %s\n", b.State, Bar(b.Share, 24), analysis.Pct(b.Share), st.Dim(analysis.Dur(float64(b.Ns)/1e3)))
		}
		fmt.Fprintf(w, "  run queue latency p50 %s  p99 %s  (%d wakeups)\n", analysis.Dur(sc.RunQ.P50()), analysis.Dur(sc.RunQ.P99()), sc.RunQ.Count)
		if len(sc.Culprits) > 0 {
			var parts []string
			for _, k := range model.SortedKeys(sc.Culprits)[:min(3, len(sc.Culprits))] {
				parts = append(parts, fmt.Sprintf("%s %s", v.EntityEndpoint(k, ep.Node).Display(), analysis.Dur(float64(sc.Culprits[k])/1e3)))
			}
			fmt.Fprintf(w, "  CPU taken by: %s\n", strings.Join(parts, ", "))
		}
		if sc.ReclaimNs > 0 {
			fmt.Fprintf(w, "  direct reclaim stalls: %s (%d)\n", analysis.Dur(float64(sc.ReclaimNs)/1e3), sc.ReclaimCount)
		}
		fmt.Fprintln(w, st.Dim("  note: 'event loop idle' and 'locks' include idle worker threads; compare against a baseline"))
	}
	if r := s.Res; r != nil {
		Section(w, st, "Resources")
		mem := analysis.Bytes(float64(r.MemCurrent))
		if r.MemMax > 0 {
			mem += " / " + analysis.Bytes(float64(r.MemMax)) + " (" + analysis.Pct(float64(r.MemCurrent)/float64(r.MemMax)) + ")"
		}
		if r.MemCurrent > 0 || r.MemMax > 0 {
			fmt.Fprintf(w, "  memory %s  peak %s  OOM kills %d\n", mem, analysis.Bytes(float64(r.MemPeak)), r.OOMKills)
		} else {
			fmt.Fprintln(w, st.Dim("  memory: not available (no cgroup v2 memory controller)"))
		}
		if r.Periods > 0 {
			fmt.Fprintf(w, "  CPU limit %dm  throttled %s of periods (%s)\n", r.CPUQuotaMilli, analysis.Pct(float64(r.Throttled)/float64(r.Periods)), analysis.Dur(float64(r.ThrottledUs)))
		}
		fmt.Fprintf(w, "  pressure (avg10): cpu %.1f%%  memory %.1f%%  io %.1f%%\n", r.PSICPU, r.PSIMem, r.PSIIO)
	}
	if cpu, mem := SeriesSparks(v, id, 40); cpu != "" {
		fmt.Fprintf(w, "  cpu    %s\n", st.Accent(cpu))
		if strings.Trim(mem, "▁") != "" || len(v.Series[id]) > 0 && v.Series[id][0].MemCurrent > 0 {
			fmt.Fprintf(w, "  memory %s\n", st.Accent(mem))
		}
	}
	for _, r := range analysis.OOMRisks(v) {
		if r.Endpoint.ID == id {
			fmt.Fprintf(w, "  %s\n", st.Crit(fmt.Sprintf("memory grows %s/min: limit reached in ~%s", analysis.Bytes(r.BytesPerSec*60), r.ETA.Round(time.Minute))))
		}
	}
	if p := e.Pod; p != nil {
		cpuReq, cpuLim, memReq, memLim := p.Requests()
		fmt.Fprintf(w, "  requests cpu %s mem %s  limits cpu %s mem %s\n", milli(cpuReq), mibOrDash(memReq), milli(cpuLim), mibOrDash(memLim))
	}
	if n := s.Net; n != nil {
		Section(w, st, "TCP (pod network namespace)")
		fmt.Fprintf(w, "  accept queue overflows %d  SYNs dropped %d  RTO timeouts %d\n", n.ListenOverflows, n.ListenDrops, n.Timeouts)
		fmt.Fprintf(w, "  zero window advertised %d  zero-window drops %d  receive queue drops %d  backlog drops %d\n",
			n.ToZeroWindowAdv, n.ZeroWindowDrops, n.RcvQueueDrops, n.BacklogDrops)
	}
	if io := s.IO; io != nil && io.Lat.Count > 0 {
		Section(w, st, "Disk")
		fmt.Fprintf(w, "  read %s/s  write %s/s  ops %s/s  latency p50 %s p99 %s\n",
			analysis.Bytes(v.PerSec(io.ReadBytes)), analysis.Bytes(v.PerSec(io.WriteBytes)), analysis.Rate(v.PerSec(io.ReadOps+io.WriteOps)),
			analysis.Dur(io.Lat.P50()), analysis.Dur(io.Lat.P99()))
	}
	out, in := v.EdgesOf(id)
	if len(out) > 0 {
		Section(w, st, "Dependencies (outgoing)")
		edgeMini(w, st, v, out, true)
	}
	if len(in) > 0 {
		Section(w, st, "Clients (incoming)")
		edgeMini(w, st, v, in, false)
	}
	if d := s.DNS; d != nil && d.Queries > 0 {
		Section(w, st, "DNS")
		dnsSummary(w, st, v, d)
	}
	if len(s.HTTP) > 0 {
		Section(w, st, "HTTP")
		httpTable(w, st, v, s.HTTP)
	}
	if len(s.DB) > 0 {
		Section(w, st, "Database calls")
		DB(w, st, v, Filter{Text: ""}.only(id))
	}
	if len(s.Files) > 0 {
		Section(w, st, "Slow file operations")
		Files(w, st, v, Filter{}.only(id))
	}
	if len(s.ConnErrors) > 0 {
		Section(w, st, "connect() errors")
		for _, k := range model.SortedKeys(s.ConnErrors) {
			fmt.Fprintf(w, "  %s: %d\n", k, s.ConnErrors[k])
		}
	}
	evs := v.EventsOf(id)
	if len(evs) > 0 {
		Section(w, st, "Recent events")
		for _, ev := range lastEvents(evs, 15) {
			fmt.Fprintf(w, "  %s %s %s\n", ev.Time.Format("15:04:05"), evSev(st, ev.Severity), ev.Message)
		}
	}
}

func lastEvents(evs []analysis.EventView, n int) []analysis.EventView {
	if len(evs) > n {
		return evs[len(evs)-n:]
	}
	return evs
}

func evSev(st Style, s string) string {
	switch s {
	case model.SevCrit:
		return st.Crit("!")
	case model.SevWarn:
		return st.Warn("!")
	}
	return st.Dim("·")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func edgeMini(w io.Writer, st Style, v *analysis.View, edges []*analysis.Edge, outgoing bool) {
	t := &Table{Headers: []string{"PEER", "PORT", "RTT p50", "RTT p99", "CONN p99", "CONN/s", "BYTES/s", "RETR", "REFUSED", "TIMEOUT"},
		Right: map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true}, MaxCol: 50}
	for _, e := range edges {
		peer := e.Server
		if !outgoing {
			peer = e.Client
		}
		s := e.Stats
		t.AddRow("  "+peer.Display(), fmt.Sprint(e.Port), analysis.Dur(s.RTT.P50()), analysis.Dur(s.RTT.P99()), analysis.Dur(s.Connect.P99()),
			analysis.Rate(v.PerSec(s.Connects)), analysis.Bytes(v.PerSec(s.BytesTx+s.BytesRx)), fmt.Sprint(s.Retrans), fmt.Sprint(s.Refused), fmt.Sprint(s.Timeouts))
	}
	t.Render(w, st)
}

func dnsSummary(w io.Writer, st Style, v *analysis.View, d *model.DNSStats) {
	var rc []string
	for _, k := range model.SortedKeys(d.RCodes) {
		rc = append(rc, fmt.Sprintf("%s %d", k, d.RCodes[k]))
	}
	fmt.Fprintf(w, "  %s queries/s  p50 %s  p99 %s  timeouts %d  ndots waste %d  [%s]\n",
		analysis.Rate(v.PerSec(d.Queries)), analysis.Dur(d.Lat.P50()), analysis.Dur(d.Lat.P99()), d.Timeouts, d.NdotsWaste, strings.Join(rc, ", "))
	type kv struct {
		name string
		s    *model.DNSName
	}
	var names []kv
	for n, s := range d.Names {
		names = append(names, kv{n, s})
	}
	sort.Slice(names, func(i, j int) bool { return names[i].s.Count > names[j].s.Count })
	t := &Table{Headers: []string{"  NAME", "QUERIES", "NXDOMAIN", "ERRORS", "TIMEOUTS", "AVG"}, Right: map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true}, MaxCol: 64}
	for i, n := range names {
		if i >= 10 {
			break
		}
		avg := 0.0
		if n.s.Answered > 0 {
			avg = float64(n.s.LatSumUs) / float64(n.s.Answered)
		}
		t.AddRow("  "+n.name, fmt.Sprint(n.s.Count), fmt.Sprint(n.s.NXDomain), fmt.Sprint(n.s.Errors), fmt.Sprint(n.s.Timeouts), analysis.Dur(avg))
	}
	t.Render(w, st)
}

func httpTable(w io.Writer, st Style, v *analysis.View, eps map[string]*model.HTTPEndpoint) {
	var list []*model.HTTPEndpoint
	for _, ep := range eps {
		list = append(list, ep)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })
	t := &Table{Headers: []string{"  ROLE", "METHOD", "PATH", "RPS", "5xx", "4xx", "p50", "p99"}, Right: map[int]bool{3: true, 4: true, 5: true, 6: true, 7: true}, MaxCol: 60}
	for _, ep := range list {
		e5 := analysis.Pct(float64(ep.Status["5xx"]) / float64(ep.Count))
		if ep.Status["5xx"] > 0 {
			e5 = st.Warn(e5)
		}
		t.AddRow("  "+ep.Role, ep.Method, ep.Path, analysis.Rate(v.PerSec(ep.Count)), e5, analysis.Pct(float64(ep.Status["4xx"])/float64(ep.Count)),
			analysis.Dur(ep.Lat.P50()), analysis.Dur(ep.Lat.P99()))
	}
	t.Render(w, st)
}

// DNS prints the cluster DNS report.
func DNS(w io.Writer, st Style, v *analysis.View, f Filter) {
	t := &Table{Headers: []string{"CLIENT", "QUERIES/s", "p50", "p99", "NXDOMAIN", "SERVFAIL", "TIMEOUT", "NDOTS WASTE"},
		Right: map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true}, MaxCol: 50}
	var ents []*analysis.EntityView
	for _, e := range v.Entities {
		if e.Stats.DNS != nil && e.Stats.DNS.Queries > 0 && f.ns(e.Endpoint) && f.match(e.Endpoint.Display()) {
			ents = append(ents, e)
		}
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Stats.DNS.Queries > ents[j].Stats.DNS.Queries })
	for _, e := range ents {
		d := e.Stats.DNS
		waste := fmt.Sprint(d.NdotsWaste)
		if d.NdotsWaste > 0 {
			waste = st.Warn(fmt.Sprintf("%d (%s)", d.NdotsWaste, analysis.Pct(float64(d.NdotsWaste)/float64(d.Queries))))
		}
		t.AddRow(e.Endpoint.Display(), analysis.Rate(v.PerSec(d.Queries)), analysis.Dur(d.Lat.P50()), analysis.Dur(d.Lat.P99()),
			fmt.Sprint(d.RCodes["NXDOMAIN"]), fmt.Sprint(d.RCodes["SERVFAIL"]), fmt.Sprint(d.Timeouts), waste)
	}
	Section(w, st, "DNS clients")
	t.Render(w, st)

	var servers []*analysis.EntityView
	for _, e := range v.Entities {
		if e.Stats.DNSServer != nil && e.Stats.DNSServer.Queries > 0 {
			servers = append(servers, e)
		}
	}
	if len(servers) > 0 {
		sort.Slice(servers, func(i, j int) bool { return servers[i].Endpoint.Display() < servers[j].Endpoint.Display() })
		Section(w, st, "DNS servers (per replica processing latency)")
		ts := &Table{Headers: []string{"SERVER", "NODE", "QUERIES/s", "p50", "p99", "SERVFAIL", "NXDOMAIN"}, Right: map[int]bool{2: true, 3: true, 4: true, 5: true, 6: true}}
		for _, e := range servers {
			d := e.Stats.DNSServer
			ts.AddRow(e.Endpoint.Display(), e.Endpoint.Node, analysis.Rate(v.PerSec(d.Queries)), analysis.Dur(d.Lat.P50()), analysis.Dur(d.Lat.P99()),
				fmt.Sprint(d.RCodes["SERVFAIL"]), fmt.Sprint(d.RCodes["NXDOMAIN"]))
		}
		ts.Render(w, st)
	}

	Section(w, st, "Top names")
	tn := &Table{Headers: []string{"NAME", "QUERIES", "NXDOMAIN", "ERRORS", "TIMEOUTS", "AVG", "FROM"}, Right: map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true}, MaxCol: 64}
	for _, n := range analysis.TopDNSNames(v, 25) {
		if !f.match(n.Name, n.Entity) {
			continue
		}
		avg := 0.0
		if n.Answered > 0 {
			avg = float64(n.LatSumUs) / float64(n.Answered)
		}
		nx := fmt.Sprint(n.NXDomain)
		if n.NXDomain > 0 {
			nx = st.Warn(nx)
		}
		tn.AddRow(n.Name, fmt.Sprint(n.Count), nx, fmt.Sprint(n.Errors), fmt.Sprint(n.Timeouts), analysis.Dur(avg), n.Entity)
	}
	tn.Render(w, st)
}

// Nodes prints the noisy-neighbour view.
func Nodes(w io.Writer, st Style, v *analysis.View, f Filter) {
	if m := analysis.BuildNodeMatrix(v); len(m.Nodes) > 1 {
		Section(w, st, "Node-to-node latency")
		NodeHeatmap(w, st, v)
		fmt.Fprintln(w)
	}
	for _, r := range analysis.NodeReports(v) {
		n := r.Node
		ct := "-"
		if n.Stats.ConntrackMax > 0 {
			ct = fmt.Sprintf("%d/%d (%s)", n.Stats.ConntrackCount, n.Stats.ConntrackMax, analysis.Pct(float64(n.Stats.ConntrackCount)/float64(n.Stats.ConntrackMax)))
		}
		fmt.Fprintf(w, "%s  zone %s  load %.2f/%d cpus  pods+host using %.2f cores  psi cpu %.1f%% mem %.1f%% io %.1f%%\n",
			st.Title("node/"+n.Name), orDash(n.Zone), n.Stats.Load1, n.Stats.CPUs, r.CPUCores, n.Stats.PSICPU, n.Stats.PSIMem, n.Stats.PSIIO)
		fmt.Fprintf(w, "  conntrack %s  insert_failed %d  drops %d  retransmits %s/s  disk %s/s\n",
			ct, n.Stats.ConntrackInsertFailed, r.Drops, analysis.Rate(v.PerSec(r.Retrans)), analysis.Bytes(v.PerSec(r.DiskBytes)))
		for name, nic := range n.Stats.NICs {
			fmt.Fprintf(w, "  nic %s rx %s/s tx %s/s  errors %d/%d  dropped %d/%d  missed %d\n", name,
				analysis.Bytes(v.PerSec(nic.RxBytes)), analysis.Bytes(v.PerSec(nic.TxBytes)), nic.RxErrors, nic.TxErrors, nic.RxDropped, nic.TxDropped, nic.RxMissed)
		}
		if n.Stats.SoftnetDropped+n.Stats.SoftnetSqueezed > 0 || n.Stats.NetRxTopShare > 0 {
			fmt.Fprintf(w, "  softnet dropped %d  squeezed %d  NET_RX on busiest CPU %s (cpu %d)\n",
				n.Stats.SoftnetDropped, n.Stats.SoftnetSqueezed, analysis.Pct(n.Stats.NetRxTopShare), n.Stats.NetRxCPU)
		}
		t := &Table{Headers: []string{"  WORKLOAD", "CPU", "RUNQ p99", "WAITING FOR CPU", "DELAY CAUSED TO OTHERS", "DISK/s", "DISK p99", "NET/s"},
			Right: map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true}, MaxCol: 50}
		shown := 0
		for _, e := range r.Entities {
			if !f.match(e.Endpoint.Display()) {
				continue
			}
			if shown >= 12 {
				break
			}
			shown++
			wait := analysis.Pct(e.RunQShare)
			if e.RunQShare > 0.2 {
				wait = st.Warn(wait)
			}
			t.AddRow("  "+e.Endpoint.Display(), fmt.Sprintf("%.3f", e.Cores), analysis.Dur(e.RunQP99), wait,
				analysis.Dur(float64(e.Stolen)/1e3), analysis.Bytes(v.PerSec(e.DiskBytes)), analysis.Dur(e.DiskP99), analysis.Bytes(v.PerSec(e.NetBytes)))
		}
		t.Render(w, st)
		var bad []string
		for c, s := range n.Collectors {
			if s != "ok" {
				bad = append(bad, c)
			}
		}
		sort.Strings(bad)
		if len(bad) > 0 {
			fmt.Fprintf(w, "  %s\n", st.Dim("collectors not running: "+strings.Join(bad, ", ")))
		}
		fmt.Fprintln(w)
	}
	if len(v.Drops) > 0 {
		Section(w, st, "Packet drops by reason")
		type agg struct {
			count, flows uint64
			ex           *model.Drop
		}
		by := map[string]*agg{}
		for _, d := range v.Drops {
			a, ok := by[d.Reason]
			if !ok {
				a = &agg{ex: d}
				by[d.Reason] = a
			}
			a.count += d.Count
			a.flows++
			if d.Count > a.ex.Count {
				a.ex = d
			}
		}
		reasons := make([]string, 0, len(by))
		for r := range by {
			reasons = append(reasons, r)
		}
		sort.Slice(reasons, func(i, j int) bool { return by[reasons[i]].count > by[reasons[j]].count })
		t := &Table{Headers: []string{"REASON", "PACKETS", "FLOWS", "EXAMPLE", ""}, Right: map[int]bool{1: true, 2: true}, MaxCol: 70}
		for _, r := range reasons {
			a := by[r]
			note := ""
			if analysis.BenignDrop(r) {
				note = st.Dim("usually benign")
			}
			ex := fmt.Sprintf("%s → %s:%d/%s", v.IPEndpoint(a.ex.Src, "").Display(), v.IPEndpoint(a.ex.Dst, "").Display(), a.ex.Port, a.ex.Proto)
			t.AddRow(r, fmt.Sprint(a.count), fmt.Sprint(a.flows), ex, note)
		}
		t.Render(w, st)
	}
}

// HTTP prints all HTTP endpoints.
func HTTP(w io.Writer, st Style, v *analysis.View, f Filter) {
	t := &Table{Headers: []string{"POD", "ROLE", "METHOD", "PATH", "RPS", "5xx", "4xx", "p50", "p99"},
		Right: map[int]bool{4: true, 5: true, 6: true, 7: true, 8: true}, MaxCol: 50}
	type row struct {
		e  *analysis.EntityView
		ep *model.HTTPEndpoint
	}
	var rows []row
	for _, e := range v.Entities {
		if !f.ns(e.Endpoint) {
			continue
		}
		for _, ep := range e.Stats.HTTP {
			if f.match(e.Endpoint.Display(), ep.Path, ep.Method) {
				rows = append(rows, row{e, ep})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ep.Count > rows[j].ep.Count })
	for _, r := range rows {
		ep := r.ep
		e5 := analysis.Pct(float64(ep.Status["5xx"]) / float64(ep.Count))
		if ep.Status["5xx"] > 0 {
			e5 = st.Warn(e5)
		}
		t.AddRow(r.e.Endpoint.Display(), ep.Role, ep.Method, ep.Path, analysis.Rate(v.PerSec(ep.Count)), e5,
			analysis.Pct(float64(ep.Status["4xx"])/float64(ep.Count)), analysis.Dur(ep.Lat.P50()), analysis.Dur(ep.Lat.P99()))
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, st.Dim("no HTTP/1.x traffic observed (the http collector is opt-in: run the agent with --l7; TLS traffic is not visible)"))
		return
	}
	t.Render(w, st)
}

// Events prints the event log.
func Events(w io.Writer, st Style, v *analysis.View, f Filter, types map[string]bool, limit int) {
	var evs []analysis.EventView
	for _, e := range v.Events {
		if len(types) > 0 && !types[e.Type] {
			continue
		}
		if !f.ns(e.Endpoint) || !f.match(e.Endpoint.Display(), e.Message, e.Type) {
			continue
		}
		evs = append(evs, e)
	}
	if limit > 0 && len(evs) > limit {
		evs = evs[len(evs)-limit:]
	}
	for _, e := range evs {
		fmt.Fprintf(w, "%s %s %-16s %-40s %s\n", e.Time.Format("15:04:05.000"), evSev(st, e.Severity), e.Type, truncate(e.Endpoint.Display(), 40), e.Message)
	}
	if len(evs) == 0 {
		fmt.Fprintln(w, st.Dim("no events"))
	}
}

// Security prints the security view.
func Security(w io.Writer, st Style, v *analysis.View, f Filter) {
	Section(w, st, "Exec sessions and suspicious shells")
	Events(w, st, v, f, map[string]bool{model.EvExecSession: true, model.EvShell: true}, 50)
	Section(w, st, "Undeclared listening ports")
	und := analysis.UndeclaredPorts(v)
	if len(und) == 0 {
		fmt.Fprintln(w, st.Dim("none"))
	}
	for _, u := range und {
		fmt.Fprintf(w, "  %s listens on %s:%d (%s)\n", u.Endpoint.Display(), u.Addr, u.Port, u.Comm)
	}
	Section(w, st, "Blocked by NetworkPolicies / firewall")
	Denials(w, st, v, f)
	Section(w, st, "Internet egress")
	ext := analysis.ExternalEgress(v)
	if len(ext) == 0 {
		fmt.Fprintln(w, st.Dim("none"))
	}
	for _, x := range ext {
		if !f.match(x.Workload) {
			continue
		}
		fmt.Fprintf(w, "  %s (%s)\n", st.Accent(x.Workload), analysis.Bytes(float64(x.Bytes)))
		for _, d := range x.Destinations {
			fmt.Fprintf(w, "      → %s\n", d)
		}
	}
	Section(w, st, "Recent process executions in pods")
	Events(w, st, v, f, map[string]bool{model.EvExec: true}, 30)
}

// Cost prints the cross-zone cost report.
func Cost(w io.Writer, st Style, v *analysis.View) {
	Section(w, st, "Rightsizing")
	Rightsize(w, st, v, Filter{}, analysis.DefaultPricing)
	Section(w, st, "Cross-zone traffic")
	costs := analysis.CrossZoneCosts(v)
	if len(costs) == 0 {
		fmt.Fprintln(w, st.Dim("no cross-zone traffic observed (nodes need topology.kubernetes.io/zone labels)"))
		return
	}
	var total float64
	t := &Table{Headers: []string{"CLIENT", "SERVER", "ZONES", "BYTES/s", "≈ $/MONTH"}, Right: map[int]bool{3: true, 4: true}}
	for _, c := range costs {
		total += c.MonthlyUSD
		t.AddRow(c.Client, c.Server, c.ClientZone+" → "+c.ServerZone, analysis.Bytes(c.BytesPerSec), analysis.Money(c.MonthlyUSD))
	}
	fmt.Fprintf(w, "Cross-zone transfer at the current rate ≈ %s/month (at $%.3f/GB each direction)\n\n", st.Warn(analysis.Money(total)), v.Opts.CostPerGB)
	t.Render(w, st)
}

// Rollout prints a rollout comparison.
func Rollout(w io.Writer, st Style, rep *analysis.RolloutReport) {
	fmt.Fprintf(w, "%s %s/%s\n", st.Title("rollout"), rep.Namespace, rep.Deployment)
	for _, g := range rep.Groups {
		mark := "  old"
		if g.New {
			mark = st.Accent("  NEW")
		}
		fmt.Fprintf(w, "%s revision %-4s %-40s %d pod(s)\n", mark, orDash(g.Revision), g.Name, len(g.Pods))
	}
	fmt.Fprintln(w)
	t := &Table{Headers: []string{"METRIC", "OLD", "NEW", ""}, Right: map[int]bool{1: true, 2: true}}
	for _, r := range rep.Rows {
		flag := st.OK("ok")
		nw := r.New
		if r.Bad {
			flag = st.Crit("WORSE")
			nw = st.Crit(nw)
		}
		t.AddRow(r.Metric, r.Old, nw, flag+" "+st.Dim(r.Note))
	}
	t.Render(w, st)
	fmt.Fprintln(w)
	if rep.Healthy {
		fmt.Fprintln(w, st.OK("✔ "+rep.Verdict))
	} else {
		fmt.Fprintln(w, st.Crit("✘ "+rep.Verdict))
	}
}

// Startup prints a startup timeline.
func Startup(w io.Writer, st Style, rep *analysis.StartupReport) {
	p := rep.Pod
	fmt.Fprintf(w, "%s %s/%s on %s\n\n", st.Title("startup"), p.Namespace, p.Name, p.Node)
	var t0 time.Time
	if len(rep.Timeline) > 0 {
		t0 = rep.Timeline[0].Time
	}
	for _, e := range rep.Timeline {
		src := st.Dim(fmt.Sprintf("%-4s", e.Source))
		mark := " "
		switch e.Severity {
		case model.SevWarn:
			mark = st.Warn("!")
		case model.SevCrit:
			mark = st.Crit("!")
		}
		fmt.Fprintf(w, "  +%-9s %s %s %s\n", fmtOffset(e.Time.Sub(t0)), src, mark, e.Text)
	}
	if len(rep.Phases) > 0 {
		Section(w, st, "Phases")
		var max time.Duration
		for _, ph := range rep.Phases {
			if ph.Duration > max {
				max = ph.Duration
			}
		}
		for _, ph := range rep.Phases {
			share := 0.0
			if max > 0 {
				share = float64(ph.Duration) / float64(max)
			}
			fmt.Fprintf(w, "  %-30s %s %s\n", ph.Name, Bar(share, 30), ph.Duration.Round(time.Millisecond))
		}
	}
	if len(rep.Advice) > 0 {
		Section(w, st, "Findings")
		for _, a := range rep.Advice {
			fmt.Fprintf(w, "  %s %s\n", st.Accent("→"), a)
		}
	}
}

func fmtOffset(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}

// Crashes prints crash reports for a pod.
func Crashes(w io.Writer, st Style, v *analysis.View, id string) {
	e := v.Entity(id)
	var pod = (*analysis.EntityView)(nil)
	if e != nil {
		pod = e
	}
	crashes := analysis.CrashesOf(v, id)
	if pod != nil && pod.Pod != nil {
		for _, c := range pod.Pod.Containers {
			if c.LastReason != "" || c.Restarts > 0 {
				fmt.Fprintf(w, "container %s: %d restarts; last termination: %s %s\n", c.Name, c.Restarts,
					analysis.ExplainExit(c.LastExitCode, c.LastReason), analysis.Ago(c.LastFinished))
			}
		}
	}
	if len(crashes) == 0 {
		fmt.Fprintln(w, st.Dim("no crash recorded by the flight recorder in this window (try a longer --window)"))
		return
	}
	for i, c := range crashes {
		if i > 0 {
			fmt.Fprintln(w, strings.Repeat("─", 60))
		}
		fmt.Fprintf(w, "%s %s on %s (%s)\n", st.Crit("crash"), c.Time.Format("2006-01-02 15:04:05.000"), c.Node, analysis.Ago(c.Time))
		fmt.Fprintf(w, "reason: %s\n\n", c.Reason)
		if len(c.Series) > 0 {
			fmt.Fprintln(w, st.Title("resources before the crash"))
			for _, s := range c.Series[max(0, len(c.Series)-12):] {
				lim := ""
				if s.MemMax > 0 {
					lim = " / " + analysis.Bytes(float64(s.MemMax)) + " " + Bar(float64(s.MemCurrent)/float64(s.MemMax), 20)
				}
				mem := "-"
				if s.MemCurrent > 0 {
					mem = analysis.Bytes(float64(s.MemCurrent))
				}
				fmt.Fprintf(w, "  %s  mem %s%s  cpu %.0fm  throttled %.0f%%\n", s.Time.Format("15:04:05"), mem, lim, s.CPUMilli, s.ThrottledPct)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, st.Title("last events"))
		evs := c.Events
		if len(evs) > 25 {
			fmt.Fprintf(w, "  %s\n", st.Dim(fmt.Sprintf("… %d earlier events (kubectl capybara events -f <pod>)", len(evs)-25)))
			evs = evs[len(evs)-25:]
		}
		for _, ev := range evs {
			fmt.Fprintf(w, "  %s %s %-16s %s\n", ev.Time.Format("15:04:05.000"), evSev(st, ev.Severity), ev.Type, ev.Message)
		}
	}
}

// Profile prints the top functions of a profile.
func Profile(w io.Writer, st Style, p *model.Profile, n int) {
	fmt.Fprintf(w, "%s %s on %s: %d samples in %s at %dHz\n\n", st.Title("profile"), p.Entity, p.Node, p.Samples, p.Duration, p.Hz)
	if p.Samples == 0 {
		fmt.Fprintln(w, st.Dim("no samples: the pod did not use CPU during the profile"))
		return
	}
	t := &Table{Headers: []string{"SELF", "SELF%", "TOTAL", "TOTAL%", "FUNCTION"}, Right: map[int]bool{0: true, 1: true, 2: true, 3: true}, MaxCol: 100}
	for i, fs := range analysis.TopFunctions(p) {
		if i >= n {
			break
		}
		t.AddRow(fmt.Sprint(fs.Self), analysis.Pct(float64(fs.Self)/float64(p.Samples)), fmt.Sprint(fs.Total), analysis.Pct(float64(fs.Total)/float64(p.Samples)), fs.Name)
	}
	t.Render(w, st)
}
