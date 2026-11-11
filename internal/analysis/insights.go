package analysis

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// ---------------------------------------------------------------- rightsizing

// RightsizeRow is a sizing recommendation for one workload (per pod values).
type RightsizeRow struct {
	Workload   string // ns/Kind/name
	Pods       int
	CPUReq     int64   // millicores per pod (sum of containers)
	CPULim     int64   // millicores per pod
	CPUAvg     float64 // millicores per pod
	CPUPeak    float64 // millicores per pod (highest 5s sample)
	CPURec     int64   // recommended request
	MemReq     int64   // bytes per pod
	MemLim     int64
	MemPeak    float64 // bytes per pod (highest sample / memory.peak)
	MemRec     int64
	MonthlyUSD float64 // savings (positive) or extra cost (negative) for all pods
	Verdict    string  // over, under, ok, no-requests
	PeakKnown  bool    // CPU peak from 5s samples (otherwise window average)
}

// Pricing for rightsizing estimates.
type Pricing struct {
	CorePerHour float64 // USD per vCPU hour
	GiBPerHour  float64 // USD per GiB hour
}

// DefaultPricing approximates on-demand cloud prices.
var DefaultPricing = Pricing{CorePerHour: 0.031, GiBPerHour: 0.0042}

func roundUp(v, step float64) float64 { return math.Ceil(v/step) * step }

// Rightsize compares measured usage with requests and limits per workload.
// CPU recommendation: 1.2x the highest 5s sample (min 10m). Memory: 1.25x
// the peak (min 32Mi). Short windows understate peaks: use -w 1h or more.
func Rightsize(v *View, price Pricing) []RightsizeRow {
	type agg struct {
		row                            RightsizeRow
		cpuSum, cpuPeak, memPeak       float64
		cpuReq, cpuLim, memReq, memLim int64
		peakKnown                      bool
		cpuPods                        int // pods with a CPU measurement
	}
	by := map[string]*agg{}
	for _, e := range v.PodEntities() {
		p := e.Pod
		if p == nil {
			continue
		}
		cpuReq, cpuLim, memReq, memLim := p.Requests()
		key := p.Namespace + "/" + p.Workload
		a, ok := by[key]
		if !ok {
			a = &agg{row: RightsizeRow{Workload: key}}
			by[key] = a
		}
		a.row.Pods++
		a.cpuReq += cpuReq
		a.cpuLim += cpuLim
		a.memReq += memReq
		a.memLim += memLim

		// no CPU measurement at all (collector missing): do not pretend 0
		hasCPU := e.Stats.Sched != nil || (e.Stats.Res != nil && e.Stats.Res.WallUs > 0)
		avg := v.CoresUsed(e.Stats.Sched) * 1000
		if r := e.Stats.Res; r != nil && r.WallUs > 0 {
			avg = float64(r.CPUUsageUs) / float64(r.WallUs) * 1000
		}
		if hasCPU {
			a.cpuPods++
			a.cpuSum += avg
		}
		peak, mem := avg, 0.0
		if r := e.Stats.Res; r != nil {
			mem = math.Max(float64(r.MemPeak), float64(r.MemCurrent))
			// per-interval peak over the whole window (survives rollups)
			if r.CPUPeakMilli > peak {
				peak = r.CPUPeakMilli
				a.peakKnown = true
			}
		}
		for _, s := range v.Series[e.ID] {
			if s.CPUMilli > peak {
				peak = s.CPUMilli
				a.peakKnown = true
			}
			mem = math.Max(mem, float64(s.MemCurrent))
		}
		a.cpuPeak = math.Max(a.cpuPeak, peak)
		a.memPeak = math.Max(a.memPeak, mem)
	}
	const month = 730.0
	var out []RightsizeRow
	for _, a := range by {
		r := a.row
		n := float64(r.Pods)
		r.CPUReq, r.CPULim = a.cpuReq/int64(r.Pods), a.cpuLim/int64(r.Pods)
		r.MemReq, r.MemLim = a.memReq/int64(r.Pods), a.memLim/int64(r.Pods)
		r.CPUPeak, r.MemPeak = a.cpuPeak, a.memPeak
		if a.cpuPods > 0 {
			r.CPUAvg = a.cpuSum / float64(a.cpuPods)
			r.CPURec = int64(math.Max(10, roundUp(r.CPUPeak*1.2, 10)))
		}
		r.PeakKnown = a.peakKnown
		if r.MemPeak > 0 {
			r.MemRec = int64(math.Max(32<<20, roundUp(r.MemPeak*1.25, 16<<20)))
		}
		switch {
		case a.cpuPods == 0 && r.MemRec == 0:
			r.Verdict = "no-data"
		case r.CPUReq == 0 && r.MemReq == 0:
			r.Verdict = "no-requests"
		case (r.CPUReq > 0 && r.CPUPeak > float64(r.CPUReq)*1.1) || (r.MemLim > 0 && r.MemPeak > 0.9*float64(r.MemLim)):
			r.Verdict = "under"
		case (r.CPURec > 0 && r.CPUReq > 2*r.CPURec && r.CPUReq-r.CPURec >= 100) || (r.MemRec > 0 && r.MemReq > 2*r.MemRec && r.MemReq-r.MemRec >= 128<<20):
			r.Verdict = "over"
		default:
			r.Verdict = "ok"
		}
		if r.CPUReq > 0 && r.CPURec > 0 {
			r.MonthlyUSD += float64(r.CPUReq-r.CPURec) / 1000 * price.CorePerHour * month * n
		}
		if r.MemReq > 0 && r.MemRec > 0 {
			r.MonthlyUSD += float64(r.MemReq-r.MemRec) / (1 << 30) * price.GiBPerHour * month * n
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MonthlyUSD > out[j].MonthlyUSD })
	return out
}

// ---------------------------------------------------------------- OOM prediction

// OOMRisk is a projection of when a pod reaches its memory limit.
type OOMRisk struct {
	Endpoint    Endpoint
	Current     uint64
	Limit       uint64
	BytesPerSec float64
	ETA         time.Duration
	R2          float64 // fit quality of the linear trend
}

// linearFit returns slope (per second), intercept and R² of y over t.
func linearFit(ts []float64, ys []float64) (slope, r2 float64) {
	n := float64(len(ts))
	var st, sy, stt, sty float64
	for i := range ts {
		st += ts[i]
		sy += ys[i]
		stt += ts[i] * ts[i]
		sty += ts[i] * ys[i]
	}
	den := n*stt - st*st
	if den == 0 {
		return 0, 0
	}
	slope = (n*sty - st*sy) / den
	icpt := (sy - slope*st) / n
	mean := sy / n
	var ssr, sst float64
	for i := range ts {
		pred := slope*ts[i] + icpt
		ssr += (ys[i] - pred) * (ys[i] - pred)
		sst += (ys[i] - mean) * (ys[i] - mean)
	}
	if sst == 0 {
		return slope, 0
	}
	return slope, 1 - ssr/sst
}

// OOMRisks projects memory growth of pods with a limit onto their limit.
// Needs at least 6 samples over 60s and a clean linear trend (R² >= 0.6).
func OOMRisks(v *View) []OOMRisk {
	var out []OOMRisk
	for id, ser := range v.Series {
		if len(ser) < 6 {
			continue
		}
		last := ser[len(ser)-1]
		if last.MemMax == 0 || last.MemCurrent == 0 {
			continue
		}
		if len(ser) > 60 {
			ser = ser[len(ser)-60:]
		}
		span := ser[len(ser)-1].Time.Sub(ser[0].Time)
		if span < time.Minute {
			continue
		}
		ts := make([]float64, len(ser))
		ys := make([]float64, len(ser))
		for i, s := range ser {
			ts[i] = s.Time.Sub(ser[0].Time).Seconds()
			ys[i] = float64(s.MemCurrent)
		}
		slope, r2 := linearFit(ts, ys)
		if slope <= 0 || r2 < 0.6 {
			continue
		}
		left := float64(last.MemMax) - float64(last.MemCurrent)
		if left <= 0 {
			continue
		}
		// a nearly flat trend projects centuries ahead: do not overflow into a
		// negative ("imminent") ETA
		secs := math.Min(left/slope, 100*365*24*3600)
		eta := time.Duration(secs) * time.Second
		e := v.Entities[id]
		ep := Endpoint{ID: id, Name: id}
		if e != nil {
			ep = e.Endpoint
		}
		out = append(out, OOMRisk{Endpoint: ep, Current: last.MemCurrent, Limit: last.MemMax, BytesPerSec: slope, ETA: eta, R2: r2})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ETA < out[j].ETA })
	return out
}

// ---------------------------------------------------------------- policy denials

// Denial is traffic dropped by packet filtering between two endpoints.
type Denial struct {
	Src, Dst Endpoint
	Port     uint16
	Proto    string
	Reason   string
	Count    uint64
}

// isPolicyDrop reports drop reasons caused by packet filtering (iptables /
// nftables NetworkPolicies, tc/eBPF dataplanes, OVS).
func isPolicyDrop(reason string) bool {
	return strings.HasPrefix(reason, "NETFILTER") || strings.HasPrefix(reason, "TC_") ||
		strings.HasPrefix(reason, "OVS") || reason == "XDP_DROP" || reason == "BPF_CGROUP_EGRESS" || reason == "IP_RPFILTER"
}

// PolicyDenials attributes filtering drops to endpoint pairs.
func PolicyDenials(v *View) []Denial {
	by := map[string]*Denial{}
	for _, d := range v.Drops {
		if !isPolicyDrop(d.Reason) {
			continue
		}
		src, dst := v.IPEndpoint(d.Src, ""), v.IPEndpoint(d.Dst, "")
		k := src.ID + "|" + dst.ID + "|" + strconv.Itoa(int(d.Port)) + "|" + d.Proto
		x, ok := by[k]
		if !ok {
			x = &Denial{Src: src, Dst: dst, Port: d.Port, Proto: d.Proto, Reason: d.Reason}
			by[k] = x
		}
		x.Count += d.Count
	}
	var out []Denial
	for _, d := range by {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// ---------------------------------------------------------------- node matrix

// NodeMatrix is the RTT between nodes, from pod/host connections whose two
// ends are on known nodes.
type NodeMatrix struct {
	Nodes []string
	RTT   map[string]map[string]*model.Hist // client node -> server node
}

// BuildNodeMatrix aggregates edge RTTs by (client node, server node).
func BuildNodeMatrix(v *View) NodeMatrix {
	m := NodeMatrix{RTT: map[string]map[string]*model.Hist{}}
	seen := map[string]bool{}
	for n := range v.Nodes {
		seen[n] = true
	}
	for _, e := range v.Edges {
		cn, sn := e.Client.Node, e.Server.Node
		if cn == "" || sn == "" || e.Stats.RTT.Count == 0 || e.Client.Kind == KindLocal || e.Server.Kind == KindLocal {
			continue
		}
		seen[cn], seen[sn] = true, true
		row, ok := m.RTT[cn]
		if !ok {
			row = map[string]*model.Hist{}
			m.RTT[cn] = row
		}
		h, ok := row[sn]
		if !ok {
			h = &model.Hist{}
			row[sn] = h
		}
		h.Add(e.Stats.RTT)
	}
	for n := range seen {
		m.Nodes = append(m.Nodes, n)
	}
	sort.Strings(m.Nodes)
	return m
}

// Cell returns the RTT histogram between two nodes in either direction.
func (m NodeMatrix) Cell(a, b string) model.Hist {
	var h model.Hist
	if x := m.RTT[a][b]; x != nil {
		h.Add(*x)
	}
	if a != b {
		if x := m.RTT[b][a]; x != nil {
			h.Add(*x)
		}
	}
	return h
}

// SlowNodes returns nodes whose links to other nodes are slow while the
// links between the remaining nodes are not: the (lower) median RTT p50 of
// the node's links must exceed 3x the median of all links not involving it
// (and 1ms). Works from 3 nodes up.
func (m NodeMatrix) SlowNodes() map[string]float64 {
	if len(m.Nodes) < 3 {
		return nil
	}
	type link struct {
		a, b string
		p50  float64
	}
	var links []link
	for i, a := range m.Nodes {
		for _, b := range m.Nodes[i+1:] {
			if h := m.Cell(a, b); h.Count >= 10 {
				links = append(links, link{a, b, h.P50()})
			}
		}
	}
	lowerMedian := func(v []float64) float64 {
		sort.Float64s(v)
		return v[(len(v)-1)/2]
	}
	out := map[string]float64{}
	for _, n := range m.Nodes {
		var own, others []float64
		for _, l := range links {
			if l.a == n || l.b == n {
				own = append(own, l.p50)
			} else {
				others = append(others, l.p50)
			}
		}
		if len(own) == 0 || len(others) == 0 {
			continue
		}
		if o, rest := lowerMedian(own), lowerMedian(others); o > 3*rest && o > 1000 {
			out[n] = o
		}
	}
	return out
}

// ---------------------------------------------------------------- service balance

// BackendShare is one backend's share of a Service's traffic.
type BackendShare struct {
	Pod   Endpoint
	Conns uint64
	Bytes uint64
	Share float64
	Ready bool
}

// ServiceBalance describes how evenly a Service spreads load.
type ServiceBalance struct {
	Service   string
	Backends  []BackendShare
	Total     uint64 // connections (or bytes when there are no new connections)
	ByBytes   bool
	Imbalance float64 // busiest share / fair share
}

// minBalanceBytes is the traffic needed to judge byte-based balance.
const minBalanceBytes = 1 << 20

// ServiceBalances measures the distribution of server-side traffic over
// the ready backends of each Service with at least two backends.
func ServiceBalances(v *View) []ServiceBalance {
	var out []ServiceBalance
	for _, s := range v.Meta.Services {
		pods := v.Meta.PodsOfService(s)
		if len(pods) < 2 {
			continue
		}
		ports := map[uint16]bool{}
		for _, sp := range s.Ports {
			if n, err := strconv.Atoi(sp.TargetPort); err == nil {
				ports[uint16(n)] = true
			}
			ports[uint16(sp.Port)] = true
		}
		sb := ServiceBalance{Service: s.Namespace + "/" + s.Name}
		var conns, bytes uint64
		for _, p := range pods {
			if p.Phase != "Running" || p.Deleting {
				continue
			}
			bs := BackendShare{Pod: v.podEndpoint(p), Ready: p.Conditions["Ready"] != (time.Time{})}
			_, in := v.EdgesOf("pod:" + p.UID)
			for _, e := range in {
				if len(ports) == 0 || ports[e.Port] {
					bs.Conns += e.Stats.Connects
					bs.Bytes += e.Stats.BytesTx + e.Stats.BytesRx
				}
			}
			conns += bs.Conns
			bytes += bs.Bytes
			sb.Backends = append(sb.Backends, bs)
		}
		if len(sb.Backends) < 2 {
			continue
		}
		sb.Total = conns
		if conns < 20 {
			sb.ByBytes, sb.Total = true, bytes
			if bytes < minBalanceBytes {
				continue // too little traffic to judge
			}
		}
		if sb.Total == 0 {
			continue
		}
		var maxShare float64
		for i := range sb.Backends {
			b := &sb.Backends[i]
			val := b.Conns
			if sb.ByBytes {
				val = b.Bytes
			}
			b.Share = float64(val) / float64(sb.Total)
			maxShare = math.Max(maxShare, b.Share)
		}
		sb.Imbalance = maxShare * float64(len(sb.Backends))
		sort.Slice(sb.Backends, func(i, j int) bool { return sb.Backends[i].Share > sb.Backends[j].Share })
		out = append(out, sb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Imbalance > out[j].Imbalance })
	return out
}

// ---------------------------------------------------------------- startup events

var pulledIn = regexp.MustCompile(`in ([0-9.]+(?:ms|s|m[0-9.]*s?|h[0-9.ms]*))`)

// AddPodEvents merges Kubernetes events (scheduling, image pulls, sandbox
// creation) into a startup report and derives image pull and network/sandbox
// setup phases.
func AddPodEvents(rep *StartupReport, events []k8smeta.PodEvent) {
	var scheduled, firstPull, lastPulled, created time.Time
	var pullTotal time.Duration
	for _, e := range events {
		sev := ""
		if e.Type == "Warning" {
			sev = model.SevWarn
		}
		rep.Timeline = append(rep.Timeline, TimelineEntry{Time: e.First, Source: "k8s", Severity: sev, Text: e.Reason + ": " + e.Message})
		switch e.Reason {
		case "Scheduled":
			scheduled = e.First
		case "Pulling":
			if firstPull.IsZero() {
				firstPull = e.First
			}
		case "Pulled":
			lastPulled = e.Last
			if m := pulledIn.FindStringSubmatch(e.Message); m != nil {
				if d, err := time.ParseDuration(m[1]); err == nil {
					pullTotal += d
				}
			}
		case "Created":
			if created.IsZero() {
				created = e.First
			}
		case "FailedCreatePodSandBox":
			rep.Advice = append(rep.Advice, "sandbox/network setup failed at least once: "+e.Message)
		}
	}
	sort.SliceStable(rep.Timeline, func(i, j int) bool { return rep.Timeline[i].Time.Before(rep.Timeline[j].Time) })
	var phases []Phase
	if !scheduled.IsZero() {
		next := firstPull
		if next.IsZero() {
			next = created
		}
		if !next.IsZero() && next.After(scheduled) {
			phases = append(phases, Phase{"sandbox + network setup (≈)", next.Sub(scheduled)})
		}
	}
	if pullTotal > 0 {
		phases = append(phases, Phase{"image pull", pullTotal})
		if pullTotal > 30*time.Second {
			rep.Advice = append(rep.Advice, fmt.Sprintf("image pulls took %s: use smaller images, pre-pull on nodes, or a registry mirror close to the cluster", pullTotal.Round(time.Second)))
		}
	} else if !firstPull.IsZero() && !lastPulled.IsZero() {
		phases = append(phases, Phase{"image pull", lastPulled.Sub(firstPull)})
	}
	rep.Phases = append(phases, rep.Phases...)
}
