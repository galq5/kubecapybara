package analysis

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/galq5/kubecapybara/internal/model"
)

// ---------------------------------------------------------------- outlier replicas

// Outlier is a replica that behaves much worse than its siblings.
type Outlier struct {
	Workload string
	Pod      Endpoint
	Metric   string
	Value    float64
	Median   float64
	Unit     string // "us", "ratio", "rate"
	Siblings int
}

// Factor is how many times worse the replica is than the median.
func (o Outlier) Factor() float64 { return ratio(o.Value, o.Median) }

// Format renders a value of the outlier's unit.
func (o Outlier) Format(v float64) string {
	switch o.Unit {
	case "us":
		return Dur(v)
	case "ratio":
		return Pct(v)
	}
	return Rate(v) + "/s"
}

type replicaMetric struct {
	name  string
	unit  string
	floor float64 // minimum absolute value to be worth reporting
	get   func(v *View, e *EntityView, out []*Edge) (float64, bool)
}

var replicaMetrics = []replicaMetric{
	{"HTTP p99", "us", 5000, func(v *View, e *EntityView, _ []*Edge) (float64, bool) {
		var h model.Hist
		for _, ep := range e.Stats.HTTP {
			if ep.Role == "server" {
				h.Add(ep.Lat)
			}
		}
		return h.P99(), h.Count >= 20
	}},
	{"HTTP 5xx rate", "ratio", 0.01, func(v *View, e *EntityView, _ []*Edge) (float64, bool) {
		var n, bad uint64
		for _, ep := range e.Stats.HTTP {
			if ep.Role == "server" {
				n += ep.Count
				bad += ep.Errors()
			}
		}
		return ratio(float64(bad), float64(n)), n >= 20
	}},
	{"RTT p99 to dependencies", "us", 1000, func(v *View, e *EntityView, out []*Edge) (float64, bool) {
		var h model.Hist
		for _, ed := range out {
			h.Add(ed.Stats.RTT)
		}
		return h.P99(), h.Count >= 20
	}},
	{"connect p99", "us", 1000, func(v *View, e *EntityView, out []*Edge) (float64, bool) {
		var h model.Hist
		for _, ed := range out {
			h.Add(ed.Stats.Connect)
		}
		return h.P99(), h.Count >= 20
	}},
	{"retransmits", "rate", 0.2, func(v *View, e *EntityView, out []*Edge) (float64, bool) {
		var r, samples uint64
		for _, ed := range out {
			r += ed.Stats.Retrans
			samples += ed.Stats.RTT.Count + ed.Stats.Connects
		}
		return v.PerSec(r), samples >= 20
	}},
	{"time waiting for CPU", "ratio", 0.05, func(v *View, e *EntityView, _ []*Edge) (float64, bool) {
		s := e.Stats.Sched
		if s == nil || s.RunQ.Count < 50 {
			return 0, false
		}
		q := float64(s.OffNs[model.StateRunQ])
		return ratio(q, q+float64(s.OnCPUNs)), true
	}},
	{"DB p99", "us", 5000, func(v *View, e *EntityView, _ []*Edge) (float64, bool) {
		var h model.Hist
		for _, q := range e.Stats.DB {
			h.Add(q.Lat)
		}
		return h.P99(), h.Count >= 20
	}},
	{"DNS p99", "us", 10000, func(v *View, e *EntityView, _ []*Edge) (float64, bool) {
		if d := e.Stats.DNS; d != nil {
			return d.Lat.P99(), d.Lat.Count >= 10
		}
		return 0, false
	}},
}

// Outliers compares replicas of each workload (3+ active pods) and returns
// pods that are at least 3x worse than the median of their siblings.
func Outliers(v *View) []Outlier {
	groups := map[string][]*EntityView{}
	for _, e := range v.PodEntities() {
		if e.Pod == nil || strings.HasPrefix(e.Pod.Workload, "Pod/") {
			continue
		}
		k := e.Pod.Namespace + "/" + e.Pod.Workload
		groups[k] = append(groups[k], e)
	}
	var out []Outlier
	for wl, pods := range groups {
		if len(pods) < 3 {
			continue
		}
		outEdges := map[string][]*Edge{}
		for _, p := range pods {
			o, _ := v.EdgesOf(p.ID)
			outEdges[p.ID] = o
		}
		for _, m := range replicaMetrics {
			vals := map[*EntityView]float64{}
			var all []float64
			for _, p := range pods {
				if x, ok := m.get(v, p, outEdges[p.ID]); ok {
					vals[p] = x
					all = append(all, x)
				}
			}
			if len(all) < 3 {
				continue
			}
			sort.Float64s(all)
			med := all[(len(all)-1)/2]
			for p, x := range vals {
				if x < m.floor {
					continue
				}
				if (med > 0 && x > 3*med) || (med == 0 && x >= m.floor) {
					out = append(out, Outlier{Workload: wl, Pod: p.Endpoint, Metric: m.name, Value: x, Median: med, Unit: m.unit, Siblings: len(all) - 1})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workload != out[j].Workload {
			return out[i].Workload < out[j].Workload
		}
		return out[i].Factor() > out[j].Factor()
	})
	return out
}

// OutlierNodes returns nodes hosting outliers of two or more workloads:
// the node, not the application, is the likely cause.
func OutlierNodes(outs []Outlier) map[string][]string {
	byNode := map[string]map[string]bool{}
	for _, o := range outs {
		if o.Pod.Node == "" {
			continue
		}
		if byNode[o.Pod.Node] == nil {
			byNode[o.Pod.Node] = map[string]bool{}
		}
		byNode[o.Pod.Node][o.Workload] = true
	}
	res := map[string][]string{}
	for n, wls := range byNode {
		if len(wls) >= 2 {
			for w := range wls {
				res[n] = append(res[n], w)
			}
			sort.Strings(res[n])
		}
	}
	return res
}

// ---------------------------------------------------------------- SLOs

// SLO is a service level objective on HTTP traffic of a workload or Service.
type SLO struct {
	Name     string        `json:"name"`
	Workload string        `json:"workload,omitempty"` // ns/Kind/name, e.g. shop/Deployment/checkout
	Service  string        `json:"service,omitempty"`  // ns/name of a Service (its backends)
	Latency  time.Duration `json:"-"`
	// LatencyRaw is the YAML latency threshold ("300ms").
	LatencyRaw       string  `json:"latency,omitempty"`
	LatencyObjective float64 `json:"latencyObjective,omitempty"` // % of requests faster than Latency, e.g. 99
	Availability     float64 `json:"availability,omitempty"`     // % of requests without 5xx, e.g. 99.5
}

// SLOFile is the YAML format of --slo-file.
type SLOFile struct {
	SLOs []SLO `json:"slos"`
}

// LoadSLOs reads SLO definitions from a YAML file.
func LoadSLOs(path string) ([]SLO, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f SLOFile
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range f.SLOs {
		s := &f.SLOs[i]
		if s.Name == "" || (s.Workload == "" && s.Service == "") {
			return nil, fmt.Errorf("%s: slo #%d needs a name and a workload or service", path, i+1)
		}
		if s.LatencyRaw != "" {
			d, err := time.ParseDuration(s.LatencyRaw)
			if err != nil {
				return nil, fmt.Errorf("%s: slo %s: latency: %w", path, s.Name, err)
			}
			s.Latency = d
			if s.LatencyObjective == 0 {
				s.LatencyObjective = 99
			}
		}
	}
	return f.SLOs, nil
}

// SLOStatus is the state of one SLO over a window.
type SLOStatus struct {
	SLO
	Requests      uint64
	Errors        uint64
	Slow          float64 // requests above the latency threshold
	AvailBurn     float64 // error budget burn rate (1 = exactly on budget)
	LatencyBurn   float64
	BaseAvailBurn float64
	BaseLatBurn   float64
	HasBase       bool
}

// Burn is the worst current burn rate.
func (s SLOStatus) Burn() float64 { return max(s.AvailBurn, s.LatencyBurn) }

// BaseBurn is the worst baseline burn rate.
func (s SLOStatus) BaseBurn() float64 { return max(s.BaseAvailBurn, s.BaseLatBurn) }

func sloTraffic(v *View, s SLO) (n, bad uint64, lat model.Hist) {
	pods := map[string]bool{}
	if s.Service != "" {
		ns, name, _ := strings.Cut(s.Service, "/")
		if svc := v.Meta.Service(ns, name); svc != nil {
			for _, p := range v.Meta.PodsOfService(svc) {
				pods["pod:"+p.UID] = true
			}
		}
	}
	for _, e := range v.PodEntities() {
		if e.Pod != nil && s.Workload != "" && e.Pod.Namespace+"/"+e.Pod.Workload == s.Workload {
			pods[e.ID] = true
		}
	}
	for id := range pods {
		e := v.Entities[id]
		if e == nil {
			continue
		}
		for _, ep := range e.Stats.HTTP {
			if ep.Role == "server" {
				n += ep.Count
				bad += ep.Errors()
				lat.Add(ep.Lat)
			}
		}
	}
	return
}

func burns(s SLO, n, bad uint64, lat model.Hist) (avail, latency, slow float64) {
	if n == 0 {
		return 0, 0, 0
	}
	if s.Availability > 0 && s.Availability < 100 {
		avail = ratio(float64(bad), float64(n)) / (1 - s.Availability/100)
	}
	if s.Latency > 0 && s.LatencyObjective > 0 && s.LatencyObjective < 100 {
		slowFrac := 1 - lat.FractionBelow(float64(s.Latency.Microseconds()))
		slow = slowFrac * float64(lat.Count)
		latency = slowFrac / (1 - s.LatencyObjective/100)
	}
	return
}

// EvaluateSLOs computes burn rates for the current window and the baseline.
func EvaluateSLOs(cur, base *View, slos []SLO) []SLOStatus {
	var out []SLOStatus
	for _, s := range slos {
		st := SLOStatus{SLO: s}
		var lat model.Hist
		st.Requests, st.Errors, lat = sloTraffic(cur, s)
		st.AvailBurn, st.LatencyBurn, st.Slow = burns(s, st.Requests, st.Errors, lat)
		if base != nil {
			bn, bbad, blat := sloTraffic(base, s)
			if bn > 0 {
				st.HasBase = true
				st.BaseAvailBurn, st.BaseLatBurn, _ = burns(s, bn, bbad, blat)
			}
		}
		out = append(out, st)
	}
	return out
}

// SLOFindings turns burn rates into findings (multi-window: the short and
// the long window must both burn fast, as in the SRE workbook: 14.4x burns
// a 30 day budget's 2% in an hour).
func SLOFindings(st []SLOStatus) []Finding {
	var out []Finding
	for _, s := range st {
		if s.Requests == 0 {
			continue
		}
		// each SLI must burn fast in both windows: a latency burn now and an
		// availability burn in the baseline is not a sustained burn
		baseAvail, baseLat := s.BaseAvailBurn, s.BaseLatBurn
		if !s.HasBase {
			baseAvail, baseLat = s.AvailBurn, s.LatencyBurn
		}
		var sev Severity
		switch b := max(min(s.AvailBurn, baseAvail), min(s.LatencyBurn, baseLat)); {
		case b >= 14.4:
			sev = SevCrit
		case b >= 6:
			sev = SevWarn
		default:
			continue
		}
		f := Finding{Severity: sev, Category: "slo", Rule: "slo-burn", Score: s.Burn(),
			Title: fmt.Sprintf("SLO %s is burning its error budget %.1fx too fast", s.Name, s.Burn())}
		if s.Availability > 0 {
			f.Detail = append(f.Detail, fmt.Sprintf("availability %.2f%% (objective %.2f%%): burn %.1fx now, %.1fx over the baseline",
				100*(1-ratio(float64(s.Errors), float64(s.Requests))), s.Availability, s.AvailBurn, s.BaseAvailBurn))
		}
		if s.Latency > 0 {
			f.Detail = append(f.Detail, fmt.Sprintf("%.1f%% of requests under %s (objective %.1f%%): burn %.1fx now, %.1fx over the baseline",
				100*(1-s.Slow/float64(max(s.Requests, 1))), s.Latency, s.LatencyObjective, s.LatencyBurn, s.BaseLatBurn))
		}
		f.Hint = "at this rate the 30 day error budget is gone in " + (time.Duration(float64(30*24*time.Hour) / s.Burn())).Round(time.Hour).String()
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------- connection pools

// Pool is the connections a client workload keeps to one dependency.
type Pool struct {
	Client     string // workload key
	Server     string
	Port       uint16
	Pods       int
	Open       uint64 // total across client pods
	Idle       uint64
	ConnPerSec float64
	BaseRate   float64 // baseline connects/s (0 if unknown)
}

// Pools aggregates open/idle connections per client workload and dependency.
func Pools(v *View, base *View) []Pool {
	type k struct {
		c, s string
		p    uint16
	}
	agg := map[k]*Pool{}
	pods := map[k]map[string]bool{}
	for _, e := range v.Edges {
		if e.Client.Kind != KindPod || e.Side == "server" {
			continue
		}
		key := k{e.Client.WorkloadKey(), e.Server.WorkloadKey(), e.Port}
		p := agg[key]
		if p == nil {
			p = &Pool{Client: key.c, Server: key.s, Port: key.p}
			agg[key] = p
			pods[key] = map[string]bool{}
		}
		pods[key][e.Client.ID] = true
		p.Open += e.Stats.OpenConns
		p.Idle += e.Stats.IdleConns
		p.ConnPerSec += v.PerSec(e.Stats.Connects)
	}
	if base != nil {
		for _, e := range base.Edges {
			if e.Client.Kind != KindPod || e.Side == "server" {
				continue
			}
			if p := agg[k{e.Client.WorkloadKey(), e.Server.WorkloadKey(), e.Port}]; p != nil {
				p.BaseRate += base.PerSec(e.Stats.Connects)
			}
		}
	}
	var out []Pool
	for key, p := range agg {
		p.Pods = len(pods[key])
		if p.Open == 0 && p.ConnPerSec == 0 {
			continue
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Open > out[j].Open })
	return out
}

func rulePools(v *View, base *View) []Finding {
	var idle, storms []string
	var score float64
	for _, p := range Pools(v, base) {
		perPod := float64(p.Idle) / float64(max(p.Pods, 1))
		if perPod >= 50 {
			idle = append(idle, fmt.Sprintf("%s → %s:%d: %d of %d connections idle (%.0f per pod)", p.Client, p.Server, p.Port, p.Idle, p.Open, perPod))
			score += perPod
		}
		if p.BaseRate > 0 && p.ConnPerSec >= 20 && p.ConnPerSec > 5*p.BaseRate {
			storms = append(storms, fmt.Sprintf("%s → %s:%d: %s new connections/s (baseline %s/s)", p.Client, p.Server, p.Port, Rate(p.ConnPerSec), Rate(p.BaseRate)))
			score += p.ConnPerSec
		}
	}
	var out []Finding
	if len(idle) > 0 {
		sort.Strings(idle)
		out = append(out, Finding{Severity: SevInfo, Category: "network", Rule: "pool-idle", Title: "oversized connection pools (many idle connections)",
			Detail: top(idle, 10), Hint: "idle connections cost memory on both sides and count against server limits (e.g. max_connections); lower pool max-idle sizes", Score: score})
	}
	if len(storms) > 0 {
		sort.Strings(storms)
		out = append(out, Finding{Severity: SevWarn, Category: "network", Rule: "connect-storm", Title: "connection storms (much higher connect rate than the baseline)",
			Detail: top(storms, 10), Hint: "a restart wave, a pool that keeps recycling, or retries after failures; check restarts and refused connections", Score: score})
	}
	return out
}

func ruleOutliers(v *View) []Finding {
	outs := Outliers(v)
	if len(outs) == 0 {
		return nil
	}
	var lines []string
	var subj []string
	for _, o := range outs {
		lines = append(lines, fmt.Sprintf("%s: %s %s vs %s median of %d siblings (×%.1f) on %s",
			o.Pod.Display(), o.Metric, o.Format(o.Value), o.Format(o.Median), o.Siblings, o.Factor(), o.Pod.Node))
		subj = append(subj, o.Pod.ID)
	}
	f := Finding{Severity: SevWarn, Category: "replica", Rule: "outlier-replica", Title: fmt.Sprintf("%d replica(s) much worse than their siblings", len(outs)),
		Detail: top(lines, 10), Subjects: subj, Score: float64(len(outs)),
		Hint: "one bad replica drives tail latency: delete the pod to reschedule it, or check its node (`kubectl capybara nodes`)"}
	for n, wls := range OutlierNodes(outs) {
		f.Detail = append(f.Detail, fmt.Sprintf("node %s hosts outliers of %d workloads (%s): suspect the node", n, len(wls), strings.Join(wls, ", ")))
	}
	return []Finding{f}
}
