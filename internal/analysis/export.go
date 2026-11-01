package analysis

import (
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------- dependency map

// MapEdge is traffic between two workloads.
type MapEdge struct {
	From, To  string
	Port      uint16
	ConnRate  float64
	RTTP99    float64
	Errors    uint64 // refused + timeouts
	Retrans   uint64
	CrossZone bool
}

// Health of map elements.
const (
	HealthOK   = "ok"
	HealthWarn = "warn"
	HealthBad  = "bad"
)

// Health classifies an edge.
func (e MapEdge) Health() string {
	switch {
	case e.Errors > 0 || e.Retrans > 50:
		return HealthBad
	case e.RTTP99 > 50e3 || e.Retrans > 0:
		return HealthWarn
	}
	return HealthOK
}

// DependencyMap aggregates edges by workload and returns node health from
// the findings' subjects.
func DependencyMap(v *View, findings []Finding) ([]MapEdge, map[string]string) {
	agg := map[string]*MapEdge{}
	for _, e := range v.Edges {
		if e.Client.Kind == KindLocal || e.Server.Kind == KindLocal {
			continue
		}
		from, to := e.Client.WorkloadKey(), e.Server.WorkloadKey()
		k := from + "|" + to + "|" + fmt.Sprint(e.Port)
		m := agg[k]
		if m == nil {
			m = &MapEdge{From: from, To: to, Port: e.Port}
			agg[k] = m
		}
		m.ConnRate += v.PerSec(e.Stats.Connects)
		if p := e.Stats.RTT.P99(); p > m.RTTP99 {
			m.RTTP99 = p
		}
		m.Errors += e.Stats.Refused + e.Stats.Timeouts
		m.Retrans += e.Stats.Retrans
		m.CrossZone = m.CrossZone || e.CrossZone
	}
	health := map[string]string{}
	for _, f := range findings {
		for _, s := range f.Subjects {
			wk := s
			if e := v.Entities[s]; e != nil {
				wk = e.Endpoint.WorkloadKey()
			}
			h := HealthWarn
			if f.Severity == SevCrit {
				h = HealthBad
			}
			if health[wk] != HealthBad {
				health[wk] = h
			}
		}
	}
	var out []MapEdge
	for _, m := range agg {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From+out[i].To < out[j].From+out[j].To })
	return out, health
}

func mapLabel(e MapEdge) string {
	l := fmt.Sprintf("%d", e.Port)
	if e.ConnRate > 0 {
		l += " · " + Rate(e.ConnRate) + " conn/s"
	}
	if e.RTTP99 > 0 {
		l += " · p99 " + Dur(e.RTTP99)
	}
	if e.Errors > 0 {
		l += fmt.Sprintf(" · %d failed", e.Errors)
	}
	if e.CrossZone {
		l += " · cross-zone"
	}
	return l
}

// Mermaid renders the dependency map as a Mermaid flowchart.
func Mermaid(edges []MapEdge, health map[string]string) string {
	ids := map[string]string{}
	id := func(n string) string {
		if x, ok := ids[n]; ok {
			return x
		}
		x := fmt.Sprintf("n%d", len(ids))
		ids[n] = x
		return x
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for i, e := range edges {
		fmt.Fprintf(&b, "  %s[\"%s\"] -->|\"%s\"| %s[\"%s\"]\n", id(e.From), e.From, mapLabel(e), id(e.To), e.To)
		switch e.Health() {
		case HealthBad:
			fmt.Fprintf(&b, "  linkStyle %d stroke:#d33,stroke-width:3px\n", i)
		case HealthWarn:
			fmt.Fprintf(&b, "  linkStyle %d stroke:#e90,stroke-width:2px\n", i)
		}
	}
	b.WriteString("  classDef bad fill:#fdd,stroke:#d33\n  classDef warn fill:#fed,stroke:#e90\n")
	names := make([]string, 0, len(ids))
	for n := range ids {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if h := health[n]; h == HealthBad || h == HealthWarn {
			fmt.Fprintf(&b, "  class %s %s\n", ids[n], h)
		}
	}
	return b.String()
}

// Dot renders the dependency map in Graphviz format.
func Dot(edges []MapEdge, health map[string]string) string {
	var b strings.Builder
	b.WriteString("digraph capybara {\n  rankdir=LR;\n  node [shape=box, style=\"rounded,filled\", fillcolor=\"#eef\", fontname=\"Helvetica\"];\n")
	nodes := map[string]bool{}
	for _, e := range edges {
		nodes[e.From], nodes[e.To] = true, true
	}
	names := make([]string, 0, len(nodes))
	for n := range nodes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		color := "#eef"
		switch health[n] {
		case HealthBad:
			color = "#fdd"
		case HealthWarn:
			color = "#fed"
		}
		fmt.Fprintf(&b, "  %q [fillcolor=%q];\n", n, color)
	}
	for _, e := range edges {
		color := "#888"
		switch e.Health() {
		case HealthBad:
			color = "#d33"
		case HealthWarn:
			color = "#e90"
		}
		fmt.Fprintf(&b, "  %q -> %q [label=%q, color=%q];\n", e.From, e.To, mapLabel(e), color)
	}
	b.WriteString("}\n")
	return b.String()
}

// ---------------------------------------------------------------- cost per group

// GroupCost is the monthly cost of a namespace or team.
type GroupCost struct {
	Group        string
	Pods         int
	RequestUSD   float64 // what the requests reserve
	UsageUSD     float64 // what is actually used (average)
	WasteUSD     float64 // requested but unused
	CrossZoneUSD float64
	EgressUSD    float64 // internet egress
	EgressBytes  float64 // per second
}

// TotalUSD is requests + cross-zone + egress.
func (g GroupCost) TotalUSD() float64 { return g.RequestUSD + g.CrossZoneUSD + g.EgressUSD }

// CostByGroup estimates monthly costs per namespace (label == "") or per the
// value of a pod label (e.g. "team"; pods without it fall back to their
// namespace).
func CostByGroup(v *View, label string, price Pricing, egressPerGB float64) []GroupCost {
	const month = 730.0
	groupOf := func(e Endpoint) string {
		if e.Kind != KindPod {
			return ""
		}
		if label != "" {
			if p := v.Meta.Pods[strings.TrimPrefix(e.ID, "pod:")]; p != nil {
				if g := p.Labels[label]; g != "" {
					return g
				}
			}
		}
		if e.Namespace == "" {
			return "(unknown)"
		}
		return e.Namespace
	}
	by := map[string]*GroupCost{}
	get := func(g string) *GroupCost {
		c := by[g]
		if c == nil {
			c = &GroupCost{Group: g}
			by[g] = c
		}
		return c
	}
	for _, e := range v.PodEntities() {
		g := groupOf(e.Endpoint)
		if g == "" {
			continue
		}
		c := get(g)
		c.Pods++
		if e.Pod != nil {
			cpuReq, _, memReq, _ := e.Pod.Requests()
			c.RequestUSD += (float64(cpuReq)/1000*price.CorePerHour + float64(memReq)/(1<<30)*price.GiBPerHour) * month
			cores := v.CoresUsed(e.Stats.Sched)
			var mem float64
			if r := e.Stats.Res; r != nil {
				if r.WallUs > 0 {
					cores = float64(r.CPUUsageUs) / float64(r.WallUs)
				}
				mem = float64(r.MemCurrent)
			}
			used := (cores*price.CorePerHour + mem/(1<<30)*price.GiBPerHour) * month
			c.UsageUSD += used
			c.WasteUSD += max(0, (float64(cpuReq)/1000-cores)*price.CorePerHour*month) + max(0, (float64(memReq)-mem)/(1<<30)*price.GiBPerHour*month)
		}
	}
	for _, e := range v.Edges {
		g := groupOf(e.Client)
		if g == "" {
			continue
		}
		bytes := float64(e.Stats.BytesTx+e.Stats.BytesRx) / v.Seconds()
		if e.CrossZone {
			get(g).CrossZoneUSD += bytes * month * 3600 / 1e9 * v.Opts.CostPerGB * 2
		}
		if e.Server.Kind == KindExternal && !e.Server.Private {
			c := get(g)
			out := float64(e.Stats.BytesTx) / v.Seconds() // egress is billed on bytes leaving the cloud
			c.EgressBytes += out
			c.EgressUSD += out * month * 3600 / 1e9 * egressPerGB
		}
	}
	var out []GroupCost
	for _, c := range by {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TotalUSD() > out[j].TotalUSD() })
	return out
}
