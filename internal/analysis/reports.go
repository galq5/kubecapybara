package analysis

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// ---------------------------------------------------------------- cost

// ZoneCost is cross-zone traffic between two workloads.
type ZoneCost struct {
	Client, Server         string
	ClientZone, ServerZone string
	BytesPerSec            float64
	MonthlyUSD             float64
}

// CrossZoneCosts estimates inter-zone transfer costs per workload pair.
// Cloud providers typically bill inter-AZ traffic in both directions.
func CrossZoneCosts(v *View) []ZoneCost {
	agg := map[string]*ZoneCost{}
	for _, e := range v.Edges {
		if !e.CrossZone {
			continue
		}
		bytes := float64(e.Stats.BytesTx + e.Stats.BytesRx)
		if bytes == 0 {
			continue
		}
		k := e.Client.WorkloadKey() + "|" + e.Server.WorkloadKey() + "|" + e.Client.Zone + "|" + e.Server.Zone
		c, ok := agg[k]
		if !ok {
			c = &ZoneCost{Client: e.Client.WorkloadKey(), Server: e.Server.WorkloadKey(), ClientZone: e.Client.Zone, ServerZone: e.Server.Zone}
			agg[k] = c
		}
		c.BytesPerSec += bytes / v.Seconds()
	}
	var out []ZoneCost
	const month = 30 * 24 * 3600
	for _, c := range agg {
		c.MonthlyUSD = c.BytesPerSec * month / 1e9 * v.Opts.CostPerGB * 2
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MonthlyUSD > out[j].MonthlyUSD })
	return out
}

// ---------------------------------------------------------------- security

// UndeclaredPorts returns listening sockets of pods that are not declared as
// containerPorts nor targeted by a Service.
func UndeclaredPorts(v *View) []ListenView {
	var out []ListenView
	seen := map[string]bool{}
	for _, l := range v.Listens {
		if l.Endpoint.Kind != KindPod {
			continue
		}
		uid := strings.TrimPrefix(l.Entity, "pod:")
		pod := v.Meta.Pods[uid]
		if pod == nil {
			continue
		}
		if a, err := netip.ParseAddr(l.Addr); err == nil && a.IsLoopback() {
			continue
		}
		if portDeclared(v.Meta, pod, l.Port) {
			continue
		}
		k := l.Entity + "|" + strconv.Itoa(int(l.Port))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	return out
}

func portDeclared(m *k8smeta.Meta, pod *k8smeta.Pod, port uint16) bool {
	for _, c := range pod.Containers {
		for _, p := range c.Ports {
			if uint16(p) == port {
				return true
			}
		}
		for _, pr := range c.Probes {
			if uint16(pr.Port) == port {
				return true
			}
		}
	}
	for _, s := range m.ServicesOfPod(pod) {
		for _, sp := range s.Ports {
			if sp.TargetPort == strconv.Itoa(int(port)) {
				return true
			}
		}
	}
	return false
}

// Egress is external traffic of one workload.
type Egress struct {
	Workload     string
	Destinations []string
	Bytes        uint64
}

// ExternalEgress lists workloads connecting to public internet endpoints.
func ExternalEgress(v *View) []Egress {
	by := map[string]*Egress{}
	dests := map[string]map[string]bool{}
	for _, e := range v.Edges {
		if e.Client.Kind != KindPod || e.Server.Kind != KindExternal || e.Server.Private {
			continue
		}
		k := e.Client.WorkloadKey()
		g, ok := by[k]
		if !ok {
			g = &Egress{Workload: k}
			by[k] = g
			dests[k] = map[string]bool{}
		}
		d := fmt.Sprintf("%s:%d", e.Server.Display(), e.Port)
		if !dests[k][d] {
			dests[k][d] = true
			g.Destinations = append(g.Destinations, d)
		}
		g.Bytes += e.Stats.BytesTx + e.Stats.BytesRx
	}
	var out []Egress
	for _, g := range by {
		sort.Strings(g.Destinations)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// ---------------------------------------------------------------- time breakdown

// Breakdown is the share of thread time per state of an entity.
type Breakdown struct {
	State string
	Ns    uint64
	Share float64
}

// TimeBreakdown returns the on-CPU/off-CPU split of an entity.
func TimeBreakdown(s *model.SchedStats) []Breakdown {
	if s == nil {
		return nil
	}
	total := float64(s.TotalNs())
	if total == 0 {
		return nil
	}
	out := []Breakdown{{"on-cpu", s.OnCPUNs, float64(s.OnCPUNs) / total}}
	labels := map[string]string{
		model.StateRunQ: "waiting for CPU", model.StateDisk: "disk / D-state", model.StateNet: "network / read-write",
		model.StatePoll: "event loop idle (poll)", model.StateLock: "locks / futex", model.StateSleep: "sleep", model.StateOther: "other wait",
	}
	for _, st := range model.OffStates {
		if ns := s.OffNs[st]; ns > 0 {
			out = append(out, Breakdown{labels[st], ns, float64(ns) / total})
		}
	}
	return out
}

// CoresUsed returns average CPU cores used by an entity over the window.
func (v *View) CoresUsed(s *model.SchedStats) float64 {
	if s == nil {
		return 0
	}
	return float64(s.OnCPUNs) / 1e9 / v.Seconds()
}

// ---------------------------------------------------------------- dns

// DNSNameStat is a ranked DNS name.
type DNSNameStat struct {
	Entity string
	Name   string
	model.DNSName
}

// TopDNSNames returns the most queried names across entities.
func TopDNSNames(v *View, n int) []DNSNameStat {
	agg := map[string]*DNSNameStat{}
	for _, e := range v.Entities {
		if e.Stats.DNS == nil {
			continue
		}
		for name, s := range e.Stats.DNS.Names {
			a, ok := agg[name]
			if !ok {
				a = &DNSNameStat{Name: name, Entity: e.Endpoint.Display()}
				agg[name] = a
			} else if a.Entity != e.Endpoint.Display() {
				a.Entity = "(multiple)"
			}
			a.Count += s.Count
			a.NXDomain += s.NXDomain
			a.Errors += s.Errors
			a.Timeouts += s.Timeouts
			a.LatSumUs += s.LatSumUs
			a.Answered += s.Answered
		}
	}
	var out []DNSNameStat
	for _, a := range agg {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return top(out, n)
}

// ---------------------------------------------------------------- profiles

// FuncStat is a function's sample counts in a profile.
type FuncStat struct {
	Name  string
	Self  uint64
	Total uint64
}

// TopFunctions aggregates a profile by function.
func TopFunctions(p *model.Profile) []FuncStat {
	self := map[string]uint64{}
	total := map[string]uint64{}
	for _, st := range p.Stacks {
		if len(st.Frames) == 0 {
			continue
		}
		leaf := st.Frames[len(st.Frames)-1]
		self[leaf] += st.Count
		seen := map[string]bool{}
		for _, f := range st.Frames[1:] { // frame 0 is the comm
			if !seen[f] {
				total[f] += st.Count
				seen[f] = true
			}
		}
	}
	var out []FuncStat
	for f, t := range total {
		out = append(out, FuncStat{Name: f, Self: self[f], Total: t})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Self != out[j].Self {
			return out[i].Self > out[j].Self
		}
		return out[i].Total > out[j].Total
	})
	return out
}

// Folded renders a profile in Brendan Gregg's folded format (for
// flamegraph.pl, speedscope, inferno...).
func Folded(p *model.Profile) string {
	var b strings.Builder
	for _, st := range p.Stacks {
		fmt.Fprintf(&b, "%s %d\n", strings.Join(st.Frames, ";"), st.Count)
	}
	return b.String()
}

// FuncDelta is the change of a function's share of CPU samples between two
// profiles.
type FuncDelta struct {
	Name        string
	Before, Now float64 // self share of samples (0..1)
	TotalBefore float64
	TotalNow    float64
}

// ProfileDiff compares two profiles by self and total share per function,
// sorted by the largest self-share change.
func ProfileDiff(before, now *model.Profile) []FuncDelta {
	share := func(p *model.Profile) (map[string]float64, map[string]float64) {
		self, total := map[string]float64{}, map[string]float64{}
		if p.Samples == 0 {
			return self, total
		}
		for _, f := range TopFunctions(p) {
			self[f.Name] = float64(f.Self) / float64(p.Samples)
			total[f.Name] = float64(f.Total) / float64(p.Samples)
		}
		return self, total
	}
	sb, tb := share(before)
	sn, tn := share(now)
	names := map[string]bool{}
	for k := range sb {
		names[k] = true
	}
	for k := range sn {
		names[k] = true
	}
	var out []FuncDelta
	for n := range names {
		out = append(out, FuncDelta{Name: n, Before: sb[n], Now: sn[n], TotalBefore: tb[n], TotalNow: tn[n]})
	}
	abs := func(x float64) float64 {
		if x < 0 {
			return -x
		}
		return x
	}
	sort.Slice(out, func(i, j int) bool { return abs(out[i].Now-out[i].Before) > abs(out[j].Now-out[j].Before) })
	return out
}
