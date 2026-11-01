package analysis

import (
	"fmt"
	"sort"
	"strconv"
)

// Regressions compares the current window with a baseline window and
// reports what got significantly worse or is new.
func Regressions(cur, base *View) []Finding {
	var out []Finding
	var lines []string
	var score float64

	baseEdges := map[string]*Edge{}
	baseDeps := map[string]bool{}
	for _, e := range base.Edges {
		baseEdges[e.Client.ID+"|"+e.Server.ID+"|"+strconv.Itoa(int(e.Port))] = e
		baseDeps[e.Client.WorkloadKey()+"|"+e.Server.WorkloadKey()] = true
	}
	for _, e := range cur.Edges {
		b, ok := baseEdges[e.Client.ID+"|"+e.Server.ID+"|"+strconv.Itoa(int(e.Port))]
		if !ok {
			continue
		}
		if c, p := e.Stats.RTT, b.Stats.RTT; c.Count >= 20 && p.Count >= 20 {
			if r := ratio(c.P99(), p.P99()); r >= 3 && c.P99() >= 1000 {
				lines = append(lines, fmt.Sprintf("network RTT %s: p99 %s → %s (×%.1f)", edgeName(e), Dur(p.P99()), Dur(c.P99()), r))
				score += r
			}
		}
		if c, p := e.Stats.Connect, b.Stats.Connect; c.Count >= 20 && p.Count >= 20 {
			if r := ratio(c.P99(), p.P99()); r >= 3 && c.P99() >= 1000 {
				lines = append(lines, fmt.Sprintf("connect latency %s: p99 %s → %s (×%.1f)", edgeName(e), Dur(p.P99()), Dur(c.P99()), r))
				score += r
			}
		}
		cr, br := cur.PerSec(e.Stats.Retrans), base.PerSec(b.Stats.Retrans)
		if e.Stats.Retrans >= 20 && cr > 3*br {
			lines = append(lines, fmt.Sprintf("retransmits %s: %s/s → %s/s", edgeName(e), Rate(br), Rate(cr)))
			score += 2
		}
	}

	for id, e := range cur.Entities {
		b := base.Entities[id]
		if b == nil {
			continue
		}
		name := e.Endpoint.Display()
		if c, p := e.Stats.DNS, b.Stats.DNS; c != nil && p != nil && c.Lat.Count >= 20 && p.Lat.Count >= 20 {
			if r := ratio(c.Lat.P99(), p.Lat.P99()); r >= 3 && c.Lat.P99() >= 20e3 {
				lines = append(lines, fmt.Sprintf("DNS latency %s: p99 %s → %s", name, Dur(p.Lat.P99()), Dur(c.Lat.P99())))
				score += r
			}
		}
		if c, p := e.Stats.Sched, b.Stats.Sched; c != nil && p != nil && c.RunQ.Count >= 50 && p.RunQ.Count >= 50 {
			if r := ratio(c.RunQ.P99(), p.RunQ.P99()); r >= 3 && c.RunQ.P99() >= 10e3 {
				lines = append(lines, fmt.Sprintf("CPU run queue %s: p99 %s → %s", name, Dur(p.RunQ.P99()), Dur(c.RunQ.P99())))
				score += r
			}
		}
		for k, ep := range e.Stats.HTTP {
			pb := b.Stats.HTTP[k]
			if pb == nil || ep.Count < 20 || pb.Count < 20 {
				continue
			}
			if r := ratio(ep.Lat.P99(), pb.Lat.P99()); r >= 2 && ep.Lat.P99() >= 50e3 {
				lines = append(lines, fmt.Sprintf("HTTP latency %s %s %s: p99 %s → %s", name, ep.Method, ep.Path, Dur(pb.Lat.P99()), Dur(ep.Lat.P99())))
				score += r
			}
			ce, be := ratio(float64(ep.Errors()), float64(ep.Count)), ratio(float64(pb.Errors()), float64(pb.Count))
			if ce > 0.05 && be < 0.01 {
				lines = append(lines, fmt.Sprintf("HTTP errors %s %s %s: %s → %s 5xx", name, ep.Method, ep.Path, Pct(be), Pct(ce)))
				score += 5
			}
		}
	}
	if len(lines) > 0 {
		sort.Strings(lines)
		out = append(out, Finding{Severity: SevWarn, Category: "regression",
			Title:  fmt.Sprintf("%d metric(s) regressed vs. the baseline window", len(lines)),
			Detail: top(lines, 12), Score: score,
			Hint: "compare with recent deploys: `kubectl capybara rollout <deployment>`"})
	}

	// new dependencies (only meaningful with a long enough baseline)
	if base.Seconds() >= 600 {
		var deps []string
		seen := map[string]bool{}
		for _, e := range cur.Edges {
			if e.Client.Kind != KindPod || e.Side == "server" {
				continue
			}
			k := e.Client.WorkloadKey() + "|" + e.Server.WorkloadKey()
			if baseDeps[k] || seen[k] {
				continue
			}
			seen[k] = true
			deps = append(deps, fmt.Sprintf("%s → %s:%d", e.Client.WorkloadKey(), e.Server.Display(), e.Port))
		}
		if len(deps) > 0 {
			sort.Strings(deps)
			out = append(out, Finding{Severity: SevInfo, Category: "regression",
				Title:  fmt.Sprintf("%d new dependency(ies) not seen in the baseline window", len(deps)),
				Detail: top(deps, 10), Score: float64(len(deps))})
		}
	}
	return out
}
