package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// TimelineItem is one line of an incident timeline.
type TimelineItem struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"` // change, signal, metric
	Severity string    `json:"severity,omitempty"`
	Subject  string    `json:"subject,omitempty"`
	Text     string    `json:"text"`
	Cause    string    `json:"cause,omitempty"` // correlated preceding change
}

type metricDef struct {
	name  string
	unit  string
	floor float64
	get   func(v *View, ids map[string]bool) (float64, bool)
}

func groupHTTP(v *View, ids map[string]bool) (n, bad uint64, h model.Hist) {
	for id := range ids {
		if e := v.Entities[id]; e != nil {
			for _, ep := range e.Stats.HTTP {
				if ep.Role == "server" {
					n += ep.Count
					bad += ep.Errors()
					h.Add(ep.Lat)
				}
			}
		}
	}
	return
}

var incidentMetrics = []metricDef{
	{"HTTP p99", "us", 10000, func(v *View, ids map[string]bool) (float64, bool) {
		n, _, h := groupHTTP(v, ids)
		return h.P99(), n >= 20
	}},
	{"HTTP 5xx rate", "ratio", 0.02, func(v *View, ids map[string]bool) (float64, bool) {
		n, bad, _ := groupHTTP(v, ids)
		return ratio(float64(bad), float64(n)), n >= 20
	}},
	{"DB p99", "us", 10000, func(v *View, ids map[string]bool) (float64, bool) {
		var h model.Hist
		for id := range ids {
			if e := v.Entities[id]; e != nil {
				for _, q := range e.Stats.DB {
					h.Add(q.Lat)
				}
			}
		}
		return h.P99(), h.Count >= 20
	}},
	{"RTT p99 to dependencies", "us", 2000, func(v *View, ids map[string]bool) (float64, bool) {
		var h model.Hist
		for _, e := range v.Edges {
			if ids[e.Client.ID] {
				h.Add(e.Stats.RTT)
			}
		}
		return h.P99(), h.Count >= 20
	}},
	{"refused connections", "rate", 0.5, func(v *View, ids map[string]bool) (float64, bool) {
		var r uint64
		for _, e := range v.Edges {
			if ids[e.Client.ID] {
				r += e.Stats.Refused + e.Stats.Timeouts
			}
		}
		return v.PerSec(r), true
	}},
	{"DNS failures", "rate", 0.5, func(v *View, ids map[string]bool) (float64, bool) {
		var bad uint64
		for id := range ids {
			if e := v.Entities[id]; e != nil && e.Stats.DNS != nil {
				d := e.Stats.DNS
				bad += d.RCodes["SERVFAIL"] + d.RCodes["REFUSED"] + d.Timeouts
			}
		}
		return v.PerSec(bad), true
	}},
}

func formatUnit(unit string, v float64) string {
	switch unit {
	case "us":
		return Dur(v)
	case "ratio":
		return Pct(v)
	}
	return Rate(v) + "/s"
}

// Incident builds a timeline from per-step views (oldest first), the view
// of the whole range (for agent signals) and cluster changes. Metric jumps
// (3x the median of the preceding steps) are correlated with the latest
// change within 15 minutes before them, preferring the same namespace.
func Incident(steps []*View, whole *View, changes []k8smeta.Change) []TimelineItem {
	var out []TimelineItem
	for _, c := range changes {
		sev := ""
		if c.Warning {
			sev = model.SevWarn
		}
		subj := c.Name
		if c.Namespace != "" {
			subj = c.Namespace + "/" + c.Name
		}
		out = append(out, TimelineItem{Time: c.Time, Kind: "change", Severity: sev, Subject: subj, Text: c.Text})
	}
	if whole != nil {
		for _, c := range whole.Crashes {
			out = append(out, TimelineItem{Time: c.Time, Kind: "signal", Severity: model.SevCrit, Subject: c.Endpoint.Display(), Text: "crash: " + c.Reason})
		}
		for _, e := range whole.Events {
			if e.Severity == model.SevCrit || e.Type == model.EvOOM || e.Type == model.EvExecSession {
				out = append(out, TimelineItem{Time: e.Time, Kind: "signal", Severity: e.Severity, Subject: e.Endpoint.Display(), Text: e.Message})
			}
		}
	}

	// workload groups across all steps
	groups := map[string]map[string]bool{}
	ns := map[string]string{}
	for _, v := range steps {
		for _, e := range v.PodEntities() {
			if e.Pod == nil {
				continue
			}
			k := e.Pod.Namespace + "/" + e.Pod.Workload
			if groups[k] == nil {
				groups[k] = map[string]bool{}
			}
			groups[k][e.ID] = true
			ns[k] = e.Pod.Namespace
		}
	}
	for wl, ids := range groups {
		for _, m := range incidentMetrics {
			var hist []float64
			degraded := false
			var base float64
			for _, v := range steps {
				x, ok := m.get(v, ids)
				if !ok {
					continue
				}
				if len(hist) >= 2 {
					sorted := append([]float64(nil), hist...)
					sort.Float64s(sorted)
					med := sorted[(len(sorted)-1)/2]
					switch {
					case !degraded && x >= m.floor && (x >= 3*med && med > 0 || med == 0 && m.unit != "us"):
						degraded, base = true, med
						it := TimelineItem{Time: v.From, Kind: "metric", Severity: model.SevWarn, Subject: wl,
							Text: fmt.Sprintf("%s rose: %s → %s", m.name, formatUnit(m.unit, med), formatUnit(m.unit, x))}
						it.Cause = correlate(changes, v.To, ns[wl], wl)
						out = append(out, it)
					case degraded && x < 1.5*base+m.floor/3:
						degraded = false
						out = append(out, TimelineItem{Time: v.From, Kind: "metric", Subject: wl,
							Text: fmt.Sprintf("%s recovered: %s", m.name, formatUnit(m.unit, x))})
					}
				}
				if !degraded {
					hist = append(hist, x)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// correlate returns the latest change shortly before t, preferring the same
// workload, then the same namespace, then any rollout/node/config change.
func correlate(changes []k8smeta.Change, t time.Time, ns, workload string) string {
	_, wlName, _ := strings.Cut(strings.TrimPrefix(workload, ns+"/"), "/")
	best, bestScore := "", 0
	for _, c := range changes {
		if c.Time.After(t) || t.Sub(c.Time) > 15*time.Minute {
			continue
		}
		score := 1
		switch {
		case wlName != "" && strings.Contains(c.Name, wlName):
			score = 4
		case c.Namespace == ns && c.Namespace != "":
			score = 3
		case c.Kind == "rollout" || c.Kind == "node" || c.Kind == "config":
			score = 2
		}
		if score >= bestScore {
			best, bestScore = fmt.Sprintf("%s before: %s", t.Sub(c.Time).Round(time.Second), c.Text), score
		}
	}
	return best
}
