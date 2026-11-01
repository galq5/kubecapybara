package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/analysis"
	cmodel "github.com/galq5/kubecapybara/internal/model"
)

// TestFramesRender renders every tab to catch panics in the render paths.
func TestFramesRender(t *testing.T) {
	now := time.Now()
	var h cmodel.Hist
	h.Observe(500)
	snap := &cmodel.Snapshot{
		Node: "n1", From: now.Add(-time.Minute), To: now,
		Pairs: []*cmodel.Pair{{Client: "10.0.0.1", Server: "10.0.0.2", Port: 80, Side: "client", Owner: "pod:a", RTT: h, Connects: 3}},
		Entities: map[string]*cmodel.EntityStats{"pod:a": {ID: "pod:a",
			Sched: &cmodel.SchedStats{OnCPUNs: 1e9, OffNs: map[string]uint64{"runq": 1e6}, RunQ: h},
			DNS:   &cmodel.DNSStats{Queries: 1, Responses: 1, RCodes: map[string]uint64{"NOERROR": 1}, Lat: h, Names: map[string]*cmodel.DNSName{"x": {Count: 1}}},
			HTTP:  map[string]*cmodel.HTTPEndpoint{"server GET /": {Role: "server", Method: "GET", Path: "/", Count: 1, Status: map[string]uint64{"2xx": 1}, Lat: h}}}},
		Events: []cmodel.Event{{Time: now, Entity: "pod:a", Type: cmodel.EvExec, Message: "exec x"}},
	}
	v := analysis.Build([]*cmodel.Snapshot{snap}, nil, analysis.Options{})
	res := &Result{View: v, Findings: analysis.Doctor(v, nil)}
	for i := range tabs {
		out := Frame(res, Options{Window: time.Minute}, 140, 40, i, "")
		if !strings.Contains(out, tabs[i]) {
			t.Errorf("tab %s not rendered", tabs[i])
		}
	}
	if out := Frame(res, Options{Window: time.Minute}, 140, 40, 2, "pod:a"); !strings.Contains(out, "Where the time goes") {
		t.Errorf("pod detail not rendered:\n%s", out)
	}
}
