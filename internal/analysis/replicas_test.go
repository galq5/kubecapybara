package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// four replicas of api; api-3 is slow and lives on node bad
func replicaFixture() ([]*model.Snapshot, *k8smeta.Meta) {
	now := time.Now()
	meta := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{}, Nodes: map[string]*k8smeta.Node{}}
	snap := &model.Snapshot{Node: "n1", From: now.Add(-time.Minute), To: now, Entities: map[string]*model.EntityStats{}}
	for i, node := range []string{"good", "good", "good", "bad"} {
		uid := "api-" + string(rune('0'+i))
		meta.Pods[uid] = &k8smeta.Pod{UID: uid, Namespace: "shop", Name: uid, Node: node, Workload: "Deployment/api", Phase: "Running",
			Labels: map[string]string{"app": "api"}, Conditions: map[string]time.Time{"Ready": now}}
		lat := uint64(4000)
		errs := uint64(1)
		if node == "bad" {
			lat, errs = 60000, 30
		}
		snap.Entities["pod:"+uid] = &model.EntityStats{ID: "pod:" + uid, HTTP: map[string]*model.HTTPEndpoint{
			"server GET /": {Role: "server", Method: "GET", Path: "/", Count: 200, Status: map[string]uint64{"2xx": 200 - errs, "5xx": errs}, Lat: hist(lat, 200)}}}
	}
	meta.Services = []*k8smeta.Service{{Namespace: "shop", Name: "api", Selector: map[string]string{"app": "api"}}}
	meta.Index()
	return []*model.Snapshot{snap}, meta
}

func TestOutliers(t *testing.T) {
	snaps, meta := replicaFixture()
	v := Build(snaps, meta, Options{})
	outs := Outliers(v)
	metrics := map[string]bool{}
	for _, o := range outs {
		if o.Pod.Name != "api-3" {
			t.Fatalf("healthy replica flagged: %+v", o)
		}
		metrics[o.Metric] = true
	}
	if !metrics["HTTP p99"] || !metrics["HTTP 5xx rate"] {
		t.Fatalf("missing outlier metrics: %+v", outs)
	}
	var found bool
	for _, f := range Doctor(v, nil) {
		if f.Rule == "outlier-replica" {
			found = true
		}
	}
	if !found {
		t.Fatal("no outlier finding")
	}
}

func TestSLOBurn(t *testing.T) {
	snaps, meta := replicaFixture()
	v := Build(snaps, meta, Options{})
	slos := []SLO{{Name: "api", Workload: "shop/Deployment/api", Availability: 99.9, Latency: 10 * time.Millisecond, LatencyObjective: 99}}
	st := EvaluateSLOs(v, nil, slos)
	if len(st) != 1 || st[0].Requests != 800 || st[0].Errors != 33 {
		t.Fatalf("traffic: %+v", st)
	}
	// 33/800 = 4.1% errors vs 0.1% budget -> ~41x; 25% slow vs 1% -> 25x
	if st[0].AvailBurn < 40 || st[0].AvailBurn > 42 || st[0].LatencyBurn < 20 {
		t.Fatalf("burn: %+v", st[0])
	}
	fs := SLOFindings(st)
	if len(fs) != 1 || fs[0].Severity != SevCrit {
		t.Fatalf("findings: %+v", fs)
	}
	// by Service selector gives the same traffic
	st = EvaluateSLOs(v, nil, []SLO{{Name: "svc", Service: "shop/api", Availability: 99}})
	if st[0].Requests != 800 {
		t.Fatalf("service slo: %+v", st[0])
	}
}

func TestLoadSLOs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "slos.yaml")
	os.WriteFile(p, []byte("slos:\n  - name: checkout\n    workload: shop/Deployment/checkout\n    availability: 99.5\n    latency: 300ms\n"), 0o644)
	slos, err := LoadSLOs(p)
	if err != nil || len(slos) != 1 || slos[0].Latency != 300*time.Millisecond || slos[0].LatencyObjective != 99 {
		t.Fatalf("%v %+v", err, slos)
	}
	os.WriteFile(p, []byte("slos:\n  - name: x\n    bogus: 1\n"), 0o644)
	if _, err := LoadSLOs(p); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("unknown fields must fail: %v", err)
	}
}

func TestFractionBelow(t *testing.T) {
	var h model.Hist
	for i := 0; i < 90; i++ {
		h.Observe(1000)
	}
	for i := 0; i < 10; i++ {
		h.Observe(100000)
	}
	if f := h.FractionBelow(50000); f < 0.89 || f > 0.91 {
		t.Fatalf("fraction %v", f)
	}
}

func TestPoolsAndStorms(t *testing.T) {
	snaps, meta := fixture(t)
	snaps[0].Pairs[0].OpenConns, snaps[0].Pairs[0].IdleConns = 120, 100
	v := Build(snaps, meta, Options{})
	base := Build(snaps, meta, Options{})
	for _, e := range base.Edges {
		e.Stats.Connects = 10 // baseline 0.17/s vs 10/s now
	}
	pools := Pools(v, base)
	if len(pools) == 0 || pools[0].Open != 120 || pools[0].Idle != 100 {
		t.Fatalf("pools: %+v", pools)
	}
	rules := map[string]bool{}
	for _, f := range DoctorWith(v, base, nil) {
		rules[f.Rule] = true
	}
	if !rules["pool-idle"] {
		t.Fatalf("no idle pool finding: %v", rules)
	}
}

func TestIncidentTimeline(t *testing.T) {
	snaps, meta := replicaFixture()
	t0 := time.Now().Add(-10 * time.Minute)
	var steps []*View
	for i := 0; i < 6; i++ {
		s := *snaps[0]
		s.Entities = map[string]*model.EntityStats{}
		lat := uint64(3000)
		if i >= 4 { // regression in the last two steps
			lat = 80000
		}
		s.Entities["pod:api-0"] = &model.EntityStats{ID: "pod:api-0", HTTP: map[string]*model.HTTPEndpoint{
			"server GET /": {Role: "server", Count: 100, Status: map[string]uint64{"2xx": 100}, Lat: hist(lat, 100)}}}
		v := Build([]*model.Snapshot{&s}, meta, Options{})
		v.From, v.To = t0.Add(time.Duration(i)*time.Minute), t0.Add(time.Duration(i+1)*time.Minute)
		steps = append(steps, v)
	}
	changes := []k8smeta.Change{
		{Time: t0.Add(3*time.Minute + 30*time.Second), Kind: "rollout", Namespace: "shop", Name: "Deployment/api", Text: "rollout of deployment shop/api (revision 7)"},
		{Time: t0.Add(4 * time.Minute), Kind: "node", Name: "Node/x", Text: "node x joined"},
	}
	items := Incident(steps, nil, changes)
	var jump *TimelineItem
	for i := range items {
		if items[i].Kind == "metric" && strings.Contains(items[i].Text, "HTTP p99 rose") {
			jump = &items[i]
		}
	}
	if jump == nil || !strings.Contains(jump.Cause, "revision 7") {
		t.Fatalf("expected the p99 jump to be attributed to the rollout: %+v", items)
	}
}

func TestProfileDiff(t *testing.T) {
	before := &model.Profile{Samples: 100, Stacks: []model.Stack{
		{Comm: "app", Frames: []string{"app", "main", "handle", "json.Marshal"}, Count: 20},
		{Comm: "app", Frames: []string{"app", "main", "handle", "db.Query"}, Count: 80}}}
	now := &model.Profile{Samples: 100, Stacks: []model.Stack{
		{Comm: "app", Frames: []string{"app", "main", "handle", "json.Marshal"}, Count: 50},
		{Comm: "app", Frames: []string{"app", "main", "handle", "db.Query"}, Count: 50}}}
	d := ProfileDiff(before, now)
	if len(d) == 0 || (d[0].Name != "json.Marshal" && d[0].Name != "db.Query") || d[0].Now-d[0].Before == 0 {
		t.Fatalf("diff: %+v", d)
	}
	for _, x := range d {
		if x.Name == "json.Marshal" && (x.Before != 0.2 || x.Now != 0.5) {
			t.Fatalf("json.Marshal: %+v", x)
		}
	}
}
