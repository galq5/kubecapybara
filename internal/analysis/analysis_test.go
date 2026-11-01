package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

func hist(us uint64, n int) model.Hist {
	var h model.Hist
	for i := 0; i < n; i++ {
		h.Observe(us)
	}
	return h
}

// fixture: frontend (zone a) calls payments via its Service (zone b),
// payments calls api.stripe.com; payments has two revisions.
func fixture(t *testing.T) ([]*model.Snapshot, *k8smeta.Meta) {
	t.Helper()
	now := time.Now()
	meta := &k8smeta.Meta{
		ClusterDomain: "cluster.local",
		Pods: map[string]*k8smeta.Pod{
			"fe-1": {UID: "fe-1", Namespace: "shop", Name: "frontend-abc", Node: "node-a", IP: "10.0.1.10",
				Labels: map[string]string{"app": "frontend", "pod-template-hash": "f1"}, OwnerKind: "ReplicaSet", OwnerName: "frontend-f1",
				TemplateHash: "f1", Workload: "Deployment/frontend", Phase: "Running", Created: now.Add(-time.Hour)},
			"pay-old": {UID: "pay-old", Namespace: "shop", Name: "payments-old", Node: "node-b", IP: "10.0.2.20",
				Labels: map[string]string{"app": "payments", "pod-template-hash": "p1"}, OwnerKind: "ReplicaSet", OwnerName: "payments-p1",
				TemplateHash: "p1", Workload: "Deployment/payments", Phase: "Running", Created: now.Add(-time.Hour),
				Containers: []k8smeta.Container{{Name: "app", Ports: []int32{8080}, Ready: true}}},
			"pay-new": {UID: "pay-new", Namespace: "shop", Name: "payments-new", Node: "node-b", IP: "10.0.2.21",
				Labels: map[string]string{"app": "payments", "pod-template-hash": "p2"}, OwnerKind: "ReplicaSet", OwnerName: "payments-p2",
				TemplateHash: "p2", Workload: "Deployment/payments", Phase: "Running", Created: now.Add(-5 * time.Minute),
				Conditions: map[string]time.Time{"PodScheduled": now.Add(-5 * time.Minute).Add(time.Second), "Ready": now.Add(-4 * time.Minute)},
				Containers: []k8smeta.Container{{Name: "app", Ports: []int32{8080}, Ready: true, Restarts: 4, StartedAt: now.Add(-290 * time.Second),
					LastReason: "OOMKilled", LastExitCode: 137, LastFinished: now.Add(-time.Minute),
					Probes: []k8smeta.Probe{{Kind: "readiness", Type: "http", Port: 8080, Period: 10, Delay: 30}}}}},
		},
		Services: []*k8smeta.Service{
			{Namespace: "shop", Name: "payments", ClusterIPs: []string{"10.96.0.50"}, Selector: map[string]string{"app": "payments"},
				Ports: []k8smeta.ServicePort{{Port: 80, TargetPort: "8080"}}},
		},
		Nodes: map[string]*k8smeta.Node{
			"node-a": {Name: "node-a", IPs: []string{"192.168.0.1"}, Zone: "zone-a"},
			"node-b": {Name: "node-b", IPs: []string{"192.168.0.2"}, Zone: "zone-b"},
		},
		ReplicaSets: map[string]*k8smeta.ReplicaSet{
			"shop/payments-p1": {Namespace: "shop", Name: "payments-p1", Deployment: "payments", Revision: "1", Hash: "p1"},
			"shop/payments-p2": {Namespace: "shop", Name: "payments-p2", Deployment: "payments", Revision: "2", Hash: "p2"},
		},
		Deployments: map[string]*k8smeta.Deployment{
			"shop/payments": {Namespace: "shop", Name: "payments", Selector: map[string]string{"app": "payments"}},
		},
	}
	meta.Index()

	from, to := now.Add(-time.Minute), now
	nodeA := &model.Snapshot{
		Node: "node-a", From: from, To: to,
		Pairs: []*model.Pair{
			// frontend -> payments Service (client side, before DNAT)
			{Client: "10.0.1.10", Server: "10.96.0.50", Port: 80, Side: "client", Owner: "pod:fe-1",
				RTT: hist(800, 100), Connect: hist(900, 600), Connects: 600, Closes: 600, LifetimeUs: 600 * 5000,
				BytesTx: 600 << 20, BytesRx: 1200 << 20},
		},
		Entities: map[string]*model.EntityStats{
			"pod:fe-1": {ID: "pod:fe-1", DNS: &model.DNSStats{Queries: 100, Responses: 100, NdotsWaste: 60,
				RCodes: map[string]uint64{"NXDOMAIN": 60, "NOERROR": 40}, Lat: hist(500, 100),
				Names: map[string]*model.DNSName{"api.stripe.com.shop.svc.cluster.local": {Count: 30, NXDomain: 30}}}},
		},
	}
	nodeB := &model.Snapshot{
		Node: "node-b", From: from, To: to,
		Pairs: []*model.Pair{
			// server side view at payments (after DNAT)
			{Client: "10.0.1.10", Server: "10.0.2.20", Port: 8080, Side: "server", Owner: "pod:pay-old", RTT: hist(800, 50), Connects: 300, BytesTx: 600 << 20, BytesRx: 300 << 20},
			{Client: "10.0.1.10", Server: "10.0.2.21", Port: 8080, Side: "server", Owner: "pod:pay-new", RTT: hist(800, 50), Connects: 300, BytesTx: 600 << 20, BytesRx: 300 << 20},
			// payments-new -> stripe, lots of refusals to a db
			{Client: "10.0.2.21", Server: "54.1.2.3", Port: 443, Side: "client", Owner: "pod:pay-new", RTT: hist(20000, 30), Connects: 10, BytesTx: 4096},
			{Client: "10.0.2.21", Server: "10.0.9.9", Port: 5432, Side: "client", Owner: "pod:pay-new", Refused: 25},
		},
		Entities: map[string]*model.EntityStats{
			"pod:pay-old": {ID: "pod:pay-old", HTTP: map[string]*model.HTTPEndpoint{
				"server POST /charge": {Role: "server", Method: "POST", Path: "/charge", Count: 1000, Status: map[string]uint64{"2xx": 1000}, Lat: hist(5000, 1000)}}},
			"pod:pay-new": {ID: "pod:pay-new", HTTP: map[string]*model.HTTPEndpoint{
				"server POST /charge": {Role: "server", Method: "POST", Path: "/charge", Count: 1000, Status: map[string]uint64{"2xx": 800, "5xx": 200}, Lat: hist(40000, 1000)}},
				Sched: &model.SchedStats{OnCPUNs: 1e9, OffNs: map[string]uint64{"runq": 300e6}, RunQ: hist(50000, 100),
					Culprits: map[string]uint64{"pod:pay-old": 200e6}}},
		},
		DNSNames: map[string]string{"54.1.2.3": "api.stripe.com"},
		Listens:  []model.Listen{{Entity: "pod:pay-new", Port: 6060, Addr: "0.0.0.0", Comm: "payments"}},
		Events: []model.Event{
			{Time: now.Add(-30 * time.Second), Entity: "pod:pay-new", Type: model.EvExecSession, Severity: model.SevWarn, Message: "interactive exec session: sh"},
		},
		Crashes: []model.CrashReport{{Entity: "pod:pay-new", Time: now.Add(-20 * time.Second), Reason: "OOM killed",
			Events: []model.Event{{Time: now.Add(-21 * time.Second), Message: "OOM killer selected pid 1"}}}},
		Startups: []model.Startup{{Entity: "pod:pay-new", FirstSeen: now.Add(-290 * time.Second), Events: []model.Event{
			{Time: now.Add(-289 * time.Second), Type: model.EvDNSFail, Severity: model.SevWarn, Message: "DNS A db.shop -> NXDOMAIN"},
			{Time: now.Add(-280 * time.Second), Type: model.EvListen, Message: "listening on 0.0.0.0:8080"},
		}}},
	}
	return []*model.Snapshot{nodeA, nodeB}, meta
}

func TestBuildResolvesServicesPodsAndExternal(t *testing.T) {
	snaps, meta := fixture(t)
	v := Build(snaps, meta, Options{})
	find := func(client, server string) *Edge {
		for _, e := range v.Edges {
			if e.Client.Display() == client && e.Server.Display() == server {
				return e
			}
		}
		return nil
	}
	if e := find("shop/frontend-abc", "svc/shop/payments"); e == nil || e.Stats.Connects != 600 {
		t.Fatalf("service edge missing or wrong: %+v", e)
	}
	e := find("shop/frontend-abc", "shop/payments-new")
	if e == nil || e.Side != "server" || !e.CrossZone {
		t.Fatalf("server side edge: %+v", e)
	}
	if e := find("shop/payments-new", "api.stripe.com"); e == nil || e.Server.Kind != KindExternal {
		t.Fatalf("external edge not resolved by DNS name: %+v", v.Edges)
	}
}

func TestDoctorFindings(t *testing.T) {
	snaps, meta := fixture(t)
	v := Build(snaps, meta, Options{})
	fs := Doctor(v, nil)
	want := map[string]bool{
		"crashed":               false,
		"ndots":                 false,
		"refused":               false,
		"connection churn":      false,
		"HTTP 5xx":              false,
		"waiting for CPU":       false,
		"interactive exec":      false,
		"undeclared listening":  false,
		"talk to the internet":  false,
		"restarting repeatedly": false,
	}
	for _, f := range fs {
		for k := range want {
			if strings.Contains(f.Title, k) {
				want[k] = true
			}
		}
	}
	for k, ok := range want {
		if !ok {
			var titles []string
			for _, f := range fs {
				titles = append(titles, f.Title)
			}
			t.Errorf("expected a finding containing %q; got:\n%s", k, strings.Join(titles, "\n"))
		}
	}
	if fs[0].Severity != SevCrit {
		t.Errorf("findings not sorted by severity: first is %v", fs[0].Severity)
	}
}

func TestCrossZoneCost(t *testing.T) {
	snaps, meta := fixture(t)
	v := Build(snaps, meta, Options{CostPerGB: 0.01})
	costs := CrossZoneCosts(v)
	if len(costs) == 0 {
		t.Fatal("expected cross-zone costs")
	}
	if costs[0].ClientZone != "zone-a" || costs[0].MonthlyUSD <= 0 {
		t.Fatalf("bad cost: %+v", costs[0])
	}
}

func TestRolloutComparison(t *testing.T) {
	snaps, meta := fixture(t)
	v := Build(snaps, meta, Options{})
	rep, err := Rollout(v, "shop", "payments")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Groups) != 2 || !rep.Groups[0].New || rep.Groups[0].Revision != "2" {
		t.Fatalf("bad groups: %+v", rep.Groups)
	}
	if rep.Healthy {
		t.Fatalf("new revision has 20%% 5xx and 8x latency but was reported healthy: %+v", rep.Rows)
	}
	bad := map[string]bool{}
	for _, r := range rep.Rows {
		if r.Bad {
			bad[r.Metric] = true
		}
	}
	for _, m := range []string{"HTTP 5xx rate", "HTTP p99 latency", "restarts"} {
		if !bad[m] {
			t.Errorf("expected %q to be flagged; rows: %+v", m, rep.Rows)
		}
	}
}

func TestNetworkPolicySuggestion(t *testing.T) {
	snaps, meta := fixture(t)
	v := Build(snaps, meta, Options{})
	y, err := SuggestNetworkPolicy(v, "shop", "Deployment/payments")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kind: NetworkPolicy", "app: payments", "app: frontend", "54.1.2.3/32", "api.stripe.com", "port: 8080"} {
		if !strings.Contains(y, want) {
			t.Errorf("policy missing %q:\n%s", want, y)
		}
	}
}

func TestStartupReport(t *testing.T) {
	snaps, meta := fixture(t)
	v := Build(snaps, meta, Options{})
	rep := Startup(v, meta.Pods["pay-new"])
	if !rep.Traced || len(rep.Timeline) < 4 {
		t.Fatalf("timeline too short: %+v", rep.Timeline)
	}
	var sawDNS bool
	for _, a := range rep.Advice {
		if strings.Contains(a, "DNS") {
			sawDNS = true
		}
	}
	if !sawDNS {
		t.Errorf("expected DNS advice, got %v", rep.Advice)
	}
}

func TestRegressions(t *testing.T) {
	snaps, meta := fixture(t)
	base := Build(snaps, meta, Options{})
	cur := Build(snaps, meta, Options{})
	for _, e := range cur.Edges {
		if e.Server.Kind == KindService {
			e.Stats.RTT = hist(20000, 100)
		}
	}
	fs := Regressions(cur, base)
	if len(fs) == 0 || !strings.Contains(strings.Join(fs[0].Detail, "\n"), "network RTT") {
		t.Fatalf("expected RTT regression, got %+v", fs)
	}
}
