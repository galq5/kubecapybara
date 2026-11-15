package hub

import (
	"testing"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

func testMeta() *k8smeta.Meta {
	m := &k8smeta.Meta{
		Pods: map[string]*k8smeta.Pod{
			"a1": {UID: "a1", Namespace: "shop", Name: "api-1", IP: "10.0.0.1", Labels: map[string]string{"app": "api"}, OwnerKind: "ReplicaSet", OwnerName: "api-7d"},
			"a2": {UID: "a2", Namespace: "shop", Name: "api-2", IP: "10.0.0.2", Labels: map[string]string{"app": "api"}},
			"d1": {UID: "d1", Namespace: "data", Name: "pg-0", IP: "10.0.1.1", Labels: map[string]string{"app": "pg"}},
			"d2": {UID: "d2", Namespace: "data", Name: "pg-1", IP: "10.0.1.2", Labels: map[string]string{"app": "pg"}},
			"o1": {UID: "o1", Namespace: "other", Name: "x", IP: "10.0.2.1"},
		},
		Services: []*k8smeta.Service{
			{Namespace: "shop", Name: "api", ClusterIPs: []string{"10.96.0.1"}, Selector: map[string]string{"app": "api"}},
			{Namespace: "data", Name: "pg", ClusterIPs: []string{"10.96.0.2"}, Selector: map[string]string{"app": "pg"}},
			{Namespace: "other", Name: "x", ClusterIPs: []string{"10.96.0.3"}},
		},
		Nodes:       map[string]*k8smeta.Node{"n1": {Name: "n1"}, "n2": {Name: "n2"}},
		ReplicaSets: map[string]*k8smeta.ReplicaSet{"shop/api-7d": {Namespace: "shop", Name: "api-7d", Deployment: "api"}, "other/x-1": {Namespace: "other", Name: "x-1"}},
		Deployments: map[string]*k8smeta.Deployment{"shop/api": {Namespace: "shop", Name: "api"}, "other/x": {Namespace: "other", Name: "x"}},
	}
	m.Index()
	return m
}

func pair(c, s, side, owner string, bytes, errs uint64) *model.Pair {
	return &model.Pair{Client: c, Server: s, Port: 5432, Side: side, Owner: owner, BytesTx: bytes, Refused: errs}
}

func testSnaps() []*model.Snapshot {
	return []*model.Snapshot{
		{Node: "n1", Pairs: []*model.Pair{
			pair("10.0.0.1", "10.0.1.1", "client", "pod:a1", 100, 0), // shop -> data
			pair("10.0.2.1", "10.0.1.2", "client", "pod:o1", 900, 0), // other -> data
		}, Entities: map[string]*model.EntityStats{
			"pod:a1": {ID: "pod:a1", Sched: &model.SchedStats{OnCPUNs: 10}},
			"pod:o1": {ID: "pod:o1", Sched: &model.SchedStats{OnCPUNs: 1000}},
		}, Events: []model.Event{{Entity: "pod:a1"}, {Entity: "pod:o1"}},
			DNSNames: map[string]string{"10.0.1.1": "pg-0", "1.2.3.4": "unrelated"}},
		{Node: "n2", Pairs: []*model.Pair{
			pair("10.0.0.1", "10.0.1.1", "server", "pod:d1", 100, 0), // other side of shop -> data
			pair("10.0.2.1", "10.0.1.2", "server", "pod:d2", 900, 0),
			pair("10.0.2.1", "10.0.1.1", "server", "pod:d1", 1, 7), // small but failing
		}, Entities: map[string]*model.EntityStats{
			"pod:d1": {ID: "pod:d1", Sched: &model.SchedStats{OnCPUNs: 500}},
			"pod:d2": {ID: "pod:d2", Sched: &model.SchedStats{OnCPUNs: 5}},
		}},
	}
}

func count(snaps []*model.Snapshot) (pairs, ents int) {
	for _, s := range snaps {
		pairs += len(s.Pairs)
		ents += len(s.Entities)
	}
	return
}

func TestApplyNamespace(t *testing.T) {
	in := testSnaps()
	out := Apply(in, testMeta(), Scope{Namespace: "shop"})
	p, e := count(out)
	if p != 2 || e != 1 {
		t.Fatalf("want both sides of the shop flow and one entity, got %d pairs %d entities", p, e)
	}
	if len(out[0].Events) != 1 || out[0].Events[0].Entity != "pod:a1" {
		t.Fatalf("events %v", out[0].Events)
	}
	if len(out[0].DNSNames) != 1 || out[0].DNSNames["10.0.1.1"] != "pg-0" {
		t.Fatalf("dns names %v", out[0].DNSNames)
	}
	// input untouched (shared through the cache)
	if p, e := count(in); p != 5 || e != 4 || len(in[0].Events) != 2 {
		t.Fatal("input snapshots were modified")
	}
	if got := Apply(in, testMeta(), Scope{}); &got[0] != &in[0] {
		t.Fatal("inactive scope should return the input")
	}
}

func TestApplyTop(t *testing.T) {
	out := Apply(testSnaps(), testMeta(), Scope{Top: 1})
	flows := map[flowKey]int{}
	for _, s := range out {
		for _, p := range s.Pairs {
			flows[flowKey{client: p.Client, server: p.Server, port: p.Port}]++
		}
	}
	// busiest flow (both sides) + the failing one; the quiet healthy one goes
	if len(flows) != 2 || flows[flowKey{client: "10.0.2.1", server: "10.0.1.2", port: 5432}] != 2 || flows[flowKey{client: "10.0.2.1", server: "10.0.1.1", port: 5432}] != 1 {
		t.Fatalf("flows %v", flows)
	}
	_, e := count(out)
	if e != 1 || out[0].Entities["pod:o1"] == nil {
		t.Fatalf("want only the busiest entity, got %d", e)
	}
}

func TestPruneMeta(t *testing.T) {
	m := testMeta()
	snaps := Apply(testSnaps(), m, Scope{Namespace: "shop"})
	pm := PruneMeta(m, snaps, "shop")
	for _, uid := range []string{"a1", "a2", "d1", "d2"} { // ns pods, the peer, and the peer Service's backends
		if pm.Pods[uid] == nil {
			t.Errorf("pod %s missing", uid)
		}
	}
	if pm.Pods["o1"] != nil {
		t.Error("unrelated pod kept")
	}
	if pm.Service("shop", "api") == nil || pm.Service("other", "x") != nil {
		t.Errorf("services %v", pm.Services)
	}
	if pm.ReplicaSets["shop/api-7d"] == nil || pm.Deployments["shop/api"] == nil || pm.Deployments["other/x"] != nil {
		t.Error("workloads not pruned correctly")
	}
	if pm.PodByIP("10.0.1.1") == nil || len(pm.Nodes) != 2 {
		t.Error("pruned meta not indexed / nodes missing")
	}
}
