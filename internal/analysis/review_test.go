package analysis

import (
	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"
	"testing"
	"time"
)

func TestLoopbackPodIsolation(t *testing.T) {
	m := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{
		"a": {UID: "a", Namespace: "ns", Name: "a", Node: "node"},
		"b": {UID: "b", Namespace: "ns", Name: "b", Node: "node"},
	}}
	m.Index()
	s := &model.Snapshot{Node: "node", From: time.Now().Add(-time.Minute), To: time.Now()}
	for _, id := range []string{"a", "b"} {
		for _, side := range []string{"client", "server"} {
			s.Pairs = append(s.Pairs, &model.Pair{Client: "127.0.0.1", Server: "127.0.0.1", Port: 8080, Side: side, Owner: "pod:" + id, Connects: 1})
		}
	}
	v := Build([]*model.Snapshot{s}, m, Options{})
	if len(v.Edges) != 2 {
		t.Fatalf("two isolated flows became %d edges", len(v.Edges))
	}
	for _, e := range v.Edges {
		if e.Client.ID != e.Server.ID || e.Stats.Connects != 1 || e.Side != "both" {
			t.Fatalf("incorrect isolated edge: %+v", e)
		}
	}
}

func TestNetworkPolicyReplicaTraffic(t *testing.T) {
	_, m := fixture(t)
	v := Build(nil, m, Options{})
	v.Edges = []*Edge{{Client: v.podEndpoint(m.Pods["pay-old"]), Server: v.podEndpoint(m.Pods["pay-new"]), Port: 8080, Stats: &model.Pair{Connects: 10}}}
	out, err := SuggestNetworkPolicy(v, "shop", "Deployment/payments")
	if err != nil {
		t.Fatal(err)
	}
	var p networkingv1.NetworkPolicy
	if err := yaml.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.Ingress) != 1 || len(p.Spec.Egress) != 1 {
		t.Fatalf("replica traffic denied:\n%s", out)
	}
	if p.Spec.Ingress[0].Ports[0].Port.IntVal != 8080 || p.Spec.Egress[0].Ports[0].Port.IntVal != 8080 {
		t.Fatal(out)
	}
}

func TestNetworkPolicyNamedPort(t *testing.T) {
	_, m := fixture(t)
	m.Services[0].Ports[0].TargetPort = "http"
	v := Build(nil, m, Options{})
	v.Edges = []*Edge{{Client: v.podEndpoint(m.Pods["fe-1"]), Server: v.IPEndpoint("10.96.0.50", "node-a"), Port: 80, Stats: &model.Pair{Connects: 10}}}
	out, err := SuggestNetworkPolicy(v, "shop", "Deployment/frontend")
	if err != nil {
		t.Fatal(err)
	}
	var p networkingv1.NetworkPolicy
	if err := yaml.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	port := p.Spec.Egress[0].Ports[0].Port
	if port.String() != "http" {
		t.Fatalf("named backend port became %s", port.String())
	}
}

func TestLoopbackOneSidedAndHostNetworking(t *testing.T) {
	m := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{
		"a": {UID: "a", Namespace: "ns", Name: "a", Node: "node"},
		"b": {UID: "b", Namespace: "ns", Name: "b", Node: "node", HostNetwork: true},
	}}
	m.Index()
	s := &model.Snapshot{Node: "node", Pairs: []*model.Pair{{Client: "127.0.0.1", Server: "127.0.0.1", Port: 8080, Side: "client", Owner: "pod:a", Connects: 1}}, Listens: []model.Listen{{Entity: "pod:b", Port: 8080}}}
	v := Build([]*model.Snapshot{s}, m, Options{})
	if v.Edges[0].Server.ID != "pod:a" {
		t.Fatalf("pod loopback resolved through a different namespace: %+v", v.Edges[0])
	}
	s.Pairs = []*model.Pair{
		{Client: "127.0.0.1", Server: "127.0.0.1", Port: 8080, Side: "client", Owner: "host:/", Connects: 1},
		{Client: "127.0.0.1", Server: "127.0.0.1", Port: 8080, Side: "server", Owner: "pod:b", Connects: 1},
	}
	v = Build([]*model.Snapshot{s}, m, Options{})
	if len(v.Edges) != 1 || v.Edges[0].Side != "both" || v.Edges[0].Server.ID != "pod:b" {
		t.Fatal("hostNetwork connection split")
	}
}
