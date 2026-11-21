package analysis

import (
	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"
	"strings"
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

func TestNetworkPolicyRejectsOverbroadSelector(t *testing.T) {
	for _, labels := range []map[string]string{nil, {"app": "shared"}} {
		meta := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{
			"a": {UID: "a", Namespace: "ns", Name: "a", Workload: "Pod/a", Labels: labels},
			"b": {UID: "b", Namespace: "ns", Name: "b", Workload: "Pod/b", Labels: labels},
		}}
		if policy, err := SuggestNetworkPolicy(Build(nil, meta, Options{}), "ns", "Pod/a"); err == nil {
			t.Fatalf("generated an overbroad policy:\n%s", policy)
		}
	}
}

func TestNetworkPolicyIgnoresLoopback(t *testing.T) {
	_, m := fixture(t)
	p := m.Pods["pay-old"]
	s := &model.Snapshot{Node: p.Node, From: time.Now().Add(-time.Minute), To: time.Now()}
	for _, side := range []string{"client", "server"} {
		s.Pairs = append(s.Pairs, &model.Pair{Client: "127.0.0.1", Server: "127.0.0.1", Port: 15000, Side: side, Owner: "pod:" + p.UID, Connects: 5})
	}
	v := Build([]*model.Snapshot{s}, m, Options{})
	out, err := SuggestNetworkPolicy(v, "shop", "Deployment/payments")
	if err != nil {
		t.Fatal(err)
	}
	var np networkingv1.NetworkPolicy
	if err := yaml.Unmarshal([]byte(out), &np); err != nil {
		t.Fatal(err)
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 {
		t.Fatalf("loopback traffic became policy rules:\n%s", out)
	}
}

// Each socket retransmits its own segments: a connection observed on both
// ends must keep the server's retransmits (lost responses, MTU black holes).
func TestEdgeKeepsServerSideRetransmits(t *testing.T) {
	m := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{
		"c": {UID: "c", Namespace: "ns", Name: "client", Node: "n1", IP: "10.0.0.1"},
		"s": {UID: "s", Namespace: "ns", Name: "server", Node: "n2", IP: "10.0.0.2"},
	}}
	m.Index()
	now := time.Now()
	from := now.Add(-time.Minute)
	snaps := []*model.Snapshot{
		{Node: "n1", From: from, To: now, Pairs: []*model.Pair{{Client: "10.0.0.1", Server: "10.0.0.2", Port: 8080, Side: "client",
			Owner: "pod:c", Connects: 10, RTT: hist(300000, 30), Retrans: 1}}},
		{Node: "n2", From: from, To: now, Pairs: []*model.Pair{{Client: "10.0.0.1", Server: "10.0.0.2", Port: 8080, Side: "server",
			Owner: "pod:s", Connects: 10, Retrans: 40, RetransLarge: 39, MTUReduced: 1}}},
	}
	v := Build(snaps, m, Options{})
	if len(v.Edges) != 1 {
		t.Fatalf("%d edges", len(v.Edges))
	}
	if s := v.Edges[0].Stats; v.Edges[0].Side != "both" || s.Retrans != 41 || s.RetransLarge != 39 || s.MTUReduced != 1 {
		t.Fatalf("server side counters lost: %+v", s)
	}
	if len(ruleMTU(v)) != 1 || len(ruleRetrans(v)) != 1 {
		t.Fatal("lossy return path not reported")
	}
}

// A node address belongs to the listener of that node, not of the node the
// connection was observed on (control-plane nodes often run no agent).
func TestNodeAddressResolvedOnItsOwnNode(t *testing.T) {
	m := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{
		"c": {UID: "c", Namespace: "ns", Name: "client", Node: "worker", IP: "10.0.0.1"},
	}, Nodes: map[string]*k8smeta.Node{
		"worker": {Name: "worker", IPs: []string{"192.168.0.1"}},
		"cp":     {Name: "cp", IPs: []string{"192.168.0.9"}},
	}}
	m.Index()
	now := time.Now()
	s := &model.Snapshot{Node: "worker", From: now.Add(-time.Minute), To: now,
		Pairs: []*model.Pair{
			{Client: "10.0.0.1", Server: "192.168.0.9", Port: 10250, Side: "client", Owner: "pod:c", Connects: 3},
			{Client: "10.0.0.1", Server: "192.168.0.1", Port: 10250, Side: "client", Owner: "pod:c", Connects: 3},
		},
		Listens: []model.Listen{{Entity: "host:/system.slice/kubelet.service", Port: 10250}}}
	v := Build([]*model.Snapshot{s}, m, Options{})
	servers := map[string]Endpoint{}
	for _, e := range v.Edges {
		servers[e.Server.Display()] = e.Server
	}
	if _, ok := servers["node/cp"]; !ok {
		t.Fatalf("control-plane kubelet attributed to another node: %v", servers)
	}
	if k, ok := servers["kubelet@worker"]; !ok || k.IP != "192.168.0.1" {
		t.Fatalf("local kubelet: %+v", servers)
	}
}

// Observed egress the policy cannot express must not be dropped silently:
// the policy would block it. The API server and host processes are known
// addresses; other Services without a selector make the generation fail.
func TestNetworkPolicyEgressToAPIServerAndHosts(t *testing.T) {
	_, m := fixture(t)
	m.Services = append(m.Services,
		&k8smeta.Service{Namespace: "default", Name: "kubernetes", ClusterIPs: []string{"10.96.0.1"},
			Ports: []k8smeta.ServicePort{{Name: "https", Port: 443, TargetPort: "6443"}}},
		&k8smeta.Service{Namespace: "shop", Name: "legacy-db", ClusterIPs: []string{"10.96.0.77"},
			Ports: []k8smeta.ServicePort{{Port: 5432, TargetPort: "5432"}}})
	m.APIServerIPs = []string{"192.168.0.10", "192.168.0.11"}
	m.Index()
	v := Build(nil, m, Options{})
	pay := v.podEndpoint(m.Pods["pay-old"])
	kubelet := Endpoint{Kind: KindHost, ID: "host:/system.slice/kubelet.service@node-a", Name: "kubelet", Node: "node-a", IP: "192.168.0.1"}
	v.Edges = []*Edge{
		{Client: pay, Server: v.IPEndpoint("10.96.0.1", "node-b"), Port: 443, Stats: &model.Pair{Connects: 1}},
		{Client: pay, Server: kubelet, Port: 10250, Stats: &model.Pair{Connects: 1}},
	}
	out, err := SuggestNetworkPolicy(v, "shop", "Deployment/payments")
	if err != nil {
		t.Fatal(err)
	}
	var p networkingv1.NetworkPolicy
	if err := yaml.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, r := range p.Spec.Egress {
		for _, to := range r.To {
			for _, port := range r.Ports {
				if to.IPBlock != nil {
					allowed[to.IPBlock.CIDR+":"+port.Port.String()] = true
				}
			}
		}
	}
	for _, want := range []string{"192.168.0.10/32:6443", "192.168.0.11/32:6443", "192.168.0.1/32:10250"} {
		if !allowed[want] {
			t.Errorf("egress to %s not allowed:\n%s", want, out)
		}
	}

	v.Edges = append(v.Edges, &Edge{Client: pay, Server: v.IPEndpoint("10.96.0.77", "node-b"), Port: 5432, Stats: &model.Pair{Connects: 1}})
	if out, err := SuggestNetworkPolicy(v, "shop", "Deployment/payments"); err == nil {
		t.Fatalf("policy blocking observed traffic to a selector-less Service:\n%s", out)
	}
}

// The names shown for failing DNS lookups are the ones failing most often.
func TestDNSErrorsNameTheWorstNames(t *testing.T) {
	m := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{"a": {UID: "a", Namespace: "ns", Name: "a", Node: "n"}}}
	m.Index()
	now := time.Now()
	d := &model.DNSStats{Queries: 200, Timeouts: 3, RCodes: map[string]uint64{"SERVFAIL": 100}, Names: map[string]*model.DNSName{
		"a.example": {Count: 1, Errors: 1}, "b.example": {Count: 1, Errors: 1}, "c.example": {Count: 1, Errors: 1},
		"zz.broken.example": {Count: 100, Errors: 97, Timeouts: 3},
	}}
	s := &model.Snapshot{Node: "n", From: now.Add(-time.Minute), To: now, Entities: map[string]*model.EntityStats{"pod:a": {ID: "pod:a", DNS: d}}}
	fs := ruleDNSErrors(Build([]*model.Snapshot{s}, m, Options{}))
	if len(fs) != 1 || len(fs[0].Detail) != 1 || !strings.Contains(fs[0].Detail[0], "zz.broken.example(100)") {
		t.Fatalf("worst failing name missing: %+v", fs)
	}
}
