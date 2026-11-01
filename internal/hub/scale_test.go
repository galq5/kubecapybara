package hub

import (
	"fmt"
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// TestScale1000Nodes checks that scoping a 1000-node / 30k-pod data set
// stays well under the refresh interval (run with -run Scale -v).
func TestScale1000Nodes(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	m := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{}, Nodes: map[string]*k8smeta.Node{},
		ReplicaSets: map[string]*k8smeta.ReplicaSet{}, Deployments: map[string]*k8smeta.Deployment{}}
	var snaps []*model.Snapshot
	for n := 0; n < 1000; n++ {
		node := fmt.Sprintf("n%d", n)
		m.Nodes[node] = &k8smeta.Node{Name: node}
		s := &model.Snapshot{Node: node, Entities: map[string]*model.EntityStats{}}
		for p := 0; p < 30; p++ {
			i := n*30 + p
			ns := fmt.Sprintf("ns%d", i%300)
			uid := fmt.Sprintf("u%d", i)
			ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)
			m.Pods[uid] = &k8smeta.Pod{UID: uid, Namespace: ns, Name: uid, IP: ip, Labels: map[string]string{"app": fmt.Sprintf("a%d", i%3000)}}
			s.Entities["pod:"+uid] = &model.EntityStats{ID: "pod:" + uid, Sched: &model.SchedStats{OnCPUNs: uint64(i)}}
		}
		snaps = append(snaps, s)
	}
	for i := 0; i < 3000; i++ {
		m.Services = append(m.Services, &k8smeta.Service{Namespace: fmt.Sprintf("ns%d", i%300), Name: fmt.Sprintf("s%d", i),
			ClusterIPs: []string{fmt.Sprintf("10.96.%d.%d", i>>8, i&255)}, Selector: map[string]string{"app": fmt.Sprintf("a%d", i)}})
	}
	m.Index()
	for n, s := range snaps { // 100 connections per node to random peers
		for c := 0; c < 100; c++ {
			a, b := (n*30+c%30)%30000, (n*7919+c*104729)%30000
			s.Pairs = append(s.Pairs, &model.Pair{Client: m.Pods[fmt.Sprintf("u%d", a)].IP, Server: m.Pods[fmt.Sprintf("u%d", b)].IP,
				Port: 80, Side: "client", Owner: fmt.Sprintf("pod:u%d", a), BytesTx: uint64(c)})
		}
	}
	for _, sc := range []Scope{{Namespace: "ns7"}, {Top: 200}, {Namespace: "ns7", Top: 50}} {
		start := time.Now()
		out := Apply(snaps, m, sc)
		applied := time.Since(start)
		pm := PruneMeta(m, out, sc.Namespace)
		p, e := count(out)
		t.Logf("%+v: apply %v, prune %v -> %d pairs, %d entities, %d/%d pods in meta", sc, applied.Round(time.Millisecond),
			(time.Since(start) - applied).Round(time.Millisecond), p, e, len(pm.Pods), len(m.Pods))
		if time.Since(start) > 3*time.Second {
			t.Errorf("scope %+v too slow: %v", sc, time.Since(start))
		}
	}
}
