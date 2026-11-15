package hub

import (
	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
	"testing"
)

func TestScopeIsolatesPodLoopback(t *testing.T) {
	m := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{"a": {UID: "a", Namespace: "shop"}, "b": {UID: "b", Namespace: "other"}}}
	m.Index()
	s := &model.Snapshot{Node: "node"}
	for _, id := range []string{"a", "b"} {
		s.Pairs = append(s.Pairs, &model.Pair{Client: "127.0.0.1", Server: "127.0.0.1", Port: 8080, Owner: "pod:" + id, Side: "client"})
	}
	out := Apply([]*model.Snapshot{s}, m, Scope{Namespace: "shop"})
	if len(out[0].Pairs) != 1 || out[0].Pairs[0].Owner != "pod:a" {
		t.Fatal("loopback traffic leaked across namespace scope")
	}
}
