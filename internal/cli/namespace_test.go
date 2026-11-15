package cli

import (
	"context"
	"github.com/galq5/kubecapybara/internal/client"
	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
	"testing"
	"time"
)

type namespaceSource struct{ client.Source }

func (namespaceSource) Meta(context.Context) (*k8smeta.Meta, error) {
	m := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{"a": {UID: "a", Namespace: "shop", Name: "a"}, "b": {UID: "b", Namespace: "other", Name: "b", Containers: []k8smeta.Container{{StateReason: "CrashLoopBackOff"}}}}}
	m.Index()
	return m, nil
}
func (namespaceSource) Snapshots(_ context.Context, from, to time.Time, _ bool) ([]*model.Snapshot, []error) {
	return []*model.Snapshot{{Node: "node", From: from, To: to, Entities: map[string]*model.EntityStats{
		"pod:a": {ID: "pod:a", Res: &model.Resources{Periods: 100, Throttled: 90}},
		"pod:b": {ID: "pod:b", Res: &model.Resources{Periods: 100, Throttled: 90}},
	}}}, nil
}
func TestNamespaceScopesLiveAndBaseline(t *testing.T) {
	o := &options{src: namespaceSource{}, namespace: "shop", window: time.Minute, baseline: time.Hour}
	r, err := o.load(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.View.Entities) != 1 || r.View.Entities["pod:a"] == nil || r.Base == nil || len(r.Base.Entities) != 1 {
		t.Fatal("namespace scope not applied to live and baseline data")
	}
	for _, f := range r.Findings {
		for _, id := range f.Subjects {
			if id == "pod:b" {
				t.Fatal("unrelated pod finding retained")
			}
		}
	}
}
