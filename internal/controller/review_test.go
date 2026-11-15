package controller

import (
	"context"
	"errors"
	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/client"
	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"testing"
	"time"
)

func TestDistinctSLOFindings(t *testing.T) {
	c, _, cp, _ := newTest(t)
	fs := analysis.SLOFindings([]analysis.SLOStatus{
		{SLO: analysis.SLO{Name: "checkout", Workload: "shop/Deployment/checkout"}, Requests: 100, AvailBurn: 20},
		{SLO: analysis.SLO{Name: "payments", Workload: "shop/Deployment/payments"}, Requests: 100, AvailBurn: 20},
	})
	for i := 0; i < 2; i++ {
		if err := c.Reconcile(context.Background(), fs, testView()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(list(t, c)); n != 2 {
		t.Fatalf("two failing SLOs became %d findings", n)
	}
	if len(cp.events()) != 2 {
		t.Fatalf("expected one notification per SLO: %v", cp.events())
	}
}

type partialSource struct {
	client.Source
	failed bool
}

func (s partialSource) Snapshots(_ context.Context, from, to time.Time, _ bool) ([]*model.Snapshot, []error) {
	var errs []error
	if s.failed {
		errs = []error{errors.New("agent unreachable")}
	}
	return []*model.Snapshot{{Node: "healthy", From: from, To: to}}, errs
}
func (partialSource) Meta(context.Context) (*k8smeta.Meta, error) { return nil, nil }
func TestPartialFailurePreservesFindings(t *testing.T) {
	c, _, cp, now := newTest(t)
	f := analysis.Finding{Rule: "cpu-throttling", Severity: analysis.SevCrit, Title: "bad", Subjects: []string{"pod:uid-1"}}
	if err := c.Reconcile(context.Background(), []analysis.Finding{f}, testView()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(11 * time.Minute)
	c.src = partialSource{failed: true}
	c.cfg.Window = time.Minute
	if err := c.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	items := list(t, c)
	state, _, _ := unstructured.NestedString(items[0].Object, "status", "state")
	if state != "Active" || len(cp.events()) != 1 {
		t.Fatalf("partial failure resolved alert: %s, %v", state, cp.events())
	}
	c.src = partialSource{}
	if err := c.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	items = list(t, c)
	state, _, _ = unstructured.NestedString(items[0].Object, "status", "state")
	if state != "Resolved" || len(cp.events()) != 2 {
		t.Fatalf("complete healthy data did not resolve alert: %s", state)
	}
}

func TestControllerFindingOwnership(t *testing.T) {
	first, dyn, _, now := newTest(t)
	cfg := first.cfg
	cfg.Instance = "another-installation"
	second := New(cfg, nil, dyn, nil, first.log)
	second.now = first.now
	ctx := context.Background()
	f := analysis.Finding{Rule: "test", Severity: analysis.SevCrit}
	if err := first.Reconcile(ctx, []analysis.Finding{f}, testView()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(11 * time.Minute)
	if err := second.Reconcile(ctx, nil, testView()); err != nil {
		t.Fatal(err)
	}
	state, _, _ := unstructured.NestedString(list(t, first)[0].Object, "status", "state")
	if state != stateActive {
		t.Fatalf("second controller changed first controller's finding to %s", state)
	}
	if err := second.Reconcile(ctx, []analysis.Finding{f}, testView()); err != nil {
		t.Fatal(err)
	}
	if count := len(list(t, first)); count != 2 {
		t.Fatalf("expected an independent finding for each controller, got %d", count)
	}
}
