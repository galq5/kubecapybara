package controller

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"

	"github.com/galq5/kubecapybara/internal/analysis"
)

type capture struct {
	mu sync.Mutex
	ns []Notification
}

func (c *capture) Notify(_ context.Context, n Notification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ns = append(c.ns, n)
	return nil
}

func (c *capture) events() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, n := range c.ns {
		out = append(out, n.Event+":"+n.Name)
	}
	return out
}

func newTest(t *testing.T) (*Controller, *dynfake.FakeDynamicClient, *capture, *time.Time) {
	t.Helper()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{GVR: "CapyFindingList"})
	cp := &capture{}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := New(Config{Namespace: "capybara", Cluster: "prod", MinSeverity: analysis.SevWarn}, nil, dyn, cp,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = func() time.Time { return now }
	return c, dyn, cp, &now
}

func testView() *analysis.View {
	return &analysis.View{Entities: map[string]*analysis.EntityView{
		"pod:uid-1": {ID: "pod:uid-1", Endpoint: analysis.Endpoint{Kind: analysis.KindPod, Namespace: "shop", Name: "api-7d9-x", Workload: "api"}},
	}}
}

func list(t *testing.T, c *Controller) []unstructured.Unstructured {
	t.Helper()
	l, err := c.dyn.Resource(GVR).Namespace(metav1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return l.Items
}

func TestReconcileLifecycle(t *testing.T) {
	c, _, cp, now := newTest(t)
	ctx := context.Background()
	v := testView()
	f := analysis.Finding{Rule: "cpu-throttling", Severity: analysis.SevCrit, Category: "cpu", Title: "api is throttled",
		Detail: []string{"62% of periods throttled"}, Subjects: []string{"pod:uid-1"}}
	info := analysis.Finding{Rule: "info-rule", Severity: analysis.SevInfo, Title: "ignored"}

	// 1. new finding: created in the pod's namespace, notified once.
	if err := c.Reconcile(ctx, []analysis.Finding{f, f, info}, v); err != nil {
		t.Fatal(err)
	}
	items := list(t, c)
	if len(items) != 1 {
		t.Fatalf("want 1 object, got %d", len(items))
	}
	obj := items[0]
	if obj.GetNamespace() != "shop" || !strings.HasPrefix(obj.GetName(), "cpu-throttling-") {
		t.Fatalf("unexpected identity %s/%s", obj.GetNamespace(), obj.GetName())
	}
	if l := obj.GetLabels(); l[labelManaged] != "true" || l[labelRule] != "cpu-throttling" || l[labelSeverity] != "crit" {
		t.Fatalf("labels: %v", l)
	}
	if s, _, _ := unstructured.NestedString(obj.Object, "spec", "subject"); s != "shop/api" {
		t.Fatalf("subject %q", s)
	}
	name := obj.GetName()
	if got := cp.events(); len(got) != 1 || got[0] != "firing:"+name {
		t.Fatalf("notifications %v", got)
	}

	// 2. seen again: occurrences increase, no new notification.
	*now = now.Add(time.Minute)
	if err := c.Reconcile(ctx, []analysis.Finding{f}, v); err != nil {
		t.Fatal(err)
	}
	obj = list(t, c)[0]
	if occ, _, _ := unstructured.NestedInt64(obj.Object, "status", "occurrences"); occ != 2 {
		t.Fatalf("occurrences %d", occ)
	}
	if len(cp.events()) != 1 {
		t.Fatalf("unexpected notification %v", cp.events())
	}

	// 3. gone but within ResolveAfter: stays active.
	*now = now.Add(5 * time.Minute)
	_ = c.Reconcile(ctx, nil, v)
	if st, _, _ := unstructured.NestedString(list(t, c)[0].Object, "status", "state"); st != stateActive {
		t.Fatalf("state %s", st)
	}

	// 4. gone for longer than ResolveAfter: resolved and notified.
	*now = now.Add(6 * time.Minute)
	_ = c.Reconcile(ctx, nil, v)
	obj = list(t, c)[0]
	if st, _, _ := unstructured.NestedString(obj.Object, "status", "state"); st != stateResolved {
		t.Fatalf("state %s", st)
	}
	if got := cp.events(); len(got) != 2 || got[1] != "resolved:"+name {
		t.Fatalf("notifications %v", got)
	}
	if cp.ns[1].Title != f.Title || cp.ns[1].Severity != "CRIT" {
		t.Fatalf("resolved notification lost fields: %+v", cp.ns[1])
	}

	// 5. fires again: reactivated and notified.
	*now = now.Add(time.Minute)
	_ = c.Reconcile(ctx, []analysis.Finding{f}, v)
	obj = list(t, c)[0]
	if st, _, _ := unstructured.NestedString(obj.Object, "status", "state"); st != stateActive {
		t.Fatalf("state %s", st)
	}
	if _, found, _ := unstructured.NestedString(obj.Object, "status", "resolvedAt"); found {
		t.Fatal("resolvedAt not cleared")
	}
	if got := cp.events(); len(got) != 3 || got[2] != "firing:"+name {
		t.Fatalf("notifications %v", got)
	}

	// 6. resolve, then delete after KeepResolved.
	*now = now.Add(11 * time.Minute)
	_ = c.Reconcile(ctx, nil, v)
	*now = now.Add(61 * time.Minute)
	_ = c.Reconcile(ctx, nil, v)
	if n := len(list(t, c)); n != 0 {
		t.Fatalf("want deletion, %d objects left", n)
	}
}

func TestClusterFindingNamespace(t *testing.T) {
	c, _, _, _ := newTest(t)
	f := analysis.Finding{Rule: "Node/Network Drops!!", Severity: analysis.SevWarn, Title: "drops"}
	if err := c.Reconcile(context.Background(), []analysis.Finding{f}, testView()); err != nil {
		t.Fatal(err)
	}
	items := list(t, c)
	if len(items) != 1 || items[0].GetNamespace() != "capybara" || !strings.HasPrefix(items[0].GetName(), "node-network-drops-") {
		t.Fatalf("unexpected %v", items)
	}
}

func TestIdentityLongRule(t *testing.T) {
	c, _, _, _ := newTest(t)
	_, name, _ := c.identity(analysis.Finding{Rule: strings.Repeat("a", 39) + "-bbbb"}, testView())
	if strings.Contains(name, "--") || len(name) > 63 {
		t.Fatalf("bad name %q", name)
	}
}

func TestWebhook(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m)
	}))
	defer srv.Close()
	n := Notification{Event: "firing", Namespace: "shop", Name: "x-1", Severity: "CRIT", Title: "api is throttled",
		Details: []string{"a", "b", "c", "d", "e", "f", "g"}, Hint: "raise the limit"}
	if err := (&Webhook{URL: srv.URL}).Notify(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if err := (&Webhook{URL: srv.URL, Slack: true}).Notify(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if got[0]["title"] != "api is throttled" {
		t.Fatalf("json body %v", got[0])
	}
	text, _ := got[1]["text"].(string)
	if !strings.Contains(text, ":red_circle:") || !strings.Contains(text, "… 2 more") || !strings.Contains(text, "raise the limit") {
		t.Fatalf("slack text %q", text)
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer fail.Close()
	if err := (&Webhook{URL: fail.URL}).Notify(context.Background(), n); err == nil {
		t.Fatal("want error on 500")
	}
}
