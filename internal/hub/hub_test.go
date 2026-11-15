package hub_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/galq5/kubecapybara/internal/client"
	"github.com/galq5/kubecapybara/internal/hub"
	"github.com/galq5/kubecapybara/internal/model"
)

const token = "s3cret"

type fakeAgent struct {
	node      string
	snapshots atomic.Int64
}

func (a *fakeAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(hub.TokenHeader) != token {
		http.Error(w, "missing or invalid token", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/v1/snapshot":
		a.snapshots.Add(1)
		uid := "app-" + a.node
		_ = json.NewEncoder(w).Encode(&model.Snapshot{Node: a.node, Entities: map[string]*model.EntityStats{
			"pod:" + uid: {ID: "pod:" + uid, Sched: &model.SchedStats{OnCPUNs: 1e9}},
		}})
	case "/v1/profile":
		_ = json.NewEncoder(w).Encode(&model.Profile{Entity: r.URL.Query().Get("entity"), Samples: 42})
	default:
		http.NotFound(w, r)
	}
}

// startAgents serves fake agents on 127.0.0.1, 127.0.0.2... sharing one port,
// like a DaemonSet with hostNetwork.
func startAgents(t *testing.T, nodes ...string) (int, []*fakeAgent) {
	t.Helper()
	l0, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l0.Addr().(*net.TCPAddr).Port
	var agents []*fakeAgent
	for i, n := range nodes {
		l := l0
		if i > 0 {
			if l, err = net.Listen("tcp", net.JoinHostPort("127.0.0."+strconv.Itoa(i+1), strconv.Itoa(port))); err != nil {
				t.Skipf("cannot bind loopback alias: %v", err)
			}
		}
		a := &fakeAgent{node: n}
		srv := &httptest.Server{Listener: l, Config: &http.Server{Handler: a}}
		srv.Start()
		t.Cleanup(srv.Close)
		agents = append(agents, a)
	}
	return port, agents
}

func agentPod(i int, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-" + node, Namespace: "capybara", UID: types.UID("agent-" + node),
			Labels: map[string]string{"app.kubernetes.io/name": "capybara-agent"}, ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "x"}}},
		Spec:   corev1.PodSpec{NodeName: node, HostNetwork: true},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0." + strconv.Itoa(i+1)},
	}
}

func appPod(node, ns string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-" + node, Namespace: ns, UID: types.UID("app-" + node)},
		Spec:       corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "c"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.1.0." + node[len(node)-1:]},
	}
}

func startHub(t *testing.T) (*hub.Hub, *httptest.Server, []*fakeAgent) {
	t.Helper()
	return startHubWith(t, func(*hub.Config) {})
}

func startHubWith(t *testing.T, edit func(*hub.Config)) (*hub.Hub, *httptest.Server, []*fakeAgent) {
	t.Helper()
	port, agents := startAgents(t, "n1", "n2")
	objs := []runtime.Object{
		agentPod(0, "n1"), agentPod(1, "n2"), appPod("n1", "shop"), appPod("n2", "data"),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}},
	}
	cs := fake.NewSimpleClientset(objs...)
	cfg := hub.Config{AgentNamespace: "capybara", AgentSelector: "app.kubernetes.io/name=capybara-agent",
		AgentPort: port, Token: token, CacheTTL: time.Minute}
	edit(&cfg)
	h, err := hub.New(cfg, cs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return h, srv, agents
}

func TestHubEndToEnd(t *testing.T) {
	_, srv, agents := startHub(t)
	ctx := context.Background()
	src := &client.HubSource{URL: srv.URL, Token: token}

	to := time.Now()
	snaps, errs := src.Snapshots(ctx, to.Add(-time.Minute), to, false)
	if len(errs) > 0 || len(snaps) != 2 || snaps[0].Node != "n1" || snaps[1].Node != "n2" {
		t.Fatalf("snaps=%d errs=%v", len(snaps), errs)
	}
	meta, err := src.Meta(ctx)
	if err != nil || meta == nil || meta.Pods["app-n1"] == nil || meta.PodByIP("10.1.0.1") == nil {
		t.Fatalf("meta not delivered with the snapshots: %v %v", meta, err)
	}

	// a second client in the same refresh interval is served from the cache
	other := &client.HubSource{URL: srv.URL, Token: token}
	if s, _ := other.Snapshots(ctx, to.Add(-time.Minute), to, false); len(s) != 2 {
		t.Fatal("second client got no data")
	}
	for _, a := range agents {
		if n := a.snapshots.Load(); n != 1 {
			t.Fatalf("agent %s asked %d times, want 1 (cache)", a.node, n)
		}
	}

	// namespace scope: only the shop pod's entity, pruned metadata
	scoped := &client.HubSource{URL: srv.URL, Token: token, ScopeNamespace: "shop"}
	snaps, _ = scoped.Snapshots(ctx, to.Add(-time.Minute), to, false)
	n := 0
	for _, s := range snaps {
		n += len(s.Entities)
	}
	if n != 1 || snaps[0].Entities["pod:app-n1"] == nil {
		t.Fatalf("scoped entities: %d", n)
	}
	if m, _ := scoped.Meta(ctx); m == nil || m.Pods["app-n2"] != nil || m.Pods["app-n1"] == nil {
		t.Fatalf("scoped meta not pruned")
	}

	// forwarded profile
	p, err := src.Profile(ctx, "n2", "pod:app-n2", 1, 99)
	if err != nil || p.Samples != 42 || p.Entity != "pod:app-n2" {
		t.Fatalf("profile %+v %v", p, err)
	}
	if _, err := src.Profile(ctx, "nope", "pod:x", 1, 99); err == nil {
		t.Fatal("profile on unknown node should fail")
	}
}

// TestHubDefaultTop: the hub's --default-top applies to clients that do not
// set --top; an explicit 0 (and the controller) gets everything, and a
// client scoped by the default does not cache the pruned metadata.
func TestHubDefaultTop(t *testing.T) {
	_, srv, _ := startHubWith(t, func(c *hub.Config) { c.DefaultTop = 1 })
	ctx := context.Background()
	to := time.Now()
	count := func(src *client.HubSource) int {
		snaps, errs := src.Snapshots(ctx, to.Add(-time.Minute), to, false)
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		n := 0
		for _, s := range snaps {
			n += len(s.Entities)
		}
		return n
	}
	def := &client.HubSource{URL: srv.URL, Token: token}
	if n := count(def); n != 1 {
		t.Fatalf("default top: %d entities, want 1", n)
	}
	m1, _ := def.Meta(ctx)
	count(def)
	if m2, _ := def.Meta(ctx); m1 == m2 {
		t.Fatal("pruned metadata of a hub-scoped response was cached instead of refreshed")
	}
	all := &client.HubSource{URL: srv.URL, Token: token, TopSet: true}
	if n := count(all); n != 2 {
		t.Fatalf("explicit --top 0: %d entities, want 2", n)
	}
}

func TestHubHTTP(t *testing.T) {
	_, srv, _ := startHub(t)
	get := func(path string, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultTransport.RoundTrip(req) // no transparent gzip
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	if r := get("/v1/snapshots", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	if r := get("/healthz", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", r.StatusCode)
	}
	r := get("/v1/snapshots?top=x", map[string]string{hub.TokenHeader: token})
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad top: %d", r.StatusCode)
	}
	r = get("/v1/snapshots", map[string]string{hub.TokenHeader: token, "Accept-Encoding": "gzip"})
	if r.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("response not gzipped")
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body hub.SnapshotsResponse
	if err := json.NewDecoder(zr).Decode(&body); err != nil || len(body.Snapshots) != 2 || body.Agents != 2 {
		t.Fatalf("decode %v agents=%d snaps=%d", err, body.Agents, len(body.Snapshots))
	}
	r = get("/v1/meta", map[string]string{hub.TokenHeader: token})
	etag := r.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	if r2 := get("/v1/meta", map[string]string{hub.TokenHeader: token, "If-None-Match": etag}); r2.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", r2.StatusCode)
	}
	if r := get("/metrics", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("metrics: %d", r.StatusCode)
	}
}
