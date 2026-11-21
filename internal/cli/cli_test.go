package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
)

func TestSplitNSAndWorkload(t *testing.T) {
	cases := []struct {
		in, ns, rest, workload string
	}{
		{"payments", "def", "payments", "Deployment/payments"},
		{"deploy/payments", "def", "deploy/payments", "Deployment/payments"},
		{"shop/payments", "shop", "payments", "Deployment/payments"},
		{"sts/postgres", "def", "sts/postgres", "StatefulSet/postgres"},
		{"statefulset/postgres", "def", "statefulset/postgres", "StatefulSet/postgres"},
		{"ds/agent", "def", "ds/agent", "DaemonSet/agent"},
		{"shop/sts/postgres", "shop", "sts/postgres", "StatefulSet/postgres"},
	}
	for _, c := range cases {
		ns, rest := splitNS("def", c.in)
		if ns != c.ns || rest != c.rest {
			t.Errorf("splitNS(%q) = %q %q, want %q %q", c.in, ns, rest, c.ns, c.rest)
		}
		w, err := parseWorkload(rest)
		if err != nil || w != c.workload {
			t.Errorf("parseWorkload(%q) = %q %v, want %q", rest, w, err, c.workload)
		}
	}
	if _, err := parseWorkload("bogus/x"); err == nil {
		t.Error("unknown kind must fail")
	}
}

// Shell completion, help and version must work without a cluster.
func TestOfflineCommandsNeedNoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for _, args := range [][]string{
		{"completion", "bash"}, {"completion", "zsh"}, {"help", "doctor"}, {"version"}, {"__complete", "do"},
	} {
		root := NewRoot("test")
		root.SetArgs(args)
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		if err := root.Execute(); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	root := NewRoot("test")
	root.SetArgs([]string{"doctor"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err == nil {
		t.Error("doctor without a cluster should fail")
	}
}

func TestIncidentRejectsAggregateBundle(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"--from-file", file, "incident"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "requires live time buckets") {
		t.Fatalf("unexpected replay result: %v", err)
	}
}

// A NetworkPolicy built from the hub's busiest flows only would block the
// others: netpol asks the hub for every flow, whatever its default top.
func TestNetpolAsksHubForEveryFlow(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	var tops []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/snapshots" {
			tops = append(tops, r.URL.Query().Get("top"))
			_, _ = io.WriteString(w, `{"snapshots":[{"node":"n"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	run := func(args ...string) error {
		root := NewRoot("test")
		root.SetArgs(append([]string{"--hub", srv.URL, "--no-k8s"}, args...))
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		return root.Execute()
	}
	_ = run("netpol", "shop/deploy/payments") // no such pods: only the request matters
	if len(tops) != 1 || tops[0] != "0" {
		t.Fatalf("netpol asked the hub for top %q", tops)
	}
	if err := run("--top", "5", "netpol", "shop/deploy/payments"); err == nil || !strings.Contains(err.Error(), "--top") {
		t.Fatalf("netpol from the top 5 flows: %v", err)
	}
}

// With --agent, a metadata reload that fails (a slow LIST of a big
// cluster) keeps the names it had; only a cluster that never answered is
// given up on.
func TestAgentModeKeepsMetadataOnReloadFailure(t *testing.T) {
	var calls int
	results := []*k8smeta.Meta{{}, nil, {}}
	km := &kubeMeta{load: func(context.Context) (*k8smeta.Meta, error) {
		m := results[calls]
		calls++
		if m == nil {
			return nil, errors.New("context deadline exceeded")
		}
		return m, nil
	}}
	ctx := context.Background()
	first := km.get(ctx)
	if first == nil || km.get(ctx) != first || calls != 1 {
		t.Fatalf("first load: %v, %d calls", first, calls)
	}
	km.loadedAt = km.loadedAt.Add(-time.Minute)
	if km.get(ctx) != first || km.unavailable() {
		t.Fatal("a failed reload dropped the metadata")
	}
	km.loadedAt = km.loadedAt.Add(-time.Minute)
	if m := km.get(ctx); m == first || m == nil || calls != 3 {
		t.Fatalf("reload after the failure: %v, %d calls", m, calls)
	}

	none := &kubeMeta{load: func(context.Context) (*k8smeta.Meta, error) { calls++; return nil, errors.New("no cluster") }}
	calls = 0
	if none.get(ctx) != nil || !none.unavailable() {
		t.Fatal("first load failed: metadata unavailable")
	}
	none.loadedAt = none.loadedAt.Add(-time.Hour)
	if none.get(ctx) != nil || calls != 1 {
		t.Fatalf("a cluster that never answered is tried again (%d calls)", calls)
	}
}
