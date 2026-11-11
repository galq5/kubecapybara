package cli

import (
	"io"
	"path/filepath"
	"testing"
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
