package cli

import "testing"

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
