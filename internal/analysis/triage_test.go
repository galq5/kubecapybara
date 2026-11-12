package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/demo"
)

func demoViews(t *testing.T, opts Options) (*View, *View) {
	t.Helper()
	c := demo.New(time.Now())
	return Build(c.Snapshots, c.Meta, opts), Build(c.Baseline, c.Meta, opts)
}

func problem(ps []Problem, key string) *Problem {
	for i := range ps {
		if ps[i].Key == key {
			return &ps[i]
		}
	}
	return nil
}

// The findings about one workload are one problem: the demo's bad payments
// replica shows up in a dozen rules and must come out as a single block
// that leads with the crash and points at the database it depends on.
func TestTriageGroupsFindingsPerWorkload(t *testing.T) {
	v, base := demoViews(t, Options{})
	findings := Doctor(v, base)
	ps := Triage(v, findings, base, Doctor(base, nil))
	if len(ps) >= len(findings)/2 {
		t.Fatalf("%d findings became %d problems: nothing was grouped", len(findings), len(ps))
	}
	pay := problem(ps, "shop/Deployment/payments")
	if pay == nil || &ps[0] != pay {
		t.Fatalf("payments should be the first problem: %v", ps[0].Key)
	}
	if pay.Severity != SevCrit || len(pay.Items) < 10 {
		t.Fatalf("payments: %s with %d findings", pay.Severity, len(pay.Items))
	}
	if r := pay.Items[0].Finding.Rule; r != "crash" {
		t.Errorf("the crash is the likely cause and comes first, got %s", r)
	}
	if last := pay.Items[len(pay.Items)-1].Finding.Rule; rank(last) < rank("http") {
		t.Errorf("symptoms come last, got %s", last)
	}
	if len(pay.Pods) == 0 || pay.Pods[0] != "pod:pay2" {
		t.Errorf("the evidence names the bad replica most: %v", pay.Pods)
	}
	if !strings.Contains(strings.Join(pay.Related, " "), "data/StatefulSet/postgres") {
		t.Errorf("payments' evidence points at postgres: %v", pay.Related)
	}
	if pay.FirstSign == nil || !strings.Contains(pay.FirstSign.Message, "OOM killer") {
		t.Errorf("first sign: %+v", pay.FirstSign)
	}
	// evidence of other workloads stays out of this problem
	for _, it := range pay.Items {
		for _, l := range it.Lines {
			if strings.HasPrefix(l, "shop/frontend") || strings.HasPrefix(l, "data/postgres-0:") {
				t.Errorf("%s: line of another workload in the payments problem: %s", it.Finding.Rule, l)
			}
		}
	}
	// nodes get their own problems, recommendations come last and apart
	if problem(ps, "node/node-b") == nil {
		t.Error("the full conntrack table of node-b should be a node problem")
	}
	adv := &ps[len(ps)-1]
	if adv.Kind != "advice" || len(adv.Items) == 0 {
		t.Fatalf("recommendations should be the last block: %+v", adv.Key)
	}
	for _, it := range adv.Items {
		if it.Finding.Severity != SevInfo && it.Finding.Category != "cost" {
			t.Errorf("%s (%s) is not a recommendation", it.Finding.Rule, it.Finding.Severity)
		}
	}
	for i := range ps[:len(ps)-1] {
		for _, it := range ps[i].Items {
			if it.Finding.Severity == SevInfo || it.Finding.Category == "cost" {
				t.Errorf("%s: recommendation %s among the problems", ps[i].Key, it.Finding.Rule)
			}
		}
	}
}

// A finding the baseline hour already had is ongoing, the rest is new.
func TestTriageMarksNewAndOngoing(t *testing.T) {
	v, base := demoViews(t, Options{})
	ps := Triage(v, Doctor(v, base), base, Doctor(base, nil))
	since := map[string]string{}
	for _, p := range ps {
		for _, it := range p.Items {
			since[p.Key+" "+it.Finding.Rule] = it.Since
		}
	}
	for key, want := range map[string]string{
		"shop/Deployment/payments cpu-throttling": "new",     // only the live window has the noisy neighbour
		"shop/Deployment/frontend dns-ndots":      "ongoing", // the search path waste is always there
		"node/node-b conntrack":                   "ongoing",
		"shop/Deployment/payments crash":          "", // the baseline carries no crash reports
	} {
		if got, ok := since[key]; !ok || got != want {
			t.Errorf("%s: since %q (found %v), want %q", key, got, ok, want)
		}
	}
	// without a baseline nothing is claimed
	for _, p := range Triage(v, Doctor(v, nil), nil, nil) {
		for _, it := range p.Items {
			if it.Since != "" {
				t.Fatalf("%s %s marked %q without a baseline", p.Key, it.Finding.Rule, it.Since)
			}
		}
	}
}

// Commands in hints name the real pod and workload.
func TestHintsNameTheSubject(t *testing.T) {
	v, base := demoViews(t, Options{})
	findings := Doctor(v, base)
	for _, f := range findings {
		if strings.Contains(f.Hint, "<pod>") || strings.Contains(f.Hint, "<deployment>") || strings.Contains(f.Hint, "<workload>") {
			t.Errorf("%s: placeholder left in the hint: %s", f.Rule, f.Hint)
		}
	}
	pay := problem(Triage(v, findings, base, nil), "shop/Deployment/payments")
	var hints []string
	for _, it := range pay.Items {
		hints = append(hints, it.Hint)
	}
	all := strings.Join(hints, "\n")
	for _, want := range []string{
		"kubectl capybara pod shop/payments-7f9c5d6b4-fghij", // the bad replica, not the first by name
		"kubectl capybara rollout shop/payments",
		"kubectl capybara why-crash shop/payments-7f9c5d6b4-fghij",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("no hint with %q in:\n%s", want, all)
		}
	}
}

// A failing call seen on both ends is reported once, on the server, with
// the callers it fails for.
func TestHTTPErrorsReportedOncePerCall(t *testing.T) {
	v, _ := demoViews(t, Options{})
	var lines []string
	for _, f := range ruleHTTP(v) {
		if f.Title == "HTTP 5xx errors" {
			lines = f.Detail
		}
	}
	all := strings.Join(lines, "\n")
	if n := strings.Count(all, "/charge"); n != 1 {
		t.Errorf("POST /charge fails on the payments server and is seen by three frontend clients: want 1 line, got %d:\n%s", n, all)
	}
	for _, want := range []string{
		"shop/Deployment/payments server POST /charge", "callers affected: shop/Deployment/frontend",
		"worst replica shop/payments-7f9c5d6b4-fghij", "shop/Deployment/frontend server POST /checkout",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if len(lines) != 2 {
		t.Errorf("want one line per failing route and workload (2), got %d:\n%s", len(lines), all)
	}
}

func TestDoctorConfigMutesAndTunes(t *testing.T) {
	v, base := demoViews(t, Options{})
	has := func(fs []Finding, rule string) bool {
		for _, f := range fs {
			if f.Rule == rule {
				return true
			}
		}
		return false
	}
	plain := Doctor(v, base)
	for _, r := range []string{"internet-egress", "cpu-throttling", "rtp-loss", "regression"} {
		if !has(plain, r) {
			t.Fatalf("the demo should trigger %s", r)
		}
	}
	cfg := DoctorConfig{Mute: []string{"internet-egress", "rtp-loss", "regression"}, Thresholds: map[string]float64{"cpu-throttled-ratio": 0.6}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	tv, tbase := demoViews(t, Options{Doctor: cfg})
	tuned := Doctor(tv, tbase)
	for _, r := range []string{"internet-egress", "rtp-loss", "regression", "cpu-throttling"} {
		if has(tuned, r) {
			t.Errorf("%s should be gone (muted, or 40%% throttling under a 60%% threshold)", r)
		}
	}
	if !has(tuned, "rtp-one-way") || !has(tuned, "crash") {
		t.Error("muting one rule must not silence the others")
	}

	// every threshold a rule asks for is registered, and bad names are refused
	for _, th := range Thresholds {
		_ = v.th(th.Name)
	}
	if err := (DoctorConfig{Mute: []string{"no-such-rule"}}).Validate(); err == nil {
		t.Error("unknown rule accepted")
	}
	if err := (DoctorConfig{Thresholds: map[string]float64{"no-such": 1}}).Validate(); err == nil {
		t.Error("unknown threshold accepted")
	}
	path := filepath.Join(t.TempDir(), "doctor.yaml")
	if err := os.WriteFile(path, []byte("mute: [undeclared-ports]\nthresholds:\n  http-5xx-ratio: 0.05\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadDoctorConfig(path)
	if err != nil || len(c.Mute) != 1 || c.Thresholds["http-5xx-ratio"] != 0.05 {
		t.Fatalf("LoadDoctorConfig: %+v %v", c, err)
	}
}

// Drops by packet filtering are the policy-denials finding, not a second
// one under drops.
func TestPolicyDropsReportedOnce(t *testing.T) {
	v, base := demoViews(t, Options{})
	var drops, denials int
	for _, f := range Doctor(v, base) {
		switch f.Rule {
		case "drops":
			drops++
		case "policy-denials":
			denials++
		}
	}
	if drops != 0 || denials != 1 {
		t.Errorf("NETFILTER_DROP: %d drops findings and %d policy-denials, want 0 and 1", drops, denials)
	}
}
