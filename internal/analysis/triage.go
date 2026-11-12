package analysis

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/galq5/kubecapybara/internal/model"
)

// ---------------------------------------------------------------- doctor configuration

// Threshold is a tunable limit of a doctor rule.
type Threshold struct {
	Name    string
	Default float64
	Rule    string // the rule that uses it
	Help    string
}

// Thresholds lists every tunable limit with its default.
var Thresholds = []Threshold{
	{"http-5xx-ratio", 0.01, "http", "share of 5xx responses of a route above which it is reported"},
	{"http-slow-p99-ms", 1000, "http", "p99 latency of a served route above which it is reported"},
	{"db-error-ratio", 0.01, "db", "share of failed requests of a statement above which it is reported"},
	{"db-slow-p99-ms", 500, "db", "p99 latency of a statement above which it is reported"},
	{"dns-error-ratio", 0.02, "dns-errors", "share of failed lookups of a pod above which it is reported"},
	{"dns-slow-p99-ms", 100, "dns-slow", "p99 lookup latency of a pod above which it is reported"},
	{"cpu-runqueue-p99-ms", 20, "cpu-runqueue", "p99 wait for a CPU above which a pod is reported"},
	{"cpu-throttled-ratio", 0.25, "cpu-throttling", "share of throttled CFS periods above which a pod is reported"},
	{"memory-near-limit-ratio", 0.9, "memory", "memory usage as a share of the limit above which a pod is reported"},
	{"oom-risk-minutes", 60, "oom-risk", "report pods projected to reach their memory limit within this many minutes"},
	{"disk-slow-p99-ms", 50, "disk-latency", "p99 block I/O latency above which a pod is reported"},
	{"refused-min", 3, "refused", "refused connection attempts on a path in the window"},
	{"connect-timeouts-min", 2, "connect-timeouts", "timed-out connection attempts on a path in the window"},
	{"retransmits-min", 20, "retransmits", "retransmitted segments on a path in the window"},
	{"conntrack-full-ratio", 0.8, "conntrack", "conntrack table usage above which a node is reported"},
	{"cross-zone-usd", 1, "cross-zone", "monthly cross-zone cost above which it is reported"},
	{"rtp-loss-ratio", 0.01, "voip", "inbound RTP loss above which a pod is reported"},
	{"rtp-jitter-ms", 30, "voip", "p90 RTP jitter above which a pod is reported"},
}

// DoctorConfig tunes the doctor: rules to leave out and limits to override.
//
//	mute: [internet-egress, undeclared-ports]
//	thresholds:
//	  http-5xx-ratio: 0.05
//	  cpu-throttled-ratio: 0.5
type DoctorConfig struct {
	Mute       []string           `json:"mute,omitempty"`
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
}

func (c DoctorConfig) muted() map[string]bool {
	m := make(map[string]bool, len(c.Mute))
	for _, r := range c.Mute {
		m[r] = true
	}
	return m
}

// RuleInfo describes a doctor rule.
type RuleInfo struct {
	ID, Description string
}

// extraRules are rule names carried by findings of the rules above.
var extraRules = []string{"pool-idle", "connect-storm", "sip-failures", "sip-slow-setup", "sip-retransmissions", "rtp-loss", "rtp-jitter", "rtp-one-way"}

// Rules lists the doctor rules.
func Rules() []RuleInfo {
	out := make([]RuleInfo, 0, len(rules))
	for _, r := range rules {
		out = append(out, RuleInfo{r.id, r.desc})
	}
	return out
}

// Validate reports unknown rule and threshold names.
func (c DoctorConfig) Validate() error {
	known := map[string]bool{}
	for _, r := range rules {
		known[r.id] = true
	}
	for _, r := range extraRules {
		known[r] = true
	}
	for _, r := range c.Mute {
		if !known[r] {
			return fmt.Errorf("unknown doctor rule %q (see `kubectl capybara doctor --list-rules`)", r)
		}
	}
	for name := range c.Thresholds {
		found := false
		for _, t := range Thresholds {
			found = found || t.Name == name
		}
		if !found {
			return fmt.Errorf("unknown doctor threshold %q (see `kubectl capybara doctor --list-rules`)", name)
		}
	}
	return nil
}

// LoadDoctorConfig reads a doctor configuration from a YAML file.
func LoadDoctorConfig(path string) (DoctorConfig, error) {
	var c DoctorConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// th returns a threshold: the configured value or its default.
func (v *View) th(name string) float64 {
	if x, ok := v.Opts.Doctor.Thresholds[name]; ok {
		return x
	}
	for _, t := range Thresholds {
		if t.Name == name {
			return t.Default
		}
	}
	panic("analysis: unknown threshold " + name)
}

// ---------------------------------------------------------------- who a finding is about

// ref is something an evidence line names: a pod (with its workload), a
// workload, or a node.
type ref struct {
	group string      // workload key or "node/<name>"
	pod   *EntityView // nil unless a pod is named
}

// subjectIndex resolves the names findings use in their text.
type subjectIndex struct {
	v         *View
	pods      map[string]*EntityView // display name
	workloads map[string]bool        // workload keys with at least one observed pod
	svc       map[string]string      // "svc/ns/name" -> workload key of its backends
}

func newSubjectIndex(v *View) *subjectIndex {
	ix := &subjectIndex{v: v, pods: map[string]*EntityView{}, workloads: map[string]bool{}, svc: map[string]string{}}
	for _, e := range v.Entities {
		ix.pods[e.Endpoint.Display()] = e
		if e.Endpoint.Kind == KindPod {
			ix.workloads[e.Endpoint.WorkloadKey()] = true
		}
	}
	for _, s := range v.Meta.Services {
		// a Service stands for its backends when they are one workload
		wl := ""
		for _, p := range v.Meta.PodsOfService(s) {
			k := p.Namespace + "/" + p.Workload
			if wl != "" && wl != k {
				wl = ""
				break
			}
			wl = k
		}
		if wl != "" {
			ix.svc["svc/"+s.Namespace+"/"+s.Name] = wl
		}
	}
	return ix
}

func (ix *subjectIndex) entityRef(e *EntityView) ref {
	if e.Endpoint.Kind == KindPod {
		return ref{group: e.Endpoint.WorkloadKey(), pod: e}
	}
	if e.Endpoint.Node != "" {
		return ref{group: "node/" + e.Endpoint.Node}
	}
	return ref{group: e.Endpoint.Display()}
}

// token resolves one word of an evidence line.
func (ix *subjectIndex) token(w string) (ref, bool) {
	w = strings.Trim(w, ":,;()[]`")
	try := func(s string) (ref, bool) {
		if e, ok := ix.pods[s]; ok {
			return ix.entityRef(e), true
		}
		if ix.workloads[s] {
			return ref{group: s}, true
		}
		if wl, ok := ix.svc[s]; ok {
			return ref{group: wl}, true
		}
		if n, ok := strings.CutPrefix(s, "node/"); ok && ix.v.Nodes[n] != nil {
			return ref{group: "node/" + n}, true
		}
		return ref{}, false
	}
	if r, ok := try(w); ok {
		return r, true
	}
	// "ns/pod:8080", "svc/ns/name:5432/tcp", "node-a/eth0"
	if i := strings.IndexByte(w, ':'); i > 0 {
		if r, ok := try(w[:i]); ok {
			return r, true
		}
	}
	if i := strings.IndexByte(w, '/'); i > 0 && ix.v.Nodes[w[:i]] != nil {
		return ref{group: "node/" + w[:i]}, true
	}
	return ref{}, false
}

// lineRefs returns what a line names, in order, each group once. A node
// name counts when it follows the word "node" or starts the line.
func (ix *subjectIndex) lineRefs(line string) []ref {
	var out []ref
	seen := map[string]bool{}
	add := func(r ref) {
		if !seen[r.group] {
			seen[r.group] = true
			out = append(out, r)
		}
	}
	words := strings.Fields(line)
	for i, w := range words {
		if r, ok := ix.token(w); ok {
			add(r)
			continue
		}
		name := strings.Trim(w, ":,;()")
		if ix.v.Nodes[name] != nil && (i == 0 || strings.EqualFold(strings.Trim(words[i-1], "("), "node")) {
			add(ref{group: "node/" + name})
		}
	}
	return out
}

// findingRefs returns what a finding as a whole is about: its subjects,
// then what its title and evidence name.
func (ix *subjectIndex) findingRefs(f *Finding) []ref {
	var out []ref
	seen := map[string]bool{}
	add := func(rs ...ref) {
		for _, r := range rs {
			if !seen[r.group] {
				seen[r.group] = true
				out = append(out, r)
			}
		}
	}
	for _, id := range f.Subjects {
		if e := ix.v.Entities[id]; e != nil {
			add(ix.entityRef(e))
		}
	}
	add(ix.lineRefs(f.Title)...)
	for _, d := range f.Detail {
		add(ix.lineRefs(d)...)
	}
	return out
}

// fillHint replaces the <pod>, <deployment> and <workload> placeholders of a
// hint with the first pod and workload among refs, so the suggested command
// can be pasted. Placeholders without a match are left as they are.
func (ix *subjectIndex) fillHint(hint string, refs []ref) string {
	if !strings.Contains(hint, "<") {
		return hint
	}
	var pod, workload string
	for _, r := range refs {
		if pod == "" && r.pod != nil {
			pod = r.pod.Endpoint.Display()
		}
		if workload == "" && !strings.HasPrefix(r.group, "node/") && ix.workloads[r.group] {
			workload = r.group
		}
	}
	if pod == "" && workload != "" {
		// any pod of the workload will do
		var names []string
		for name, e := range ix.pods {
			if e.Endpoint.Kind == KindPod && e.Endpoint.WorkloadKey() == workload {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		if len(names) > 0 {
			pod = names[0]
		}
	}
	if pod != "" {
		hint = strings.ReplaceAll(hint, "<pod>", pod)
	}
	if workload != "" {
		hint = strings.ReplaceAll(hint, "<workload>", workload)
		// ns/Deployment/name -> ns/name for `rollout`
		if p := strings.SplitN(workload, "/", 3); len(p) == 3 && p[1] == "Deployment" {
			hint = strings.ReplaceAll(hint, "<deployment>", p[0]+"/"+p[2])
		}
	}
	return hint
}

// ---------------------------------------------------------------- problems

// Problem is everything the doctor found about one workload (or node): the
// findings that share a subject are usually one problem seen from several
// angles, and are easier to act on together.
type Problem struct {
	Key      string // workload key, "node/<name>", "" for the cluster, "advice"
	Title    string
	Kind     string // workload, node, cluster or advice
	Severity Severity
	Items    []ProblemItem
	// Pods are the pods of the workload the evidence names, most often
	// named first.
	Pods []string
	// Related are other problems the evidence refers to (a dependency, a
	// caller, the node, a noisy neighbour).
	Related []string
	// FirstSign is the earliest warning or critical event of the pods in
	// the window.
	FirstSign *EventView
}

// ProblemItem is one finding as far as it concerns a problem.
type ProblemItem struct {
	Finding Finding
	// Lines are the evidence lines about this problem (all of them when
	// the finding cannot be split).
	Lines []string
	Hint  string // with the names of this problem filled in
	// Headline is the one line that says most about the finding for this
	// problem: its title when that names the subject, else its first
	// evidence line.
	Headline string
	// Since is "new" when the baseline window did not have this finding
	// for this subject, "ongoing" when it did, "" when unknown.
	Since string
}

// advice reports findings that are recommendations rather than something
// being broken: they are listed apart from the problems.
func advice(f *Finding) bool { return f.Severity == SevInfo || f.Category == "cost" }

// causeRank orders the findings of a problem: what usually comes first in
// a chain of cause and effect is listed first.
var causeRank = map[string]int{
	"crash": 1, "restarts": 1, "oom-risk": 1, "memory": 1,
	"cpu-runqueue": 2, "cpu-throttling": 2, "disk-latency": 2, "files": 2, "accept-queue": 2, "zero-window": 2,
	"node-network": 2, "conntrack": 2, "control-plane": 2, "slow-node": 2,
	"dns-errors": 3, "dns-slow": 3, "refused": 3, "connect-timeouts": 3, "retransmits": 3, "mtu": 3, "drops": 3,
	"policy-denials": 3, "connect-errors": 3, "connect-storm": 3, "churn": 3, "service-balance": 3,
	"db": 4, "sip-failures": 4, "sip-slow-setup": 4, "sip-retransmissions": 4, "rtp-loss": 4, "rtp-jitter": 4, "rtp-one-way": 4,
	"http": 5, "slo-burn": 5, "outlier-replica": 6, "regression": 7,
}

func rank(rule string) int {
	if r, ok := causeRank[rule]; ok {
		return r
	}
	return 8
}

// rules that need data a baseline (lite) snapshot does not carry
var noBaseline = map[string]bool{"crash": true, "restarts": true, "exec-shell": true, "undeclared-ports": true, "oom-risk": true, "regression": true, "connect-storm": true}

// Triage groups findings into problems. baseFindings are the findings of
// the baseline view (may be nil): they tell new problems from ongoing ones.
func Triage(v *View, findings []Finding, base *View, baseFindings []Finding) []Problem {
	ix := newSubjectIndex(v)

	// which rule already fired for which subject in the baseline
	var before map[string]bool
	if base != nil && baseFindings != nil {
		before = map[string]bool{}
		bx := newSubjectIndex(base)
		for i := range baseFindings {
			f := &baseFindings[i]
			refs := bx.findingRefs(f)
			if len(refs) == 0 {
				before[f.Rule+"|"] = true
			}
			for _, r := range refs {
				before[f.Rule+"|"+r.group] = true
			}
		}
	}
	since := func(rule, group string) string {
		if before == nil || noBaseline[rule] {
			return ""
		}
		if before[rule+"|"+group] {
			return "ongoing"
		}
		return "new"
	}

	byKey := map[string]*Problem{}
	var order []*Problem
	get := func(key string) *Problem {
		p, ok := byKey[key]
		if !ok {
			p = &Problem{Key: key, Title: key, Kind: "workload"}
			switch {
			case key == "":
				p.Title, p.Kind = "cluster", "cluster"
			case key == "advice":
				p.Title, p.Kind = "recommendations", "advice"
			case strings.HasPrefix(key, "node/"):
				p.Kind = "node"
			}
			byKey[key] = p
			order = append(order, p)
		}
		return p
	}
	podCount := map[string]map[string]int{} // problem -> pod id -> mentions
	related := map[string]map[string]bool{}
	note := func(key string, refs []ref) {
		for i, r := range refs {
			if r.group == key {
				if r.pod != nil {
					if podCount[key] == nil {
						podCount[key] = map[string]int{}
					}
					podCount[key][r.pod.ID] += len(refs) - i // named first counts most
				}
				continue
			}
			if related[key] == nil {
				related[key] = map[string]bool{}
			}
			related[key][r.group] = true
		}
	}

	for i := range findings {
		f := findings[i]
		raw := f.rawHint
		if raw == "" {
			raw = f.Hint
		}
		if advice(&f) {
			p := get("advice")
			p.Items = append(p.Items, ProblemItem{Finding: f, Lines: f.Detail, Hint: f.Hint})
			continue
		}
		// split the evidence by the first thing each line names
		lines := map[string][]string{}
		lineRefs := map[string][]ref{}
		var keys []string
		put := func(key, line string, refs []ref) {
			if _, ok := lines[key]; !ok {
				keys = append(keys, key)
			}
			if line != "" {
				lines[key] = append(lines[key], line)
			} else if lines[key] == nil {
				lines[key] = []string{}
			}
			lineRefs[key] = append(lineRefs[key], refs...)
		}
		whole := ix.findingRefs(&f)
		fallback := ""
		if len(whole) > 0 {
			fallback = whole[0].group
		}
		for _, d := range f.Detail {
			refs := ix.lineRefs(d)
			key := fallback
			if len(refs) > 0 {
				key = refs[0].group
			}
			put(key, d, refs)
		}
		if len(f.Detail) == 0 {
			put(fallback, "", whole)
		}
		for _, key := range keys {
			p := get(key)
			p.Items = append(p.Items, ProblemItem{Finding: f, Lines: lines[key], Hint: raw, Since: since(f.Rule, key)})
			if f.Severity > p.Severity {
				p.Severity = f.Severity
			}
			note(key, lineRefs[key])
		}
	}

	for _, p := range order {
		sort.SliceStable(p.Items, func(i, j int) bool {
			a, b := &p.Items[i].Finding, &p.Items[j].Finding
			if p.Kind == "advice" {
				return a.Score > b.Score
			}
			if ra, rb := rank(a.Rule), rank(b.Rule); ra != rb {
				return ra < rb
			}
			return a.Severity > b.Severity
		})
		// pods by how prominently the evidence names them
		counts := podCount[p.Key]
		for id := range counts {
			p.Pods = append(p.Pods, id)
		}
		sort.Slice(p.Pods, func(i, j int) bool {
			if counts[p.Pods[i]] != counts[p.Pods[j]] {
				return counts[p.Pods[i]] > counts[p.Pods[j]]
			}
			return p.Pods[i] < p.Pods[j]
		})
		for k := range related[p.Key] {
			if byKey[k] != nil && k != "advice" {
				p.Related = append(p.Related, k)
			}
		}
		sort.Strings(p.Related)
		p.FirstSign = firstSign(v, p)
		// commands in hints name this workload and the pod its evidence
		// names most
		if p.Kind != "advice" {
			refs := []ref{{group: p.Key}}
			for _, id := range p.Pods {
				refs = append(refs, ref{group: p.Key, pod: v.Entities[id]})
			}
			for i := range p.Items {
				p.Items[i].Hint = ix.fillHint(p.Items[i].Hint, refs)
			}
		}
		for i := range p.Items {
			it := &p.Items[i]
			it.Headline = it.Finding.Title
			if p.Kind != "advice" && len(it.Lines) > 0 && len(ix.lineRefs(it.Finding.Title)) == 0 {
				it.Headline = it.Lines[0]
				if n := len(it.Lines) - 1; n > 0 {
					it.Headline += fmt.Sprintf(" (+%d more)", n)
				}
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if (a.Kind == "advice") != (b.Kind == "advice") {
			return b.Kind == "advice"
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if len(a.Items) != len(b.Items) {
			return len(a.Items) > len(b.Items)
		}
		return a.Key < b.Key
	})
	out := make([]Problem, len(order))
	for i, p := range order {
		out[i] = *p
	}
	return out
}

// firstSign returns the earliest warning or critical event of the pods of
// a workload problem.
func firstSign(v *View, p *Problem) *EventView {
	if p.Kind != "workload" {
		return nil
	}
	for i := range v.Events { // sorted by time
		e := &v.Events[i]
		if e.Severity != model.SevWarn && e.Severity != model.SevCrit {
			continue
		}
		if e.Endpoint.Kind == KindPod && e.Endpoint.WorkloadKey() == p.Key {
			return e
		}
	}
	return nil
}

// Summary names what a problem consists of, most likely cause first:
// "crash, CPU, database, HTTP".
func (p *Problem) Summary() string {
	var parts []string
	seen := map[string]bool{}
	for _, it := range p.Items {
		c := it.Finding.Category
		if !seen[c] {
			seen[c] = true
			parts = append(parts, c)
		}
	}
	return strings.Join(parts, ", ")
}
