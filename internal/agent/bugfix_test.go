package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/cgroups"
	"github.com/galq5/kubecapybara/internal/dnsparse"
	"github.com/galq5/kubecapybara/internal/model"
)

func testDNSCollector(t *testing.T) *dnsCollector {
	t.Helper()
	a := &Agent{resolver: cgroups.NewResolver(t.TempDir()), rec: NewRecorder(), clock: newClock(), status: map[string]string{}}
	return &dnsCollector{a: a, cur: NewWindow(a.clock.wall(0), a.clock.wall(0)), clients: map[dnsKey]dnsPending{}, servers: map[dnsKey]dnsPending{}}
}

// A query stamped after the collector read the clock (or delivered out of
// order) must not wrap around into an instant timeout or a huge latency.
func TestDNSTimestampsDoNotWrap(t *testing.T) {
	c := testDNSCollector(t)
	future := monoNow() + 1e9
	c.clients[dnsKey{"10.0.0.1", 1234, 7}] = dnsPending{ts: future, entity: "pod:a", name: "db.example.com", qtype: "A"}
	c.servers[dnsKey{"10.0.0.1", 1234, 7}] = dnsPending{ts: future, entity: "pod:dns", name: "db.example.com", qtype: "A"}
	w := NewWindow(c.a.clock.wall(0), c.a.clock.wall(0))
	c.Collect(w)
	if len(c.clients) != 1 || len(c.servers) != 1 {
		t.Fatalf("pending queries dropped: %d clients, %d servers", len(c.clients), len(c.servers))
	}
	for id, e := range w.Entities {
		if (e.DNS != nil && e.DNS.Timeouts > 0) || (e.DNSServer != nil && e.DNSServer.Timeouts > 0) {
			t.Fatalf("%s: a query newer than the clock reading timed out", id)
		}
	}

	// the answer carries an older timestamp than the query
	ev := &bpf.DnsDnsEvent{Ts: future - 500, Dport: 1234}
	ev.Daddr[10], ev.Daddr[11], ev.Daddr[12], ev.Daddr[15] = 0xff, 0xff, 10, 1 // ::ffff:10.0.0.1
	c.handle(ev, &dnsparse.Message{ID: 7, Response: true, RCode: "NOERROR", Name: "db.example.com"})
	c.Collect(w)
	var d *model.DNSStats
	for _, e := range w.Entities {
		if e.DNS != nil && e.DNS.Responses > 0 {
			d = e.DNS
		}
	}
	if d == nil {
		t.Fatal("response not matched")
	}
	if d.Lat.Sum != 0 || d.Lat.Count != 1 {
		t.Fatalf("latency of an out-of-order answer: sum %dus, count %d", d.Lat.Sum, d.Lat.Count)
	}
}

// The Prometheus text format knows only \\, \" and \n in label values.
func TestMetricLabelEscaping(t *testing.T) {
	got := labels("path", "a\tb\"c\\d\ne\xffé\x00", "empty", "")
	want := `path="a` + "\t" + `b\"c\\d\ne` + "�" + "é\x00" + `"`
	if got != want {
		t.Fatalf("labels:\n got %q\nwant %q", got, want)
	}
	if !utf8.ValidString(got) {
		t.Fatal("label is not valid UTF-8")
	}
}

// The agent and model.EntityStats.Merge must fold statements over the
// cardinality limit into the same "(other)" entry.
func TestDBOverflowKeyMatchesMerge(t *testing.T) {
	agentSide := &model.EntityStats{DB: map[string]*model.DBQuery{}}
	for i := 0; i < model.MaxDBQueries-1; i++ {
		q := "select " + strings.Repeat("x", i+1)
		agentSide.DB[dbKey(protoPostgres, q)] = &model.DBQuery{Proto: "postgres", Query: q, Count: 1}
	}
	agentSide.DB[dbKey(protoPostgres, "(other)")] = &model.DBQuery{Proto: "postgres", Query: "(other)", Count: 1}
	merged := &model.EntityStats{}
	merged.Merge(agentSide)
	merged.Merge(&model.EntityStats{DB: map[string]*model.DBQuery{
		dbKey(protoPostgres, "select new"): {Proto: "postgres", Query: "select new", Count: 5},
	}})
	var others int
	var count uint64
	for _, q := range merged.DB {
		if q.Query == "(other)" {
			others++
			count += q.Count
		}
	}
	if others != 1 || count != 6 {
		t.Fatalf("%d (other) entries with %d requests, want 1 with 6", others, count)
	}
}

func TestTruncationKeepsValidUTF8(t *testing.T) {
	sql := NormalizeSQL("select * from t where name = x" + strings.Repeat("é", 80))
	if !utf8.ValidString(sql) || !strings.HasSuffix(sql, "…") {
		t.Fatalf("NormalizeSQL cut a character in half: %q", sql)
	}
	path := NormalizePath("/files/" + strings.Repeat("ż", 60))
	if !utf8.ValidString(path) || !strings.HasSuffix(path, "…") || len(path) > 80+len("…") {
		t.Fatalf("NormalizePath cut a character in half: %q", path)
	}
	if got := truncate("short", 80); got != "short" {
		t.Fatalf("truncate changed a short string: %q", got)
	}
}

// The OOM tracepoint runs in the task that triggered the killer: the kill
// must be attributed to the victim's pod, not to the trigger's.
func TestOOMAttributedToVictim(t *testing.T) {
	root, proc := t.TempDir(), t.TempDir()
	const (
		victim  = "/kubepods/pod11111111-2222-3333-4444-555555555555/c1"
		trigger = "/kubepods/pod99999999-2222-3333-4444-555555555555/c1"
	)
	for _, d := range []string{victim, trigger} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(proc, "4242"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "4242", "cgroup"), []byte("0::"+victim+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := cgroups.NewResolver(root)
	c := &procCollector{a: &Agent{cfg: Config{ProcRoot: proc}, resolver: r}}
	var triggerID uint64
	for _, id := range r.IDsForEntity("pod:99999999-2222-3333-4444-555555555555") {
		triggerID = id
	}
	if triggerID == 0 {
		t.Fatal("trigger cgroup not found")
	}
	if got := c.oomVictim(triggerID, 4242).Entity; got != "pod:11111111-2222-3333-4444-555555555555" {
		t.Fatalf("OOM attributed to %s, want the victim's pod", got)
	}
	// the victim was reaped before the event was read: the trigger's cgroup
	if got := c.oomVictim(triggerID, 777).Entity; got != "pod:99999999-2222-3333-4444-555555555555" {
		t.Fatalf("fallback: %s", got)
	}
}

func TestRoundLatency(t *testing.T) {
	for in, want := range map[time.Duration]string{
		40 * time.Microsecond:               "40µs",
		20123456 * time.Nanosecond:          "20ms",
		3204567 * time.Microsecond:          "3.2s",
		1234567 * time.Nanosecond:           "1.235ms",
		32*time.Second + 4*time.Millisecond: "32s",
	} {
		if got := roundLatency(in).String(); got != want {
			t.Errorf("roundLatency(%s) = %s, want %s", in, got, want)
		}
	}
}
