package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	return &dnsCollector{a: a, cur: NewWindow(a.clock.wall(0), a.clock.wall(0)), clients: newDNSTable(), servers: newDNSTable()}
}

// A query stamped after the collector read the clock (or delivered out of
// order) must not wrap around into an instant timeout or a huge latency.
func TestDNSTimestampsDoNotWrap(t *testing.T) {
	c := testDNSCollector(t)
	future := monoNow() + 1e9
	c.clients.put(dnsKey{client: "10.0.0.1", server: "::", clientPort: 1234, id: 7}, dnsPending{ts: future, entity: "pod:a", name: "db.example.com", qtype: "A"})
	c.servers.put(dnsKey{client: "10.0.0.1", server: "::", clientPort: 1234, id: 7}, dnsPending{ts: future, entity: "pod:dns", name: "db.example.com", qtype: "A"})
	w := NewWindow(c.a.clock.wall(0), c.a.clock.wall(0))
	c.Collect(w)
	if len(c.clients.byKey) != 1 || len(c.servers.byKey) != 1 {
		t.Fatalf("pending queries dropped: %d clients, %d servers", len(c.clients.byKey), len(c.servers.byKey))
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

func TestDNSMatchesParallelResolvers(t *testing.T) {
	c := testDNSCollector(t)
	query := &bpf.DnsDnsEvent{Ts: 1000, Cgroup: 1, Sport: 45678, Dport: 53, Egress: 1,
		Saddr: [16]uint8{15: 1}, Daddr: [16]uint8{15: 2}}
	msg := &dnsparse.Message{ID: 7, Name: "a.example", Type: "A"}
	c.handle(query, msg)
	query.Daddr[15] = 3
	c.handle(query, msg)
	for _, addr := range []uint8{2, 3} {
		c.handle(&bpf.DnsDnsEvent{Ts: 5000, Cgroup: 1, Sport: 53, Dport: 45678,
			Saddr: [16]uint8{15: addr}, Daddr: query.Saddr},
			&dnsparse.Message{ID: 7, Name: msg.Name, Type: msg.Type, Response: true, RCode: "NOERROR"})
	}
	if got := c.cur.Entities["cg:1"].DNS.Responses; got != 2 {
		t.Fatalf("two valid DNS replies became %d", got)
	}
}

func TestDNSMatchesReplyFromServiceIP(t *testing.T) {
	c := testDNSCollector(t)
	// host network client: the query leaves DNATed to a CoreDNS pod, the
	// reply arrives translated back to the Service IP
	query := &bpf.DnsDnsEvent{Ts: 1000, Cgroup: 1, Sport: 45678, Dport: 53, Egress: 1,
		Saddr: [16]uint8{15: 1}, Daddr: [16]uint8{15: 2}}
	c.handle(query, &dnsparse.Message{ID: 7, Name: "a.example", Type: "A"})
	c.handle(&bpf.DnsDnsEvent{Ts: 5000, Cgroup: 1, Sport: 53, Dport: 45678,
		Saddr: [16]uint8{15: 10}, Daddr: query.Saddr},
		&dnsparse.Message{ID: 7, Name: "a.example", Type: "A", Response: true, RCode: "NOERROR"})
	if got := c.cur.Entities["cg:1"].DNS.Responses; got != 1 {
		t.Fatalf("reply from the Service IP not matched: %d responses", got)
	}
	if len(c.clients.byKey) != 0 || len(c.clients.byLoose) != 0 {
		t.Fatalf("matched query left pending: %v %v", c.clients.byKey, c.clients.byLoose)
	}
}

func TestAdjacentWindowBoundaries(t *testing.T) {
	start := time.Now().Truncate(time.Hour)
	for _, interval := range []time.Duration{time.Second, time.Minute} {
		fineKeep := time.Hour
		if interval == time.Minute {
			fineKeep = 0
		}
		store := NewStore(fineKeep, time.Hour)
		for i := 0; i < 3; i++ {
			from := start.Add(time.Duration(i) * interval)
			w := NewWindow(from, from.Add(interval))
			w.Entity("pod:a").DNS = &model.DNSStats{Queries: 1}
			store.Add(w)
		}
		for i := 0; i < 2; i++ {
			from := start.Add(time.Duration(i) * interval)
			w := store.Query(from, from.Add(interval))
			if got := w.Entities["pod:a"].DNS.Queries; got != 1 {
				t.Fatalf("%s window %d includes %d queries, want 1", interval, i, got)
			}
		}
	}
}

type metricsWriterFunc func([]byte) (int, error)

func (f metricsWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestMetricsWritesOutsideCollectionLock(t *testing.T) {
	m := newMetrics(nil)
	m.observe(NewWindow(time.Now(), time.Now()))
	wrote := false
	m.write(metricsWriterFunc(func(p []byte) (int, error) {
		wrote = true
		if !m.mu.TryLock() {
			t.Fatal("metrics response holds the collection lock")
		}
		m.mu.Unlock()
		return len(p), nil
	}))
	if !wrote {
		t.Fatal("no metrics were written")
	}
}

// The agent and model.EntityStats.Merge must fold routes over the
// cardinality limit into the same "(other)" entry.
func TestHTTPOverflowKeyMatchesMerge(t *testing.T) {
	a := &Agent{resolver: cgroups.NewResolver(t.TempDir()), rec: NewRecorder(), clock: newClock()}
	c := &httpCollector{a: a, cur: NewWindow(time.Time{}, time.Time{}), lastWarn: map[string]time.Time{}}
	for i := 0; i <= model.MaxHTTPEndpoints; i++ {
		ev := &bpf.HttpHttpEvent{Proto: protoHTTP, Role: 2, Cgroup: 1}
		for j, b := range []byte("GET /page-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + " HTTP/1.1\r\n") {
			ev.Req[j] = int8(b)
		}
		for j, b := range []byte("HTTP/1.1 200 OK") {
			ev.Resp[j] = int8(b)
		}
		c.handle(ev)
	}
	e := c.cur.Entities["cg:1"]
	merged := &model.EntityStats{}
	merged.Merge(e)
	merged.Merge(&model.EntityStats{HTTP: map[string]*model.HTTPEndpoint{
		"server GET /new": {Role: "server", Method: "GET", Path: "/new", Count: 5},
	}})
	var others int
	var other, total uint64
	for _, ep := range merged.HTTP {
		total += ep.Count
		if ep.Path == "(other)" {
			others++
			other += ep.Count
		}
	}
	if others != 1 || other < 6 || total != model.MaxHTTPEndpoints+1+5 {
		t.Fatalf("%d (other) routes with %d of %d requests, want 1 with at least 6", others, other, total)
	}
}

// Cgroups of containers that are gone are forgotten after a while; live
// ones and recently seen ones are kept.
func TestSeenCgroupsArePruned(t *testing.T) {
	root := t.TempDir()
	const live = "/kubepods/pod11111111-2222-3333-4444-555555555555/c1"
	if err := os.MkdirAll(filepath.Join(root, live), 0o755); err != nil {
		t.Fatal(err)
	}
	a := &Agent{resolver: cgroups.NewResolver(root), seen: map[string]time.Time{}}
	now := time.Now()
	a.seen[live] = now.Add(-time.Hour)
	a.seen["/kubepods/pod99999999-2222-3333-4444-555555555555/gone"] = now.Add(-time.Hour)
	a.seen["/kubepods/pod99999999-2222-3333-4444-555555555555/just-exited"] = now.Add(-time.Minute)
	a.pruneSeen(now)
	if len(a.seen) != 2 || a.seen[live].IsZero() || a.seen["/kubepods/pod99999999-2222-3333-4444-555555555555/just-exited"].IsZero() {
		t.Fatalf("seen after pruning: %v", a.seen)
	}
}

// Stopping a pod is not a crash, whatever its containers' main processes
// do on SIGTERM; a container that dies on its own meanwhile still is.
func TestPodDeletionIsNotACrash(t *testing.T) {
	root := t.TempDir()
	cg := func(p string) uint64 {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
		var st syscall.Stat_t
		if err := syscall.Stat(filepath.Join(root, p), &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	const pod = "/kubepods/pod11111111-2222-3333-4444-555555555555"
	app, side, pause := cg(pod+"/app"), cg(pod+"/sidecar"), cg(pod+"/pause")
	other, otherPause := cg("/kubepods/pod99999999-2222-3333-4444-555555555555/app"), cg("/kubepods/pod99999999-2222-3333-4444-555555555555/pause")
	host := cg("/system.slice/containerd.service")
	comm := func(s string) (out [16]int8) {
		for i := 0; i < len(s); i++ {
			out[i] = int8(s[i])
		}
		return
	}
	a := &Agent{resolver: cgroups.NewResolver(root), rec: NewRecorder(), clock: newClock(), seen: map[string]time.Time{}}
	c := &procCollector{a: a, terminating: map[string]time.Time{}}
	ts := monoNow()
	signal := func(code int32, from uint64, fromPid uint32, fromComm string, to uint64, pid uint32) {
		ts += 1e8
		c.handle(&bpf.ProcCapyProcEvent{Ts: ts, Type: procEvSignal, Cgroup: from, Pid: fromPid, Comm: comm(fromComm),
			Code: code, TargetPid: pid, TargetNsPid: 1, TargetCgroup: to})
	}
	exit := func(code int32, cg uint64, pid uint32) {
		ts += 1e8
		c.handle(&bpf.ProcCapyProcEvent{Ts: ts, Type: procEvExit, Cgroup: cg, Pid: pid, NsPid: 1, Code: code})
	}
	crashes := func() []model.CrashReport { return a.rec.Crashes(time.Time{}, time.Now().Add(time.Hour)) }

	// kubectl delete pod: SIGTERM to every container, then the sandbox
	signal(15, host, 500, "runc", app, 1001)
	signal(15, host, 500, "runc", side, 1002)
	exit(143<<8, app, 1001) // the JVM exits 128+SIGTERM
	exit(1<<8, side, 1002)  // handled SIGTERM, exit status 1
	signal(9, host, 501, "runc", pause, 1000)
	exit(9, pause, 1000)
	// a PID 1 without a SIGTERM handler: the kernel drops the SIGTERM
	// unseen, the runtime kills it when the grace period ends
	signal(9, host, 502, "runc", other, 2001)
	exit(9, other, 2001)
	signal(9, host, 503, "runc", otherPause, 2000)
	exit(9, otherPause, 2000)
	if cr := crashes(); len(cr) != 0 {
		t.Fatalf("pod deletions reported as crashes: %+v", cr)
	}

	// the sidecar of a pod whose app is being stopped crashes on its own
	signal(15, host, 504, "runc", app, 1011)
	exit(1<<8, side, 1012)
	if cr := crashes(); len(cr) != 1 || !strings.Contains(cr[0].Reason, "status 1") {
		t.Fatalf("crash of a container that was not stopped: %+v", cr)
	}
	// a fault, and a SIGKILL from inside the pod (not the runtime)
	signal(11, other, 2011, "app", other, 2011)
	signal(9, other, 2012, "runc-lookalike", other, 2013)
	if cr := crashes(); len(cr) != 2 || !strings.Contains(cr[1].Reason, "SIGSEGV") || !strings.Contains(cr[1].Reason, "SIGKILL") {
		t.Fatalf("crashes: %+v", cr)
	}
}

// The gauges of a deleted pod leave /metrics within a minute or two
// instead of adding its last memory reading to every sum for 30 minutes;
// counters of a quiet entity are kept (a gap would read as a reset).
func TestGaugesOfGoneEntitiesExpire(t *testing.T) {
	m := newMetrics(nil)
	w := NewWindow(time.Now(), time.Now())
	for _, id := range []string{"pod:gone", "pod:live"} {
		e := w.Entity(id)
		e.Res = &model.Resources{MemCurrent: 1 << 30, Throttled: 3, SampledAt: time.Now()}
	}
	m.observe(w)
	m.mu.Lock()
	for _, s := range m.vals {
		s.updated = s.updated.Add(-2 * time.Minute)
	}
	m.mu.Unlock()
	w = NewWindow(time.Now(), time.Now())
	w.Entity("pod:live").Res = &model.Resources{MemCurrent: 1 << 30, SampledAt: time.Now()}
	m.observe(w)
	var b strings.Builder
	m.write(&b)
	out := b.String()
	if strings.Contains(out, `capybara_memory_bytes{entity="pod:gone"`) {
		t.Error("memory gauge of a pod gone for 2 minutes is still exported")
	}
	for _, want := range []string{`capybara_memory_bytes{entity="pod:live"`, `capybara_cpu_throttled_periods_total{entity="pod:gone"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
}
