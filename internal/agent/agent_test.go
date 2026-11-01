package agent

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
)

func TestParseHTTP(t *testing.T) {
	m, p, ok := ParseRequestLine([]byte("GET /users/123/orders?x=1 HTTP/1.1\r\nHost: a\r\n"))
	if !ok || m != "GET" || p != "/users/123/orders" {
		t.Fatalf("got %q %q %v", m, p, ok)
	}
	if NormalizePath("/users/123/orders/550e8400-e29b-41d4-a716-446655440000") != "/users/:id/orders/:id" {
		t.Fatal(NormalizePath("/users/123/orders/550e8400-e29b-41d4-a716-446655440000"))
	}
	if NormalizePath("/api/v1/health") != "/api/v1/health" {
		t.Fatal("must not collapse version segments")
	}
	if ParseStatus([]byte("HTTP/1.1 503 Service Unavailable\r\n")) != 503 {
		t.Fatal("status")
	}
	if ParseStatus([]byte("garbage")) != 0 {
		t.Fatal("garbage status")
	}
}

func TestStoreRollupsAndQuery(t *testing.T) {
	s := NewStore(2*time.Minute, time.Hour)
	base := time.Now().Truncate(time.Minute).Add(-10 * time.Minute)
	for i := 0; i < 120; i++ { // 10 minutes of 5s windows
		start := base.Add(time.Duration(i) * 5 * time.Second)
		w := NewWindow(start, start.Add(5*time.Second))
		w.AddPair(&model.Pair{Client: "a", Server: "b", Port: 80, Side: "client", Owner: "x", Connects: 1})
		w.Entity("pod:1").DNS = &model.DNSStats{Queries: 2}
		s.Add(w)
	}
	end := base.Add(10 * time.Minute)
	// recent: served from fine windows
	q := s.Query(end.Add(-time.Minute), end)
	if got := q.Pairs[model.PairKey{Client: "a", Server: "b", Port: 80, Side: "client", Owner: "x"}].Connects; got != 12 {
		t.Fatalf("last minute connects = %d, want 12", got)
	}
	// old: served from rollups (fine windows only cover 2 minutes)
	q = s.Query(base, end)
	// fine windows start mid-minute (7m55s): the boundary must not be
	// counted twice (rollup + fine)
	if got := q.Pairs[model.PairKey{Client: "a", Server: "b", Port: 80, Side: "client", Owner: "x"}].Connects; got != 120 {
		t.Fatalf("10 minute connects = %d, want exactly 120", got)
	}
	if q.Entities["pod:1"].DNS.Queries != 240 {
		t.Fatalf("dns queries = %d, want 240", q.Entities["pod:1"].DNS.Queries)
	}
}

func TestRecorderCrashAndStartup(t *testing.T) {
	r := NewRecorder()
	now := time.Now()
	r.BeginStartup("pod:a", now.Add(-time.Second))
	r.Add(model.Event{Time: now.Add(-500 * time.Millisecond), Entity: "pod:a", Type: model.EvExec, Message: "exec app"})
	r.Add(model.Event{Time: now, Entity: "pod:b", Type: model.EvExec, Message: "other"})
	r.Crash("pod:a", "SIGSEGV", now)
	r.Crash("pod:a", "exit 139", now.Add(time.Second)) // merged into the first report
	cr := r.Crashes(now.Add(-time.Minute), now.Add(time.Minute))
	if len(cr) != 1 || cr[0].Reason != "SIGSEGV; exit 139" || len(cr[0].Events) != 1 {
		t.Fatalf("crashes: %+v", cr)
	}
	st := r.Startups(now.Add(-time.Minute), now)
	if len(st) != 1 || len(st[0].Events) != 1 {
		t.Fatalf("startups: %+v", st)
	}
}

func TestDecodeProcAddr(t *testing.T) {
	if a := decodeProcAddr("0100007F"); a != "127.0.0.1" {
		t.Fatal(a)
	}
	if a := decodeProcAddr("00000000000000000000000001000000"); a != "::1" {
		t.Fatal(a)
	}
}

func TestRedactArgs(t *testing.T) {
	cases := map[string]string{
		"app --password=hunter2 --port 80":         "app --password=*** --port 80",
		"psql --password hunter2 -h db":            "psql --password *** -h db",
		"env DB_PASSWORD=s3cret API_KEY=abc ./run": "env DB_PASSWORD=*** API_KEY=*** ./run",
		"curl -H token: xyz http://a":              "curl -H token: *** http://a",
		"nginx -g daemon off;":                     "nginx -g daemon off;",
		"java -Xmx1g -jar app.jar":                 "java -Xmx1g -jar app.jar",
	}
	for in, want := range cases {
		if got := RedactArgs(in); got != want {
			t.Errorf("RedactArgs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTerminationIsNotACrash(t *testing.T) {
	c := &procCollector{terminating: map[string]time.Time{}}
	now := time.Now()
	if !c.isTermination("pod:a", 15, 0, now) || !c.isTermination("pod:a", 0, 143, now) {
		t.Fatal("SIGTERM / exit 143 must be a termination")
	}
	if c.isTermination("pod:a", 11, 0, now) || c.isTermination("pod:a", 0, 1, now) {
		t.Fatal("SIGSEGV / exit 1 without a prior SIGTERM is a crash")
	}
	c.terminating["pod:a"] = now.Add(-30 * time.Second)
	if !c.isTermination("pod:a", 9, 0, now) {
		t.Fatal("SIGKILL after SIGTERM (grace period expired) is a termination")
	}
	c.terminating["pod:a"] = now.Add(-time.Hour)
	if c.isTermination("pod:a", 9, 0, now) {
		t.Fatal("old SIGTERM must not hide a later crash")
	}
}

func TestListenRefcountAndPrune(t *testing.T) {
	r := NewRecorder()
	r.Listen(model.Listen{Entity: "pod:a", Port: 80})
	r.Listen(model.Listen{Entity: "pod:a", Port: 80}) // v4 + v6 listener
	r.Listen(model.Listen{Entity: "pod:b", Port: 90})
	r.Unlisten("pod:a", 80)
	if len(r.Listens()) != 2 {
		t.Fatalf("one of two sockets closed: %+v", r.Listens())
	}
	r.Unlisten("pod:a", 80)
	if len(r.Listens()) != 1 {
		t.Fatalf("both sockets closed: %+v", r.Listens())
	}
	r.PruneListens(func(e string) bool { return e != "pod:b" })
	if len(r.Listens()) != 0 {
		t.Fatalf("pruned: %+v", r.Listens())
	}
}

func TestLearnNameEvictsInBatches(t *testing.T) {
	r := NewRecorder()
	for i := 0; i < maxDNSNames+10; i++ {
		r.LearnName(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "n")
	}
	if n := len(r.Names()); n > maxDNSNames || n < maxDNSNames*9/10 {
		t.Fatalf("cache size %d out of bounds", n)
	}
}

func TestTokenAuth(t *testing.T) {
	a := &Agent{cfg: Config{Token: "s3cret"}, store: NewStore(time.Minute, time.Hour), rec: NewRecorder(), status: map[string]string{}}
	a.metrics = newMetrics(a)
	h := a.Handler()
	do := func(path, token string) int {
		req := httptest.NewRequest("GET", path, nil)
		if token != "" {
			req.Header.Set(TokenHeader, token)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if c := do("/v1/snapshot", ""); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c := do("/v1/snapshot", "wrong"); c != 401 {
		t.Fatalf("wrong token: %d", c)
	}
	if c := do("/v1/snapshot?lite=1", "s3cret"); c != 200 {
		t.Fatalf("good token: %d", c)
	}
	if c := do("/healthz", ""); c != 200 {
		t.Fatalf("healthz must stay open: %d", c)
	}
	if c := do("/metrics", ""); c != 200 {
		t.Fatalf("metrics must stay open: %d", c)
	}
}

func TestDBParsing(t *testing.T) {
	pgQ := append([]byte{'Q', 0, 0, 0, 40}, []byte("SELECT * FROM users WHERE id = 42 AND name = 'bob'\x00")...)
	if q := ParseDBRequest(protoPostgres, pgQ); q != "SELECT * FROM users WHERE id = ? AND name = ?" {
		t.Errorf("pg Q: %q", q)
	}
	pgP := append([]byte{'P', 0, 0, 0, 40}, []byte("stmt1\x00INSERT INTO t (a, b) VALUES ($1, $2)\x00")...)
	if q := ParseDBRequest(protoPostgres, pgP); q != "INSERT INTO t (a, b) VALUES ($?, $?)" {
		t.Errorf("pg P: %q", q)
	}
	my := append([]byte{30, 0, 0, 0, 0x03}, []byte("select a from b where c in (1, 2, 3)")...)
	if q := ParseDBRequest(protoMySQL, my); q != "select a from b where c IN (?)" {
		t.Errorf("mysql: %q", q)
	}
	if q := ParseDBRequest(protoRedis, []byte("*2\r\n$3\r\nget\r\n$5\r\nmykey\r\n")); q != "GET" {
		t.Errorf("redis: %q", q)
	}
	if !DBError(protoPostgres, []byte("E\x00\x00\x00")) || DBError(protoPostgres, []byte("T\x00")) {
		t.Error("pg error detection")
	}
	if !DBError(protoRedis, []byte("-ERR wrong type")) || DBError(protoRedis, []byte("+OK")) {
		t.Error("redis error detection")
	}
	if !DBError(protoMySQL, []byte{9, 0, 0, 1, 0xff, 0x15}) || DBError(protoMySQL, []byte{7, 0, 0, 1, 0x00}) {
		t.Error("mysql error detection")
	}
}

func TestDBParsingEdgeCases(t *testing.T) {
	// a Redis server's array reply is not a client command
	if q := ParseDBRequest(protoRedis, []byte("*3\r\n$5\r\njob-1\r\n$5\r\njob-2\r\n")); q != "" {
		t.Errorf("server reply parsed as command %q", q)
	}
	if q := ParseDBRequest(protoRedis, []byte("*2\r\n$7\r\nmessage\r\n$4\r\nchan\r\n")); q != "" {
		t.Errorf("pub/sub push parsed as command %q", q)
	}
	// extended protocol: ParseComplete, BindComplete, then ErrorResponse
	reply := []byte{'1', 0, 0, 0, 4, '2', 0, 0, 0, 4, 'E', 0, 0, 0, 0x40, 'S'}
	if !DBError(protoPostgres, reply) {
		t.Error("error after ParseComplete/BindComplete missed")
	}
	ok := []byte{'1', 0, 0, 0, 4, '2', 0, 0, 0, 4, 'C', 0, 0, 0, 0x0d, 'I'}
	if DBError(protoPostgres, ok) {
		t.Error("CommandComplete reported as error")
	}
}
