package agent

import (
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
	if got := q.Pairs[model.PairKey{Client: "a", Server: "b", Port: 80, Side: "client", Owner: "x"}].Connects; got < 11 || got > 13 {
		t.Fatalf("last minute connects = %d, want ~12", got)
	}
	// old: served from rollups (fine windows only cover 2 minutes)
	q = s.Query(base, end)
	if got := q.Pairs[model.PairKey{Client: "a", Server: "b", Port: 80, Side: "client", Owner: "x"}].Connects; got < 115 {
		t.Fatalf("10 minute connects = %d, want ~120 (rollups)", got)
	}
	if q.Entities["pod:1"].DNS.Queries < 230 {
		t.Fatalf("dns queries = %d", q.Entities["pod:1"].DNS.Queries)
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
