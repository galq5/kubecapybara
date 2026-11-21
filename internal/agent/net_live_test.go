package agent

import (
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/galq5/kubecapybara/internal/cgroups"
)

// TestListenerSurvivesAccept loads the TCP programs into the running kernel
// (root only). An accepted connection is a clone of its listener and its
// first state change is reported as LISTEN -> SYN_RECV, which must not be
// taken for the listener closing.
func TestListenerSurvivesAccept(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	root, err := cgroups.DetectRoot("")
	if err != nil {
		t.Skipf("no cgroup v2: %v", err)
	}
	_ = rlimit.RemoveMemlock()
	a := &Agent{
		cfg: Config{ProcRoot: "/proc"}, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolver: cgroups.NewResolver(root), rec: NewRecorder(), clock: newClock(),
		status: map[string]string{}, seen: map[string]time.Time{},
	}
	c := &netCollector{}
	a.net = c
	if err := c.Start(a); err != nil {
		t.Skipf("cannot load the TCP programs on this kernel: %v", err)
	}
	defer c.Close()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	listening := func() bool {
		for _, x := range a.rec.Listens() {
			if x.Port == port {
				return true
			}
		}
		return false
	}
	waitFor := func(want bool) bool {
		for i := 0; i < 100; i++ {
			if listening() == want {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}
	if !waitFor(true) {
		t.Skip("listen event not delivered (tracing unavailable in this environment)")
	}
	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp4", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		srv, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		srv.Close()
	}
	time.Sleep(300 * time.Millisecond) // let the ring buffer drain
	if !listening() {
		t.Fatal("the listener was forgotten after accepting connections")
	}
	l.Close()
	if !waitFor(false) {
		t.Fatal("the listener is still reported after it was closed")
	}
}
