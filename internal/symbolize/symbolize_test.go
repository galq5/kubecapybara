package symbolize

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestPerfMap resolves JIT addresses from /proc/<pid>/root/tmp/perf-<nspid>.map
// using a fake procfs.
func TestPerfMap(t *testing.T) {
	proc := t.TempDir()
	pid := 4242
	root := filepath.Join(proc, fmt.Sprint(pid), "root", "tmp")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(proc, fmt.Sprint(pid), "status"), []byte("Name:\tjava\nNSpid:\t4242\t1\n"), 0o644)
	os.WriteFile(filepath.Join(proc, fmt.Sprint(pid), "maps"), []byte(""), 0o644)
	os.WriteFile(filepath.Join(root, "perf-1.map"), []byte("7f0000001000 100 Lcom/shop/Checkout;::price\n7f0000002000 80 Ljava/util/HashMap;::get\n"), 0o644)
	s := New(proc)
	if got := s.User(uint32(pid), 0x7f0000001050); got != "Lcom/shop/Checkout;::price" {
		t.Fatalf("got %q", got)
	}
	if got := s.User(uint32(pid), 0x7f0000001500); got != "[unknown] 0x7f0000001500" {
		t.Fatalf("gap between symbols: %q", got)
	}
}
