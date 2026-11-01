package bpf

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestLoad loads every object into the running kernel to make sure the
// verifier accepts it. Requires root (or CAP_BPF+CAP_PERFMON).
func TestLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	_ = rlimit.RemoveMemlock()
	loaders := map[string]func() (*ebpf.CollectionSpec, error){
		"net": LoadNet, "drop": LoadDrop, "dns": LoadDns, "sched": LoadSched,
		"io": LoadIo, "proc": LoadProc, "http": LoadHttp, "profile": LoadProfile, "files": LoadFiles, "voip": LoadVoip,
	}
	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			spec, err := load()
			if err != nil {
				t.Fatal(err)
			}
			coll, err := ebpf.NewCollection(spec)
			if err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					t.Fatalf("verifier: %+v", ve)
				}
				t.Fatal(err)
			}
			coll.Close()
		})
	}
}
