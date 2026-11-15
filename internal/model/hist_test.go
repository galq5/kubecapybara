package model

import "testing"

func TestHistQuantiles(t *testing.T) {
	var h Hist
	for i := 0; i < 99; i++ {
		h.Observe(100) // slot [64,128)
	}
	h.Observe(100000) // one outlier ~100ms
	if p := h.P50(); p < 64 || p > 128 {
		t.Fatalf("p50 = %v", p)
	}
	if p := h.Quantile(0.999); p < 65536 {
		t.Fatalf("p99.9 = %v", p)
	}
	var o Hist
	o.Add(h)
	o.Add(h)
	if o.Count != 200 || o.Sum != 2*h.Sum {
		t.Fatalf("merge: %+v", o)
	}
	k := HistFromSlots([]uint64{0, 1, 0, 0}, 1, 1)
	if len(k.B) != 2 {
		t.Fatalf("trim: %+v", k)
	}
	if SlotFor(0) != 0 || SlotFor(1) != 1 || SlotFor(2) != 2 || SlotFor(3) != 2 || SlotFor(4) != 3 {
		t.Fatal("slots")
	}
}

// TestPairGauges: open/idle connections are max-merged over time (Add) and
// summed across distinct concurrent connection sets (AddConcurrent).
func TestPairGauges(t *testing.T) {
	p := &Pair{OpenConns: 10, IdleConns: 4, Connects: 1}
	p.Add(&Pair{OpenConns: 8, IdleConns: 6, Connects: 1})
	if p.OpenConns != 10 || p.IdleConns != 6 || p.Connects != 2 {
		t.Fatalf("Add: %+v", p)
	}
	p.AddConcurrent(&Pair{OpenConns: 5, IdleConns: 1, Connects: 1})
	if p.OpenConns != 15 || p.IdleConns != 7 || p.Connects != 3 {
		t.Fatalf("AddConcurrent: %+v", p)
	}
}
