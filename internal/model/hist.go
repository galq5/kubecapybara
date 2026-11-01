// Package model contains the wire types shared by the agent and the CLI.
package model

import (
	"math"
	"math/bits"
)

// HistSlots is the number of log2 buckets produced by the eBPF programs.
const HistSlots = 32

// Hist is a log2 latency histogram in microseconds.
//
//	slot 0       -> 0us
//	slot k (k>0) -> [2^(k-1), 2^k) us
type Hist struct {
	B     []uint64 `json:"b,omitempty"`
	Count uint64   `json:"n,omitempty"`
	Sum   uint64   `json:"s,omitempty"` // microseconds
}

// HistFromSlots builds a histogram from raw kernel slots, trimming trailing
// empty buckets to keep the wire format small.
func HistFromSlots(slots []uint64, count, sum uint64) Hist {
	last := -1
	for i, v := range slots {
		if v != 0 {
			last = i
		}
	}
	if last < 0 {
		return Hist{}
	}
	b := make([]uint64, last+1)
	copy(b, slots[:last+1])
	return Hist{B: b, Count: count, Sum: sum}
}

// SlotFor returns the bucket index for a value in microseconds.
func SlotFor(us uint64) int {
	if us == 0 {
		return 0
	}
	s := bits.Len64(us) // floor(log2)+1
	if s >= HistSlots {
		s = HistSlots - 1
	}
	return s
}

// Observe records a single value in microseconds.
func (h *Hist) Observe(us uint64) {
	s := SlotFor(us)
	if len(h.B) <= s {
		nb := make([]uint64, s+1)
		copy(nb, h.B)
		h.B = nb
	}
	h.B[s]++
	h.Count++
	h.Sum += us
}

// Add merges o into h.
func (h *Hist) Add(o Hist) {
	if o.Count == 0 {
		return
	}
	if len(h.B) < len(o.B) {
		nb := make([]uint64, len(o.B))
		copy(nb, h.B)
		h.B = nb
	}
	for i, v := range o.B {
		h.B[i] += v
	}
	h.Count += o.Count
	h.Sum += o.Sum
}

// Empty reports whether the histogram has no samples.
func (h Hist) Empty() bool { return h.Count == 0 }

// Mean returns the average in microseconds.
func (h Hist) Mean() float64 {
	if h.Count == 0 {
		return 0
	}
	return float64(h.Sum) / float64(h.Count)
}

// bounds returns the [lo, hi) range of a slot in microseconds.
func bounds(slot int) (float64, float64) {
	if slot == 0 {
		return 0, 1
	}
	lo := math.Ldexp(1, slot-1)
	return lo, lo * 2
}

// Quantile estimates the q-quantile (0..1) in microseconds using linear
// interpolation within the bucket.
func (h Hist) Quantile(q float64) float64 {
	var total uint64
	for _, v := range h.B {
		total += v
	}
	if total == 0 {
		return 0
	}
	if q <= 0 {
		q = 0
	}
	if q >= 1 {
		q = 1
	}
	rank := q * float64(total)
	var cum float64
	for i, v := range h.B {
		if v == 0 {
			continue
		}
		next := cum + float64(v)
		if next >= rank {
			lo, hi := bounds(i)
			frac := (rank - cum) / float64(v)
			return lo + (hi-lo)*frac
		}
		cum = next
	}
	_, hi := bounds(len(h.B) - 1)
	return hi
}

// P50, P90 and P99 are shorthands in microseconds.
func (h Hist) P50() float64 { return h.Quantile(0.50) }
func (h Hist) P90() float64 { return h.Quantile(0.90) }
func (h Hist) P99() float64 { return h.Quantile(0.99) }
