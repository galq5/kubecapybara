package agent

import (
	"sort"
	"sync"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
)

// Window holds aggregated statistics for a time interval.
type Window struct {
	Start, End time.Time
	Pairs      map[model.PairKey]*model.Pair
	Entities   map[string]*model.EntityStats
	Drops      map[model.DropKey]*model.Drop
	Node       model.NodeStats
}

// NewWindow creates an empty window.
func NewWindow(start, end time.Time) *Window {
	return &Window{
		Start:    start,
		End:      end,
		Pairs:    map[model.PairKey]*model.Pair{},
		Entities: map[string]*model.EntityStats{},
		Drops:    map[model.DropKey]*model.Drop{},
	}
}

// Entity returns (creating) the stats for an entity.
func (w *Window) Entity(id string) *model.EntityStats {
	e, ok := w.Entities[id]
	if !ok {
		e = &model.EntityStats{ID: id}
		w.Entities[id] = e
	}
	return e
}

// AddPair merges a pair into the window.
func (w *Window) AddPair(p *model.Pair) {
	k := p.Key()
	if cur, ok := w.Pairs[k]; ok {
		cur.Add(p)
		return
	}
	w.Pairs[k] = p.Clone()
}

// AddDrop merges a drop into the window.
func (w *Window) AddDrop(d *model.Drop) {
	k := d.Key()
	if cur, ok := w.Drops[k]; ok {
		cur.Count += d.Count
		return
	}
	c := *d
	w.Drops[k] = &c
}

// Merge adds o into w and widens the time range.
func (w *Window) Merge(o *Window) {
	if w.Start.IsZero() || (!o.Start.IsZero() && o.Start.Before(w.Start)) {
		w.Start = o.Start
	}
	if o.End.After(w.End) {
		w.End = o.End
	}
	for _, p := range o.Pairs {
		w.AddPair(p)
	}
	for id, e := range o.Entities {
		w.Entity(id).Merge(e)
	}
	for _, d := range o.Drops {
		w.AddDrop(d)
	}
	w.Node.Merge(o.Node)
}

// Store keeps fine-grained windows for a short period and minute rollups
// for the full retention period.
type Store struct {
	mu        sync.RWMutex
	fine      []*Window
	coarse    []*Window
	pending   *Window
	fineKeep  time.Duration
	keep      time.Duration
	rollEvery time.Duration
}

// NewStore creates a store.
func NewStore(fineKeep, keep time.Duration) *Store {
	return &Store{fineKeep: fineKeep, keep: keep, rollEvery: time.Minute}
}

// Add appends a collected window.
func (s *Store) Add(w *Window) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fine = append(s.fine, w)

	bucket := w.Start.Truncate(s.rollEvery)
	if s.pending != nil && !s.pending.Start.Truncate(s.rollEvery).Equal(bucket) {
		s.coarse = append(s.coarse, s.pending)
		s.pending = nil
	}
	if s.pending == nil {
		s.pending = NewWindow(w.Start, w.End)
	}
	s.pending.Merge(w)

	now := w.End
	for len(s.fine) > 0 && now.Sub(s.fine[0].End) > s.fineKeep {
		s.fine = s.fine[1:]
	}
	for len(s.coarse) > 0 && now.Sub(s.coarse[0].End) > s.keep {
		s.coarse = s.coarse[1:]
	}
}

// Query merges all data overlapping [from, to).
func (s *Store) Query(from, to time.Time) *Window {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := NewWindow(time.Time{}, time.Time{})
	overlaps := func(w *Window) bool { return from.Before(to) && w.End.After(from) && w.Start.Before(to) }
	coarse := s.coarse
	if s.pending != nil {
		coarse = append(coarse[:len(coarse):len(coarse)], s.pending)
	}
	// Every fine window is also merged into exactly one minute rollup (by
	// its start). Use rollups for the minutes before the first minute fully
	// covered by fine windows and fine windows from there on, so nothing is
	// counted twice.
	boundary := to.Add(time.Nanosecond)
	if len(s.fine) > 0 {
		fineStart := s.fine[0].Start
		boundary = fineStart.Truncate(s.rollEvery)
		if boundary.Before(fineStart) {
			boundary = boundary.Add(s.rollEvery)
		}
		if !from.Before(fineStart) {
			boundary = time.Time{} // fully inside the fine range
		}
	}
	for _, w := range coarse {
		if overlaps(w) && w.Start.Before(boundary) {
			out.Merge(w)
		}
	}
	for _, w := range s.fine {
		if overlaps(w) && !w.Start.Before(boundary) {
			out.Merge(w)
		}
	}
	if out.Start.IsZero() {
		out.Start, out.End = from, to
	}
	return out
}

// Oldest returns the start of the oldest retained data.
func (s *Store) Oldest() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.coarse) > 0 {
		return s.coarse[0].Start
	}
	if len(s.fine) > 0 {
		return s.fine[0].Start
	}
	return time.Time{}
}

// ToSnapshot converts a window into the wire format.
func (w *Window) ToSnapshot() *model.Snapshot {
	snap := &model.Snapshot{
		From:      w.Start,
		To:        w.End,
		Entities:  w.Entities,
		NodeStats: w.Node,
	}
	for _, p := range w.Pairs {
		snap.Pairs = append(snap.Pairs, p)
	}
	sort.Slice(snap.Pairs, func(i, j int) bool {
		a, b := snap.Pairs[i], snap.Pairs[j]
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		return a.Port < b.Port
	})
	for _, d := range w.Drops {
		snap.Drops = append(snap.Drops, d)
	}
	sort.Slice(snap.Drops, func(i, j int) bool { return snap.Drops[i].Count > snap.Drops[j].Count })
	return snap
}
