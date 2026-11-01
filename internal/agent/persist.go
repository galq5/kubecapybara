package agent

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
)

// persisted is the on-disk state: enough to answer "what happened at 3am"
// after an agent restart (rollups, recent fine windows, crash reports).
type persisted struct {
	Version int
	Saved   time.Time
	Node    string
	Fine    []*Window
	Coarse  []*Window
	Pending *Window
	Crashes []model.CrashReport
}

const stateVersion = 1

func (a *Agent) statePath() string { return filepath.Join(a.cfg.StateDir, "state.gob") }

// SaveState writes the store and crash reports atomically.
func (a *Agent) SaveState() error {
	if a.cfg.StateDir == "" {
		return nil
	}
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return err
	}
	a.store.mu.RLock()
	st := persisted{Version: stateVersion, Saved: time.Now(), Node: a.cfg.Node,
		Fine: append([]*Window(nil), a.store.fine...), Coarse: append([]*Window(nil), a.store.coarse...)}
	if p := a.store.pending; p != nil {
		// the pending rollup keeps being merged into: encode a copy
		st.Pending = NewWindow(p.Start, p.End)
		st.Pending.Merge(p)
	}
	a.store.mu.RUnlock()
	st.Crashes = a.rec.Crashes(time.Time{}, time.Now())

	tmp, err := os.CreateTemp(a.cfg.StateDir, "state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// encoding happens outside the store lock on the copied slices; windows
	// are immutable once added to the store
	if err := gob.NewEncoder(tmp).Encode(&st); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.statePath())
}

// LoadState restores the store and crash reports saved by a previous run
// on this node, dropping data older than the retention.
func (a *Agent) LoadState() error {
	if a.cfg.StateDir == "" {
		return nil
	}
	f, err := os.Open(a.statePath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var st persisted
	if err := gob.NewDecoder(f).Decode(&st); err != nil {
		return fmt.Errorf("decode %s: %w", a.statePath(), err)
	}
	if st.Version != stateVersion || (st.Node != "" && st.Node != a.cfg.Node) {
		return nil
	}
	now := time.Now()
	keep := func(ws []*Window, d time.Duration) []*Window {
		var out []*Window
		for _, w := range ws {
			if w != nil && now.Sub(w.End) <= d {
				out = append(out, w)
			}
		}
		return out
	}
	a.store.mu.Lock()
	a.store.coarse = keep(st.Coarse, a.store.keep)
	a.store.fine = keep(st.Fine, a.store.fineKeep)
	if st.Pending != nil && now.Sub(st.Pending.End) < a.store.rollEvery {
		a.store.pending = st.Pending
	} else if st.Pending != nil && now.Sub(st.Pending.End) <= a.store.keep {
		a.store.coarse = append(a.store.coarse, st.Pending)
	}
	a.store.mu.Unlock()
	for _, c := range st.Crashes {
		a.rec.restoreCrash(c)
	}
	a.log.Info("restored state", "saved", st.Saved.Format(time.RFC3339), "rollups", len(st.Coarse), "crashes", len(st.Crashes))
	return nil
}
