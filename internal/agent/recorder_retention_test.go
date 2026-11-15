package agent

import (
	"github.com/galq5/kubecapybara/internal/model"
	"testing"
	"time"
)

func TestRecorderExpiresInactiveSamples(t *testing.T) {
	r := NewRecorder()
	now := time.Now()
	old := now.Add(-seriesIdle - time.Second)
	r.Sample("old", model.ResourceSample{Time: old, MemCurrent: 123})
	r.Crash("old", "crash", old)
	r.Sample("active", model.ResourceSample{Time: now})
	r.Prune(now)
	if len(r.series) != 1 || len(r.series["active"]) != 1 || len(r.lastCrash) != 0 {
		t.Fatal("inactive entity retained or active entity removed")
	}
	crashes := r.Crashes(time.Time{}, now)
	if len(crashes) != 1 || len(crashes[0].Series) != 1 || crashes[0].Series[0].MemCurrent != 123 {
		t.Fatal("pruning damaged frozen crash history")
	}
}
