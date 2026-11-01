package agent

import (
	"errors"
	"fmt"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/model"
)

// schedCollector: per-entity thread time breakdown, run queue latency,
// noisy neighbour attribution and direct reclaim stalls.
type schedCollector struct {
	a    *Agent
	objs bpf.SchedObjects
	l    linker
}

func (c *schedCollector) Name() string { return "sched" }

func (c *schedCollector) Start(a *Agent) error {
	c.a = a
	if err := bpf.LoadSchedObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	p := c.objs.SchedPrograms
	if err := errors.Join(
		c.l.tracing(p.OnSwitch, "tp_btf/sched_switch"),
		c.l.tracing(p.OnWakeup, "tp_btf/sched_wakeup"),
		c.l.tracing(p.OnWakeupNew, "tp_btf/sched_wakeup_new"),
	); err != nil {
		return err
	}
	if err := errors.Join(
		c.l.tracepoint("vmscan", "mm_vmscan_direct_reclaim_begin", p.OnReclaimBegin),
		c.l.tracepoint("vmscan", "mm_vmscan_direct_reclaim_end", p.OnReclaimEnd),
	); err != nil {
		a.log.Warn("sched: reclaim tracing unavailable", "err", err)
	}
	return nil
}

func (c *schedCollector) Collect(w *Window) {
	a := c.a
	// time spent in a state before this point is not credited to the next window
	if c.objs.WindowStartNs != nil {
		_ = c.objs.WindowStartNs.Set(monoNow())
	}
	drainMap(c.objs.CgStats, func(cg uint64, v *bpf.SchedCgSched) {
		e := w.Entity(a.resolver.Entity(cg))
		s := &model.SchedStats{
			OnCPUNs:      v.OncpuNs,
			OffNs:        map[string]uint64{},
			RunQ:         model.HistFromSlots(v.Runq.Slots[:], v.Runq.Count, v.Runq.Sum),
			ReclaimNs:    v.ReclaimNs,
			ReclaimCount: v.ReclaimCnt,
			Wakeups:      v.Wakeups,
		}
		for i, name := range model.OffStates {
			if v.OffNs[i] > 0 {
				s.OffNs[name] = v.OffNs[i]
			}
		}
		if e.Sched == nil {
			e.Sched = &model.SchedStats{}
		}
		e.Sched.Merge(s)
	})
	drainMap(c.objs.Culprits, func(k bpf.SchedCulpritKey, ns *uint64) {
		victim := a.resolver.Entity(k.Victim)
		culprit := a.resolver.Entity(k.Culprit)
		if victim == culprit {
			return
		}
		e := w.Entity(victim)
		if e.Sched == nil {
			e.Sched = &model.SchedStats{}
		}
		if e.Sched.Culprits == nil {
			e.Sched.Culprits = map[string]uint64{}
		}
		e.Sched.Culprits[culprit] += *ns
	})
}

func (c *schedCollector) Close() error {
	c.l.close()
	return c.objs.Close()
}
