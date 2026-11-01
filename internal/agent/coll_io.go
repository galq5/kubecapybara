package agent

import (
	"errors"
	"fmt"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/model"
)

// ioCollector: block I/O latency and throughput per entity.
type ioCollector struct {
	a    *Agent
	objs bpf.IoObjects
	l    linker
}

func (c *ioCollector) Name() string { return "io" }

func (c *ioCollector) Start(a *Agent) error {
	c.a = a
	if err := bpf.LoadIoObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	return errors.Join(
		c.l.tracing(c.objs.OnBioQueue, "tp_btf/block_bio_queue"),
		c.l.tracing(c.objs.OnRqComplete, "tp_btf/block_rq_complete"),
	)
}

func (c *ioCollector) Collect(w *Window) {
	drainMap(c.objs.IoStats, func(cg uint64, v *bpf.IoCgIo) {
		e := w.Entity(c.a.resolver.Entity(cg))
		s := &model.IOStats{
			ReadBytes: v.RdBytes, WriteBytes: v.WrBytes, ReadOps: v.RdOps, WriteOps: v.WrOps,
			Lat: model.HistFromSlots(v.Lat.Slots[:], v.Lat.Count, v.Lat.Sum),
		}
		if e.IO == nil {
			e.IO = &model.IOStats{}
		}
		e.IO.Merge(s)
	})
}

func (c *ioCollector) Close() error {
	c.l.close()
	return c.objs.Close()
}
