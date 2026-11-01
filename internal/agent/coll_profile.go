package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/model"
	"github.com/galq5/kubecapybara/internal/symbolize"
)

// profileCollector implements on-demand, cgroup filtered CPU profiling.
type profileCollector struct {
	a    *Agent
	objs bpf.ProfileObjects
	sym  *symbolize.Symbolizer
	busy sync.Mutex
}

func (c *profileCollector) Name() string { return "profile" }

func (c *profileCollector) Start(a *Agent) error {
	c.a = a
	c.sym = symbolize.New(a.cfg.ProcRoot)
	if err := bpf.LoadProfileObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	return nil
}

func (c *profileCollector) Collect(w *Window) {}

func (c *profileCollector) Close() error { return c.objs.Close() }

// ErrBusy is returned when a profile is already running.
var ErrBusy = errors.New("a profile is already running on this node")

// Profile samples the CPU stacks of an entity for d at hz samples/second.
func (c *profileCollector) Profile(ctx context.Context, entity string, d time.Duration, hz int) (*model.Profile, error) {
	if c.objs.OnSample == nil {
		return nil, errors.New("profiler not loaded")
	}
	if !c.busy.TryLock() {
		return nil, ErrBusy
	}
	defer c.busy.Unlock()
	if hz <= 0 || hz > 1000 {
		hz = 99
	}

	c.a.resolver.Scan()
	ids := c.a.resolver.IDsForEntity(entity)
	if len(ids) == 0 {
		return nil, fmt.Errorf("entity %s has no cgroups on node %s", entity, c.a.cfg.Node)
	}
	clearMap := func() {
		drainMap(c.objs.Samples, func(bpf.ProfileSampleKey, *uint64) {})
		drainMap(c.objs.ProfileCgroups, func(uint64, *uint8) {})
		drainMap(c.objs.Stacks, func(uint32, *[127]uint64) {})
	}
	clearMap()
	defer clearMap()
	for _, id := range ids {
		if err := c.objs.ProfileCgroups.Put(id, uint8(1)); err != nil {
			return nil, err
		}
	}

	var fds []int
	defer func() {
		for _, fd := range fds {
			_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
			_ = unix.Close(fd)
		}
	}()
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Size:   uint32(binary.Size(unix.PerfEventAttr{})),
		Sample: uint64(hz),
		Bits:   unix.PerfBitFreq | unix.PerfBitDisabled,
	}
	for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			continue // offline CPU
		}
		fds = append(fds, fd)
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, c.objs.OnSample.FD()); err != nil {
			return nil, fmt.Errorf("attach perf event: %w", err)
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			return nil, fmt.Errorf("enable perf event: %w", err)
		}
	}
	if len(fds) == 0 {
		return nil, errors.New("perf_event_open failed on all CPUs")
	}

	select {
	case <-time.After(d):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	for _, fd := range fds {
		_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
	}

	prof := &model.Profile{Entity: entity, Node: c.a.cfg.Node, Duration: d, Hz: hz}
	folded := map[string]*model.Stack{}
	defer c.sym.Forget()

	var (
		k   bpf.ProfileSampleKey
		cnt uint64
	)
	it := c.objs.Samples.Iterate()
	for it.Next(&k, &cnt) {
		prof.Samples += cnt
		var frames []string
		// user frames (leaf first) then kernel frames (leaf first); we
		// produce root-first order at the end.
		var leafFirst []string
		if k.Kstack >= 0 {
			for _, addr := range c.stack(uint32(k.Kstack)) {
				leafFirst = append(leafFirst, c.sym.Kernel(addr)+"_[k]")
			}
		}
		if k.Ustack >= 0 {
			for _, addr := range c.stack(uint32(k.Ustack)) {
				leafFirst = append(leafFirst, c.sym.User(k.Tgid, addr))
			}
		}
		comm := cstr(k.Comm[:])
		frames = append(frames, comm)
		for i := len(leafFirst) - 1; i >= 0; i-- {
			frames = append(frames, leafFirst[i])
		}
		key := strings.Join(frames, ";")
		if st, ok := folded[key]; ok {
			st.Count += cnt
		} else {
			folded[key] = &model.Stack{Comm: comm, Frames: frames, Count: cnt}
		}
	}
	for _, st := range folded {
		prof.Stacks = append(prof.Stacks, *st)
	}
	sort.Slice(prof.Stacks, func(i, j int) bool { return prof.Stacks[i].Count > prof.Stacks[j].Count })
	return prof, nil
}

func (c *profileCollector) stack(id uint32) []uint64 {
	var raw [127]uint64
	if err := c.objs.Stacks.Lookup(id, &raw); err != nil {
		return nil
	}
	var out []uint64
	for _, a := range raw {
		if a == 0 {
			break
		}
		out = append(out, a)
	}
	return out
}
