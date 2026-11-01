package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/galq5/kubecapybara/internal/model"
)

var hwEvents = []uint64{unix.PERF_COUNT_HW_CPU_CYCLES, unix.PERF_COUNT_HW_INSTRUCTIONS, unix.PERF_COUNT_HW_CACHE_REFERENCES, unix.PERF_COUNT_HW_CACHE_MISSES}

// openCounters opens one counter per CPU for event cfg, for a cgroup
// (cgroupFD >= 0) or the whole node (cgroupFD == -1).
func openCounters(cfg uint64, cgroupFD int) ([]int, error) {
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_HARDWARE,
		Config:      cfg,
		Size:        uint32(binary.Size(unix.PerfEventAttr{})),
		Read_format: unix.PERF_FORMAT_TOTAL_TIME_ENABLED | unix.PERF_FORMAT_TOTAL_TIME_RUNNING,
		Bits:        unix.PerfBitDisabled,
	}
	flags := unix.PERF_FLAG_FD_CLOEXEC
	pid := -1
	if cgroupFD >= 0 {
		flags |= unix.PERF_FLAG_PID_CGROUP
		pid = cgroupFD
	}
	var fds []int
	for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
		fd, err := unix.PerfEventOpen(&attr, pid, cpu, -1, flags)
		if err != nil {
			if errors.Is(err, unix.ENODEV) { // offline CPU
				continue
			}
			for _, f := range fds {
				unix.Close(f)
			}
			return nil, err
		}
		fds = append(fds, fd)
	}
	return fds, nil
}

// readScaled sums counters, scaling for the time they were not scheduled.
func readScaled(fds []int) uint64 {
	var total float64
	buf := make([]byte, 24)
	for _, fd := range fds {
		if n, err := unix.Read(fd, buf); err != nil || n < 24 {
			continue
		}
		v := binary.LittleEndian.Uint64(buf[0:])
		enabled := binary.LittleEndian.Uint64(buf[8:])
		running := binary.LittleEndian.Uint64(buf[16:])
		if running == 0 {
			continue
		}
		total += float64(v) * float64(enabled) / float64(running)
	}
	return uint64(total)
}

// Counters measures hardware counters of an entity (pod) and of the node.
func (a *Agent) Counters(ctx context.Context, entity string, d time.Duration) (*model.Counters, error) {
	uid, ok := strings.CutPrefix(entity, "pod:")
	if !ok {
		return nil, fmt.Errorf("counters are measured per pod (entity pod:<uid>)")
	}
	a.resolver.Scan()
	dir, ok := a.resolver.Pods()[uid]
	if !ok {
		return nil, fmt.Errorf("pod %s has no cgroup on node %s", uid, a.cfg.Node)
	}
	cg, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(cg)

	var all [][]int
	defer func() {
		for _, fds := range all {
			for _, fd := range fds {
				unix.Close(fd)
			}
		}
	}()
	for _, target := range []int{cg, -1} {
		for _, ev := range hwEvents {
			fds, err := openCounters(ev, target)
			if err != nil {
				return nil, fmt.Errorf("hardware counters unavailable on node %s (VMs often expose no PMU): %w", a.cfg.Node, err)
			}
			all = append(all, fds)
		}
	}
	for _, fds := range all {
		for _, fd := range fds {
			_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0)
		}
	}
	select {
	case <-time.After(d):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	for _, fds := range all {
		for _, fd := range fds {
			_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		}
	}
	return &model.Counters{
		Entity: entity, Node: a.cfg.Node, Duration: d,
		Cycles: readScaled(all[0]), Instructions: readScaled(all[1]), CacheRefs: readScaled(all[2]), CacheMisses: readScaled(all[3]),
		NodeCycles: readScaled(all[4]), NodeInstructions: readScaled(all[5]), NodeCacheRefs: readScaled(all[6]), NodeCacheMisses: readScaled(all[7]),
	}, nil
}
