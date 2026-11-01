package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
)

// cgroupfsCollector reads per-pod cgroup v2 statistics: memory, CPU usage,
// CFS throttling, OOM kill counters and pressure stall information.
type cgroupfsCollector struct {
	a    *Agent
	prev map[string]cgCounters
}

type cgCounters struct {
	at          time.Time
	usageUs     uint64
	periods     uint64
	throttled   uint64
	throttledUs uint64
	oomKills    uint64
}

func (c *cgroupfsCollector) Name() string { return "cgroupfs" }

func (c *cgroupfsCollector) Start(a *Agent) error {
	c.a = a
	c.prev = map[string]cgCounters{}
	return nil
}

func readUint(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0, true
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

func readKV(path string) map[string]uint64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 {
			if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				out[fields[0]] = v
			}
		}
	}
	return out
}

// readPSI returns the "some avg10" value of a pressure file.
func readPSI(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, "avg10="); ok {
				x, _ := strconv.ParseFloat(v, 64)
				return x
			}
		}
	}
	return 0
}

func readCPUMax(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) != 2 || f[0] == "max" {
		return 0
	}
	quota, err1 := strconv.ParseFloat(f[0], 64)
	period, err2 := strconv.ParseFloat(f[1], 64)
	if err1 != nil || err2 != nil || period == 0 {
		return 0
	}
	return uint64(quota / period * 1000)
}

func (c *cgroupfsCollector) Collect(w *Window) {
	now := time.Now()
	seen := map[string]bool{}
	for uid, dir := range c.a.resolver.Pods() {
		if _, err := os.Stat(filepath.Join(dir, "cgroup.procs")); err != nil {
			continue
		}
		entity := "pod:" + uid
		seen[entity] = true
		mem, _ := readUint(filepath.Join(dir, "memory.current"))
		memMax, _ := readUint(filepath.Join(dir, "memory.max"))
		cpu := readKV(filepath.Join(dir, "cpu.stat"))
		events := readKV(filepath.Join(dir, "memory.events"))
		peak, _ := readUint(filepath.Join(dir, "memory.peak"))
		cur := cgCounters{
			at:          now,
			usageUs:     cpu["usage_usec"],
			periods:     cpu["nr_periods"],
			throttled:   cpu["nr_throttled"],
			throttledUs: cpu["throttled_usec"],
			oomKills:    events["oom_kill"],
		}
		res := &model.Resources{
			MemCurrent:    mem,
			MemMax:        memMax,
			MemPeak:       peak,
			CPUQuotaMilli: readCPUMax(filepath.Join(dir, "cpu.max")),
			PSICPU:        readPSI(filepath.Join(dir, "cpu.pressure")),
			PSIMem:        readPSI(filepath.Join(dir, "memory.pressure")),
			PSIIO:         readPSI(filepath.Join(dir, "io.pressure")),
			SampledAt:     now,
		}
		if prev, ok := c.prev[entity]; ok {
			res.CPUUsageUs = sub(cur.usageUs, prev.usageUs)
			res.Periods = sub(cur.periods, prev.periods)
			res.Throttled = sub(cur.throttled, prev.throttled)
			res.ThrottledUs = sub(cur.throttledUs, prev.throttledUs)
			res.OOMKills = sub(cur.oomKills, prev.oomKills)
			res.WallUs = uint64(now.Sub(prev.at).Microseconds())
			if res.OOMKills > 0 {
				c.a.rec.Add(model.Event{
					Time: now, Entity: entity, Type: model.EvOOM, Severity: model.SevCrit,
					Message: "memory.events reports an OOM kill in this pod (limit " + humanBytes(memMax) + ")",
				})
				c.a.rec.Crash(entity, "OOM killed (memory.events)", now)
			}
		}
		c.prev[entity] = cur

		sample := model.ResourceSample{Time: now, MemCurrent: mem, MemMax: memMax}
		if res.WallUs > 0 {
			sample.CPUMilli = float64(res.CPUUsageUs) / float64(res.WallUs) * 1000
			res.CPUPeakMilli = sample.CPUMilli
		}
		if res.Periods > 0 {
			sample.ThrottledPct = float64(res.Throttled) / float64(res.Periods) * 100
		}
		e := w.Entity(entity)
		e.PodUID = uid
		if e.Res == nil {
			e.Res = &model.Resources{}
		}
		e.Res.Merge(res)

		c.a.rec.Sample(entity, sample)
	}
	for k := range c.prev {
		if !seen[k] {
			delete(c.prev, k)
		}
	}
}

func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

func humanBytes(b uint64) string {
	if b == 0 {
		return "unlimited"
	}
	const unit = 1024
	if b < unit {
		return strconv.FormatUint(b, 10) + "B"
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(b)/float64(div), 'f', 1, 64) + string("KMGTPE"[exp]) + "i"
}

func (c *cgroupfsCollector) Close() error { return nil }
