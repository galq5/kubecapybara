package agent

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// onlineCPUs returns the IDs of the node's online CPUs. runtime.NumCPU is
// not a substitute: it counts the CPUs the agent may run on (its affinity
// mask), which excludes CPUs pinned to Guaranteed pods by the static CPU
// manager policy, and CPU IDs need not be contiguous.
func onlineCPUs() []int {
	if b, err := os.ReadFile("/sys/devices/system/cpu/online"); err == nil {
		if cpus := parseCPUList(string(b)); len(cpus) > 0 {
			return cpus
		}
	}
	cpus := make([]int, runtime.NumCPU())
	for i := range cpus {
		cpus[i] = i
	}
	return cpus
}

// parseCPUList parses the kernel's CPU list format ("0-3,8,10-11").
func parseCPUList(s string) []int {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return nil
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return nil
			}
		}
		for c := a; c <= b; c++ {
			out = append(out, c)
		}
	}
	return out
}
