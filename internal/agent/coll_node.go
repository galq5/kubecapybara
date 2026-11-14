package agent

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
)

// nodeCollector reads node level health: conntrack table usage and
// failures, load and pressure stall information.
type nodeCollector struct {
	a    *Agent
	prev map[string]uint64
}

func (c *nodeCollector) Name() string { return "node" }

func (c *nodeCollector) Start(a *Agent) error {
	c.a = a
	c.prev = map[string]uint64{}
	return nil
}

func (c *nodeCollector) proc(p ...string) string {
	return filepath.Join(append([]string{c.a.cfg.ProcRoot}, p...)...)
}

// conntrackStats sums the per-CPU rows of /proc/net/stat/nf_conntrack.
func conntrackStats(path string) map[string]uint64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return nil
	}
	header := strings.Fields(sc.Text())
	out := map[string]uint64{}
	for sc.Scan() {
		vals := strings.Fields(sc.Text())
		for i, v := range vals {
			if i >= len(header) {
				break
			}
			n, err := strconv.ParseUint(v, 16, 64)
			if err == nil && header[i] != "entries" {
				out[header[i]] += n
			}
		}
	}
	return out
}

func (c *nodeCollector) Collect(w *Window) {
	now := time.Now()
	ns := model.NodeStats{CPUs: len(onlineCPUs()), SampledAt: now}
	if b, err := os.ReadFile(c.proc("loadavg")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			ns.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	// pid 1's view is the host network namespace (hostPID)
	ns.ConntrackCount, _ = readUint(c.proc("sys/net/netfilter/nf_conntrack_count"))
	ns.ConntrackMax, _ = readUint(c.proc("sys/net/netfilter/nf_conntrack_max"))
	if st := conntrackStats(c.proc("1/net/stat/nf_conntrack")); st != nil {
		for k, dst := range map[string]*uint64{
			"insert_failed": &ns.ConntrackInsertFailed,
			"drop":          &ns.ConntrackDrop,
			"early_drop":    &ns.ConntrackEarlyDrop,
		} {
			if prev, ok := c.prev[k]; ok {
				*dst = sub(st[k], prev)
			}
			c.prev[k] = st[k]
		}
	}
	c.netStack(&ns)
	ns.PSICPU = readPSI(c.proc("pressure/cpu"))
	ns.PSIMem = readPSI(c.proc("pressure/memory"))
	ns.PSIIO = readPSI(c.proc("pressure/io"))
	w.Node.Merge(ns)
}

func (c *nodeCollector) Close() error { return nil }

// virtual interfaces of containers and overlays: their drops are reported
// by the drop collector per flow; NIC counters are for real devices
var virtualIf = []string{"lo", "veth", "cali", "cilium", "lxc", "flannel", "vxlan", "docker", "br-", "cni", "kube-", "tunl", "genev", "ifb", "dummy", "nodelocaldns", "virbr", "tap", "weave", "antrea", "ovs"}

func isVirtualIf(name string) bool {
	for _, p := range virtualIf {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (c *nodeCollector) delta(key string, cur uint64) uint64 {
	prev, ok := c.prev[key]
	c.prev[key] = cur
	if !ok {
		return 0
	}
	return sub(cur, prev)
}

// netStack reads NIC counters (sysfs of the host network namespace, the
// agent runs with hostNetwork), softnet drops/squeezes and the NET_RX
// softirq distribution over CPUs.
func (c *nodeCollector) netStack(ns *model.NodeStats) {
	entries, _ := os.ReadDir("/sys/class/net")
	for _, e := range entries {
		name := e.Name()
		if isVirtualIf(name) {
			continue
		}
		dir := filepath.Join("/sys/class/net", name, "statistics")
		r := func(f string) uint64 {
			v, _ := readUint(filepath.Join(dir, f))
			return c.delta("nic|"+name+"|"+f, v)
		}
		s := &model.NICStats{RxBytes: r("rx_bytes"), TxBytes: r("tx_bytes"), RxErrors: r("rx_errors"), TxErrors: r("tx_errors"),
			RxDropped: r("rx_dropped"), TxDropped: r("tx_dropped"), RxMissed: r("rx_missed_errors")}
		if ns.NICs == nil {
			ns.NICs = map[string]*model.NICStats{}
		}
		ns.NICs[name] = s
	}
	if b, err := os.ReadFile(c.proc("net/softnet_stat")); err == nil {
		var dropped, squeezed uint64
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 {
				d, _ := strconv.ParseUint(f[1], 16, 64)
				q, _ := strconv.ParseUint(f[2], 16, 64)
				dropped += d
				squeezed += q
			}
		}
		ns.SoftnetDropped = c.delta("softnet|dropped", dropped)
		ns.SoftnetSqueezed = c.delta("softnet|squeezed", squeezed)
	}
	if b, err := os.ReadFile(c.proc("softirqs")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || f[0] != "NET_RX:" {
				continue
			}
			var total, top uint64
			topCPU := 0
			for i, v := range f[1:] {
				n, _ := strconv.ParseUint(v, 10, 64)
				d := c.delta("netrx|"+strconv.Itoa(i), n)
				total += d
				if d > top {
					top, topCPU = d, i
				}
			}
			if total > 1000 && len(f)-1 >= 4 {
				ns.NetRxTopShare = float64(top) / float64(total)
				ns.NetRxCPU = topCPU
			}
		}
	}
}

// scanExistingListeners discovers sockets that were already listening when
// the agent started by reading /proc/<pid>/net/tcp{,6} once per network
// namespace of pod processes.
func scanExistingListeners(a *Agent) {
	entries, err := os.ReadDir(a.cfg.ProcRoot)
	if err != nil {
		return
	}
	seenNS := map[string]bool{}
	// hostNetwork pods share the host namespace: its sockets belong to host
	// processes (sshd, kubelet...), not to the pod
	hostNS, _ := os.Readlink(filepath.Join(a.cfg.ProcRoot, "1", "ns", "net"))
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		cg, err := a.resolver.ProcCgroupID(a.cfg.ProcRoot, uint32(pid))
		if err != nil {
			continue
		}
		info := a.resolver.Lookup(cg)
		if info.PodUID == "" {
			continue
		}
		nsLink, err := os.Readlink(filepath.Join(a.cfg.ProcRoot, e.Name(), "ns", "net"))
		if err != nil || seenNS[nsLink+info.Entity] || nsLink == hostNS {
			continue
		}
		seenNS[nsLink+info.Entity] = true
		comm, _ := os.ReadFile(filepath.Join(a.cfg.ProcRoot, e.Name(), "comm"))
		for _, f := range []string{"tcp", "tcp6"} {
			for _, l := range parseProcNetListen(filepath.Join(a.cfg.ProcRoot, e.Name(), "net", f)) {
				l.Entity = info.Entity
				l.Comm = strings.TrimSpace(string(comm))
				l.Time = time.Now()
				a.rec.Listen(l)
			}
		}
	}
}

// parseProcNetListen returns LISTEN sockets from a /proc/net/tcp style file.
func parseProcNetListen(path string) []model.Listen {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []model.Listen
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		hostport := strings.Split(fields[1], ":")
		if len(hostport) != 2 {
			continue
		}
		port, err := strconv.ParseUint(hostport[1], 16, 16)
		if err != nil {
			continue
		}
		out = append(out, model.Listen{Port: uint16(port), Addr: decodeProcAddr(hostport[0])})
	}
	return out
}

func decodeProcAddr(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return ""
	}
	// /proc/net/tcp stores addresses as host-endian 32-bit words
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b)).String()
	case 16:
		return netip.AddrFrom16([16]byte(b)).Unmap().String()
	}
	return fmt.Sprintf("%x", b)
}
