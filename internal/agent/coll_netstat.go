package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/galq5/kubecapybara/internal/model"
)

// netstatCollector reads TcpExt counters (/proc/<pid>/net/netstat) of every
// pod network namespace: accept queue overflows, zero window and receive
// queue drops, RTO timeouts. These are exact kernel counters per pod.
type netstatCollector struct {
	a    *Agent
	prev map[string]map[string]uint64 // entity -> counter -> value
}

func (c *netstatCollector) Name() string { return "netstat" }

func (c *netstatCollector) Start(a *Agent) error {
	c.a = a
	c.prev = map[string]map[string]uint64{}
	return nil
}

// tcpExt parses the TcpExt header/value line pair of a netstat file.
func tcpExt(path string) map[string]uint64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var header []string
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || fields[0] != "TcpExt:" {
			continue
		}
		if header == nil {
			header = fields[1:]
			continue
		}
		out := make(map[string]uint64, len(header))
		for i, v := range fields[1:] {
			if i < len(header) {
				n, _ := strconv.ParseUint(v, 10, 64)
				out[header[i]] = n
			}
		}
		return out
	}
	return nil
}

// podPid returns one process of a pod (any leaf cgroup with processes).
func podPid(dir string) string {
	var pid string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || pid != "" || !d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(filepath.Join(p, "cgroup.procs"))
		if err == nil {
			if f := strings.Fields(string(b)); len(f) > 0 {
				pid = f[0]
				return filepath.SkipAll
			}
		}
		return nil
	})
	return pid
}

func (c *netstatCollector) Collect(w *Window) {
	hostNS, _ := os.Readlink(filepath.Join(c.a.cfg.ProcRoot, "1", "ns", "net"))
	seen := map[string]bool{}
	for uid, dir := range c.a.resolver.Pods() {
		pid := podPid(dir)
		if pid == "" {
			continue
		}
		ns, err := os.Readlink(filepath.Join(c.a.cfg.ProcRoot, pid, "ns", "net"))
		if err != nil || ns == hostNS { // hostNetwork pods: counters are the node's
			continue
		}
		cur := tcpExt(filepath.Join(c.a.cfg.ProcRoot, pid, "net", "netstat"))
		if cur == nil {
			continue
		}
		entity := "pod:" + uid
		seen[entity] = true
		prev, ok := c.prev[entity]
		c.prev[entity] = cur
		if !ok {
			continue
		}
		d := func(k string) uint64 { return sub(cur[k], prev[k]) }
		ns2 := &model.NetStats{
			ListenOverflows: d("ListenOverflows"),
			ListenDrops:     d("ListenDrops"),
			ZeroWindowDrops: d("TCPZeroWindowDrop"),
			ToZeroWindowAdv: d("TCPToZeroWindowAdv"),
			RcvQueueDrops:   d("TCPRcvQDrop"),
			BacklogDrops:    d("TCPBacklogDrop"),
			Timeouts:        d("TCPTimeouts"),
		}
		if *ns2 == (model.NetStats{}) {
			continue
		}
		e := w.Entity(entity)
		if e.Net == nil {
			e.Net = &model.NetStats{}
		}
		e.Net.Merge(ns2)
	}
	for k := range c.prev {
		if !seen[k] {
			delete(c.prev, k)
		}
	}
}

func (c *netstatCollector) Close() error { return nil }
