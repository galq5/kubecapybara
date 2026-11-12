package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/galq5/kubecapybara/internal/model"
)

// ControlPlaneComponent is the health of one control plane pod.
type ControlPlaneComponent struct {
	Role       string // etcd, apiserver, scheduler, controller-manager, dns
	Endpoint   Endpoint
	Restarts   int32
	CPUWait    float64 // share of runnable time waiting for CPU
	Throttled  float64
	MemPct     float64
	DiskP99    float64 // us
	FsyncP99   float64 // us, from slow fsyncs (etcd WAL); 0 if unknown
	FsyncSlow  uint64
	DNSP99     float64 // dns servers
	DNSErrRate float64
	Problems   []string
}

func roleOf(e *EntityView) string {
	if e.Pod == nil {
		return ""
	}
	l, name := e.Pod.Labels, e.Pod.Name
	switch {
	case l["component"] == "etcd" || strings.HasPrefix(name, "etcd-"):
		return "etcd"
	case l["component"] == "kube-apiserver" || strings.HasPrefix(name, "kube-apiserver"):
		return "apiserver"
	case l["component"] == "kube-scheduler" || strings.HasPrefix(name, "kube-scheduler"):
		return "scheduler"
	case l["component"] == "kube-controller-manager" || strings.HasPrefix(name, "kube-controller-manager"):
		return "controller-manager"
	case l["k8s-app"] == "kube-dns" || strings.HasPrefix(name, "coredns"):
		return "dns"
	}
	return ""
}

// ControlPlane reports etcd, API server, scheduler, controller manager and
// cluster DNS pods with the signals that matter for each.
func ControlPlane(v *View) []ControlPlaneComponent {
	var out []ControlPlaneComponent
	for _, e := range v.PodEntities() {
		role := roleOf(e)
		if role == "" {
			continue
		}
		c := ControlPlaneComponent{Role: role, Endpoint: e.Endpoint}
		for _, ct := range e.Pod.Containers {
			c.Restarts += ct.Restarts
		}
		s := e.Stats
		if sc := s.Sched; sc != nil {
			q := float64(sc.OffNs[model.StateRunQ])
			c.CPUWait = ratio(q, q+float64(sc.OnCPUNs))
		}
		if r := s.Res; r != nil {
			c.Throttled = ratio(float64(r.Throttled), float64(r.Periods))
			if r.MemMax > 0 {
				c.MemPct = float64(r.MemCurrent) / float64(r.MemMax)
			}
		}
		if io := s.IO; io != nil && io.Lat.Count > 0 {
			c.DiskP99 = io.Lat.P99()
		}
		for _, f := range s.Files {
			if f.Fsyncs > 0 {
				c.FsyncSlow += f.Fsyncs
				if float64(f.MaxNs)/1e3 > c.FsyncP99 {
					c.FsyncP99 = float64(f.MaxNs) / 1e3
				}
			}
		}
		if d := s.DNSServer; d != nil && d.Queries > 0 {
			c.DNSP99 = d.Lat.P99()
			c.DNSErrRate = ratio(float64(d.RCodes["SERVFAIL"]+d.Timeouts), float64(d.Queries))
		}
		if c.Restarts > 0 {
			c.Problems = append(c.Problems, fmt.Sprintf("%d restarts", c.Restarts))
		}
		if c.CPUWait > 0.1 {
			c.Problems = append(c.Problems, "waits for CPU "+Pct(c.CPUWait))
		}
		if c.Throttled > 0.1 {
			c.Problems = append(c.Problems, "CPU throttled "+Pct(c.Throttled))
		}
		if c.MemPct > 0.9 {
			c.Problems = append(c.Problems, "memory at "+Pct(c.MemPct)+" of limit")
		}
		if role == "etcd" {
			// etcd wants WAL fsyncs well under 10ms; slow ones cause leader
			// elections and API server timeouts
			if c.FsyncP99 > 10e3 {
				c.Problems = append(c.Problems, fmt.Sprintf("%d slow fsyncs, worst %s (etcd needs < 10ms)", c.FsyncSlow, Dur(c.FsyncP99)))
			} else if c.DiskP99 > 10e3 {
				c.Problems = append(c.Problems, "disk p99 "+Dur(c.DiskP99)+" (etcd needs < 10ms fsync)")
			}
		}
		if role == "dns" && (c.DNSP99 > 50e3 || c.DNSErrRate > 0.01) {
			c.Problems = append(c.Problems, fmt.Sprintf("DNS p99 %s, SERVFAIL/timeouts %s", Dur(c.DNSP99), Pct(c.DNSErrRate)))
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Endpoint.Display() < out[j].Endpoint.Display()
	})
	return out
}

func ruleControlPlane(v *View) []Finding {
	var lines []string
	sev := SevWarn
	for _, c := range ControlPlane(v) {
		if len(c.Problems) == 0 {
			continue
		}
		if c.Role == "etcd" && c.FsyncP99 > 100e3 {
			sev = SevCrit
		}
		lines = append(lines, fmt.Sprintf("%s %s: %s", c.Role, c.Endpoint.Display(), strings.Join(c.Problems, ", ")))
	}
	if len(lines) == 0 {
		return nil
	}
	return []Finding{{Severity: sev, Category: "control-plane", Title: "control plane components degraded", Detail: top(lines, 10),
		Hint:  "a slow etcd or starved API server slows down every kubectl, controller and deploy: give them dedicated CPU and fast disks; for cluster DNS see `kubectl capybara dns`",
		Score: float64(len(lines))}}
}

func ruleNodeNetwork(v *View) []Finding {
	var lines []string
	var score float64
	for _, n := range v.Nodes {
		s := n.Stats
		for name, nic := range s.NICs {
			if bad := nic.RxErrors + nic.TxErrors + nic.RxMissed + nic.RxDropped + nic.TxDropped; bad > 0 {
				lines = append(lines, fmt.Sprintf("%s/%s: rx errors %d, missed %d, dropped %d; tx errors %d, dropped %d",
					n.Name, name, nic.RxErrors, nic.RxMissed, nic.RxDropped, nic.TxErrors, nic.TxDropped))
				score += float64(bad)
			}
		}
		if s.SoftnetDropped > 0 {
			lines = append(lines, fmt.Sprintf("%s: %d packets dropped, input backlog full (raise net.core.netdev_max_backlog)", n.Name, s.SoftnetDropped))
			score += float64(s.SoftnetDropped)
		}
		if v.PerSec(s.SoftnetSqueezed) > 10 {
			lines = append(lines, fmt.Sprintf("%s: packet processing ran out of budget %s/s (raise net.core.netdev_budget)", n.Name, Rate(v.PerSec(s.SoftnetSqueezed))))
			score += v.PerSec(s.SoftnetSqueezed)
		}
		if s.NetRxTopShare > 0.6 && s.CPUs >= 4 {
			lines = append(lines, fmt.Sprintf("%s: %s of receive processing on CPU %d (enable RSS/RPS or irqbalance)", n.Name, Pct(s.NetRxTopShare), s.NetRxCPU))
			score++
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevWarn, Category: "network", Title: "node network stack losing packets or saturated", Detail: top(lines, 10),
		Hint: "NIC ring overflows and softirq saturation drop packets before any pod sees them: retransmits and latency follow", Score: score}}
}
