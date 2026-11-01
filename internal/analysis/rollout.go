package analysis

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// RolloutGroup is one ReplicaSet (revision) of a Deployment.
type RolloutGroup struct {
	Name     string
	Revision string
	Hash     string
	New      bool
	Pods     []*k8smeta.Pod
	M        RolloutMetrics
}

// RolloutMetrics aggregates the health of a set of pods.
type RolloutMetrics struct {
	Pods       int
	Ready      int
	Restarts   int32
	Crashes    int
	HTTPReq    uint64
	HTTP5xx    uint64
	HTTPLat    model.Hist // server side
	OutRTT     model.Hist // RTT of outgoing connections
	OutConnect model.Hist
	Refused    uint64
	Timeouts   uint64
	Retrans    uint64
	Resets     uint64
	DNSQueries uint64
	DNSErrors  uint64
	DNSLat     model.Hist
	CPUCores   float64
	MemBytes   uint64
	RunQ       model.Hist
	Throttled  uint64
	Periods    uint64
	InConnects uint64
	InRefused  uint64
}

// RolloutReport compares the newest revision with the previous ones.
type RolloutReport struct {
	Namespace, Deployment string
	Groups                []*RolloutGroup
	Rows                  []CompareRow
	Verdict               string
	Healthy               bool
}

// CompareRow is one metric of the comparison table.
type CompareRow struct {
	Metric   string
	Old, New string
	Bad      bool
	Note     string
}

// Rollout builds a comparison between ReplicaSets of a Deployment.
func Rollout(v *View, ns, deploy string) (*RolloutReport, error) {
	rep := &RolloutReport{Namespace: ns, Deployment: deploy}
	groups := map[string]*RolloutGroup{}
	for _, rs := range v.Meta.ReplicaSets {
		if rs.Namespace == ns && rs.Deployment == deploy {
			groups[rs.Hash] = &RolloutGroup{Name: rs.Name, Revision: rs.Revision, Hash: rs.Hash}
		}
	}
	for _, p := range v.Meta.Pods {
		if p.Namespace != ns || p.Workload != "Deployment/"+deploy {
			continue
		}
		g, ok := groups[p.TemplateHash]
		if !ok {
			g = &RolloutGroup{Name: p.OwnerName, Hash: p.TemplateHash}
			groups[p.TemplateHash] = g
		}
		g.Pods = append(g.Pods, p)
	}
	var list []*RolloutGroup
	for _, g := range groups {
		if len(g.Pods) > 0 {
			list = append(list, g)
		}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no running pods found for deployment %s/%s", ns, deploy)
	}
	sort.Slice(list, func(i, j int) bool {
		ri, _ := strconv.Atoi(list[i].Revision)
		rj, _ := strconv.Atoi(list[j].Revision)
		if ri != rj {
			return ri > rj
		}
		return newestPod(list[i].Pods) > newestPod(list[j].Pods)
	})
	list[0].New = true
	for _, g := range list {
		g.M = v.groupMetrics(g.Pods)
	}
	rep.Groups = list
	if len(list) == 1 {
		rep.Verdict = "only one revision is running: nothing to compare (showing its health)"
		rep.Rows = compare(RolloutMetrics{}, list[0].M, v)
		rep.Healthy = true
		for _, r := range rep.Rows {
			if r.Bad {
				rep.Healthy = false
			}
		}
		return rep, nil
	}
	var old RolloutMetrics
	for _, g := range list[1:] {
		old = mergeMetrics(old, g.M)
	}
	rep.Rows = compare(old, list[0].M, v)
	bad := 0
	for _, r := range rep.Rows {
		if r.Bad {
			bad++
		}
	}
	rep.Healthy = bad == 0
	if rep.Healthy {
		rep.Verdict = fmt.Sprintf("revision %s looks healthy compared to the previous revision(s)", list[0].Revision)
	} else {
		rep.Verdict = fmt.Sprintf("revision %s is worse than the previous revision(s) on %d metric(s)", list[0].Revision, bad)
	}
	return rep, nil
}

func newestPod(pods []*k8smeta.Pod) int64 {
	var t int64
	for _, p := range pods {
		if p.Created.Unix() > t {
			t = p.Created.Unix()
		}
	}
	return t
}

func (v *View) groupMetrics(pods []*k8smeta.Pod) RolloutMetrics {
	var m RolloutMetrics
	ids := map[string]bool{}
	for _, p := range pods {
		ids["pod:"+p.UID] = true
		m.Pods++
		ready := true
		for _, c := range p.Containers {
			if !c.Init {
				m.Restarts += c.Restarts
				ready = ready && c.Ready
			}
		}
		if ready {
			m.Ready++
		}
		e := v.Entities["pod:"+p.UID]
		if e == nil {
			continue
		}
		s := e.Stats
		for _, ep := range s.HTTP {
			if ep.Role == "server" {
				m.HTTPReq += ep.Count
				m.HTTP5xx += ep.Errors()
				m.HTTPLat.Add(ep.Lat)
			}
		}
		if d := s.DNS; d != nil {
			m.DNSQueries += d.Queries
			m.DNSErrors += d.RCodes["SERVFAIL"] + d.RCodes["REFUSED"] + d.Timeouts
			m.DNSLat.Add(d.Lat)
		}
		if sc := s.Sched; sc != nil {
			m.CPUCores += v.CoresUsed(sc)
			m.RunQ.Add(sc.RunQ)
		}
		if r := s.Res; r != nil {
			m.MemBytes += r.MemCurrent
			m.Throttled += r.Throttled
			m.Periods += r.Periods
		}
	}
	for _, c := range v.Crashes {
		if ids[c.Endpoint.ID] {
			m.Crashes++
		}
	}
	for _, e := range v.Edges {
		if ids[e.Client.ID] {
			m.OutRTT.Add(e.Stats.RTT)
			m.OutConnect.Add(e.Stats.Connect)
			m.Refused += e.Stats.Refused
			m.Timeouts += e.Stats.Timeouts
			m.Retrans += e.Stats.Retrans
			m.Resets += e.Stats.RstRcvd
		}
		if ids[e.Server.ID] {
			m.InConnects += e.Stats.Connects
		}
	}
	return m
}

func mergeMetrics(a, b RolloutMetrics) RolloutMetrics {
	a.Pods += b.Pods
	a.Ready += b.Ready
	a.Restarts += b.Restarts
	a.Crashes += b.Crashes
	a.HTTPReq += b.HTTPReq
	a.HTTP5xx += b.HTTP5xx
	a.HTTPLat.Add(b.HTTPLat)
	a.OutRTT.Add(b.OutRTT)
	a.OutConnect.Add(b.OutConnect)
	a.Refused += b.Refused
	a.Timeouts += b.Timeouts
	a.Retrans += b.Retrans
	a.Resets += b.Resets
	a.DNSQueries += b.DNSQueries
	a.DNSErrors += b.DNSErrors
	a.DNSLat.Add(b.DNSLat)
	a.CPUCores += b.CPUCores
	a.MemBytes += b.MemBytes
	a.RunQ.Add(b.RunQ)
	a.Throttled += b.Throttled
	a.Periods += b.Periods
	a.InConnects += b.InConnects
	a.InRefused += b.InRefused
	return a
}

func perPod(v float64, pods int) float64 {
	if pods == 0 {
		return 0
	}
	return v / float64(pods)
}

func compare(o, n RolloutMetrics, v *View) []CompareRow {
	var rows []CompareRow
	add := func(metric, old, nw string, bad bool, note string) {
		rows = append(rows, CompareRow{metric, old, nw, bad, note})
	}
	hasOld := o.Pods > 0
	oldS := func(s string) string {
		if !hasOld {
			return "-"
		}
		return s
	}
	add("pods ready", oldS(fmt.Sprintf("%d/%d", o.Ready, o.Pods)), fmt.Sprintf("%d/%d", n.Ready, n.Pods), n.Ready < n.Pods, "")
	add("restarts", oldS(fmt.Sprint(o.Restarts)), fmt.Sprint(n.Restarts), n.Restarts > o.Restarts && n.Restarts > 0, "")
	add("crashes (flight recorder)", oldS(fmt.Sprint(o.Crashes)), fmt.Sprint(n.Crashes), n.Crashes > 0, "")

	oe, ne := ratio(float64(o.HTTP5xx), float64(o.HTTPReq)), ratio(float64(n.HTTP5xx), float64(n.HTTPReq))
	if o.HTTPReq+n.HTTPReq > 0 {
		add("HTTP requests/s per pod", oldS(Rate(perPod(v.PerSec(o.HTTPReq), o.Pods))), Rate(perPod(v.PerSec(n.HTTPReq), n.Pods)), false, "")
		add("HTTP 5xx rate", oldS(Pct(oe)), Pct(ne), n.HTTPReq >= 10 && ne > 0.01 && ne > 2*oe, "")
		add("HTTP p99 latency", oldS(Dur(o.HTTPLat.P99())), Dur(n.HTTPLat.P99()), worse(o.HTTPLat, n.HTTPLat, 1.5, 10e3), "")
	}
	add("outgoing RTT p99", oldS(Dur(o.OutRTT.P99())), Dur(n.OutRTT.P99()), worse(o.OutRTT, n.OutRTT, 3, 1e3), "network to dependencies")
	add("outgoing connect p99", oldS(Dur(o.OutConnect.P99())), Dur(n.OutConnect.P99()), worse(o.OutConnect, n.OutConnect, 3, 1e3), "")
	add("refused connections", oldS(fmt.Sprint(o.Refused)), fmt.Sprint(n.Refused), n.Refused > 2*o.Refused+2, "")
	add("connect timeouts", oldS(fmt.Sprint(o.Timeouts)), fmt.Sprint(n.Timeouts), n.Timeouts > 2*o.Timeouts+1, "")
	add("retransmits/s", oldS(Rate(v.PerSec(o.Retrans))), Rate(v.PerSec(n.Retrans)), n.Retrans > 20 && v.PerSec(n.Retrans) > 3*v.PerSec(o.Retrans), "")
	if o.DNSQueries+n.DNSQueries > 0 {
		add("DNS failure rate", oldS(Pct(ratio(float64(o.DNSErrors), float64(o.DNSQueries)))), Pct(ratio(float64(n.DNSErrors), float64(n.DNSQueries))),
			n.DNSErrors > 2 && ratio(float64(n.DNSErrors), float64(n.DNSQueries)) > 2*ratio(float64(o.DNSErrors), float64(o.DNSQueries))+0.01, "")
		add("DNS p99", oldS(Dur(o.DNSLat.P99())), Dur(n.DNSLat.P99()), worse(o.DNSLat, n.DNSLat, 3, 10e3), "")
	}
	add("CPU cores per pod", oldS(fmt.Sprintf("%.3f", perPod(o.CPUCores, o.Pods))), fmt.Sprintf("%.3f", perPod(n.CPUCores, n.Pods)),
		hasOld && perPod(n.CPUCores, n.Pods) > 1.5*perPod(o.CPUCores, o.Pods) && perPod(n.CPUCores, n.Pods) > 0.05, "")
	add("memory per pod", oldS(Bytes(perPod(float64(o.MemBytes), o.Pods))), Bytes(perPod(float64(n.MemBytes), n.Pods)),
		hasOld && perPod(float64(n.MemBytes), n.Pods) > 1.5*perPod(float64(o.MemBytes), o.Pods) && n.MemBytes > 64<<20, "")
	add("CPU run queue p99", oldS(Dur(o.RunQ.P99())), Dur(n.RunQ.P99()), worse(o.RunQ, n.RunQ, 3, 10e3), "")
	add("CPU throttled periods", oldS(Pct(ratio(float64(o.Throttled), float64(o.Periods)))), Pct(ratio(float64(n.Throttled), float64(n.Periods))),
		ratio(float64(n.Throttled), float64(n.Periods)) > 0.25, "")
	return rows
}

func worse(o, n model.Hist, factor, floorUs float64) bool {
	if o.Count < 10 || n.Count < 10 {
		return false
	}
	return n.P99() > factor*o.P99() && n.P99() > floorUs
}
