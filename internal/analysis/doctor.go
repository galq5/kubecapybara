package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
)

// Severity of a finding.
type Severity int

const (
	SevInfo Severity = iota
	SevWarn
	SevCrit
)

func (s Severity) String() string {
	switch s {
	case SevCrit:
		return "CRIT"
	case SevWarn:
		return "WARN"
	}
	return "INFO"
}

// Finding is one diagnosis produced by Doctor.
type Finding struct {
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Detail   []string `json:"detail,omitempty"`
	Hint     string   `json:"hint,omitempty"`
	Subjects []string `json:"subjects,omitempty"` // entity IDs involved
	Score    float64  `json:"score"`
	// Rule identifies the rule that produced the finding (stable across
	// runs, e.g. "dns-ndots"); used to track findings over time.
	Rule string `json:"rule"`
}

// benign drop reasons that happen during normal operation
var benignDrops = map[string]bool{
	"QUEUE_PURGE": true, "SOCKET_CLOSE": true, "TCP_CLOSE": true, "NOT_SPECIFIED": true,
	"PKT_TOO_SMALL": false, "OTHERHOST": true, "UNHANDLED_PROTO": true, "TCP_OLD_DATA": true,
	"TCP_OFO_DROP": true, "TCP_ZEROWINDOW": false, "SOCKET_FILTER": true, "TCP_OLD_ACK": true,
	"TCP_FLAGS": true, "TCP_RESET": true, "TCP_INVALID_SEQUENCE": true, "TCP_OLD_SEQUENCE": true,
	"DUP_FRAG": true, "FRAG_REASM_TIMEOUT": false, "IP_INNOHDR": true, "SKB_CONSUMED": true,
}

// BenignDrop reports whether a drop reason is part of normal operation.
func BenignDrop(reason string) bool { return benignDrops[reason] }

var badDrops = map[string]string{
	"NETFILTER_DROP":  "dropped by netfilter (NetworkPolicy, iptables/nftables rules or a full conntrack table)",
	"SOCKET_RCVBUFF":  "socket receive buffer full: the application is not reading fast enough",
	"PROTO_MEM":       "TCP memory pressure (net.ipv4.tcp_mem exhausted)",
	"QDISC_DROP":      "egress queue (qdisc) overflow",
	"CPU_BACKLOG":     "per-CPU input backlog full (net.core.netdev_max_backlog)",
	"FULL_RING":       "NIC ring buffer full",
	"NEIGH_FAILED":    "ARP/ND resolution failed (dead peer or bad routing)",
	"NEIGH_QUEUEFULL": "ARP/ND queue full",
	"IP_NOROUTE":      "no route to destination",
	"NO_SOCKET":       "nothing listening on the destination port",
	"TC_DROP":         "dropped by a tc program (CNI dataplane / policy)",
	"XDP_DROP":        "dropped by an XDP program",
	"OVS_DROP":        "dropped by Open vSwitch",
	"TCP_ZEROWINDOW":  "receiver advertised a zero window (slow consumer)",
}

// rule is a named doctor rule.
type rule struct {
	id string
	fn func(*View) []Finding
}

var rules = []rule{
	{"crash", ruleCrashes}, {"restarts", ruleRestarts}, {"memory", ruleOOMAndMemory}, {"dns-ndots", ruleNdots},
	{"dns-errors", ruleDNSErrors}, {"dns-slow", ruleDNSSlow}, {"refused", ruleRefused}, {"connect-timeouts", ruleTimeouts},
	{"retransmits", ruleRetrans}, {"mtu", ruleMTU}, {"drops", ruleDrops}, {"conntrack", ruleConntrack},
	{"connect-errors", ruleConnErrors}, {"churn", ruleChurn}, {"cross-zone", ruleCrossZone}, {"apiserver-load", ruleAPIServer},
	{"cpu-runqueue", ruleRunQ}, {"cpu-throttling", ruleThrottle}, {"disk-latency", ruleDisk}, {"http", ruleHTTP},
	{"exec-shell", ruleSecurity}, {"undeclared-ports", ruleUndeclaredPorts}, {"internet-egress", ruleExternalEgress},
	{"collectors", ruleCollectors}, {"oom-risk", ruleOOMRisk}, {"policy-denials", rulePolicyDenials},
	{"accept-queue", ruleAcceptQueue}, {"zero-window", ruleZeroWindow}, {"slow-node", ruleSlowNodes},
	{"service-balance", ruleServiceBalance}, {"rightsizing", ruleRightsizing}, {"db", ruleDB}, {"files", ruleFiles},
	{"outlier-replica", ruleOutliers}, {"control-plane", ruleControlPlane}, {"node-network", ruleNodeNetwork},
	{"voip", ruleVoIP},
}

// Doctor runs all rules. base may be nil; when present regressions are
// detected by comparing the current window with the baseline window.
func Doctor(v *View, base *View) []Finding { return DoctorWith(v, base, nil) }

// DoctorWith runs all rules plus SLO burn rate checks.
func DoctorWith(v *View, base *View, slos []SLO) []Finding {
	var out []Finding
	add := func(id string, fs []Finding) {
		for i := range fs {
			if fs[i].Rule == "" {
				fs[i].Rule = id
			}
		}
		out = append(out, fs...)
	}
	for _, r := range rules {
		add(r.id, r.fn(v))
	}
	add("pools", rulePools(v, base))
	if base != nil {
		add("regression", Regressions(v, base))
	}
	if len(slos) > 0 {
		add("slo-burn", SLOFindings(EvaluateSLOs(v, base, slos)))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func top[T any](items []T, n int) []T {
	if len(items) > n {
		return items[:n]
	}
	return items
}

func edgeName(e *Edge) string {
	return fmt.Sprintf("%s → %s:%d", e.Client.Display(), e.Server.Display(), e.Port)
}

// ---------------------------------------------------------------- crashes

func ruleCrashes(v *View) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, c := range v.Crashes {
		if seen[c.Endpoint.ID] {
			continue
		}
		seen[c.Endpoint.ID] = true
		f := Finding{
			Severity: SevCrit, Category: "crash",
			Title:    fmt.Sprintf("%s crashed %s: %s", c.Endpoint.Display(), Ago(c.Time), c.Reason),
			Hint:     fmt.Sprintf("kubectl capybara why-crash %s", c.Endpoint.Display()),
			Subjects: []string{c.Endpoint.ID},
			Score:    float64(c.Time.Unix()),
		}
		for _, e := range lastN(c.Events, 4) {
			f.Detail = append(f.Detail, fmt.Sprintf("%s  %s", e.Time.Format("15:04:05.000"), e.Message))
		}
		out = append(out, f)
	}
	return out
}

func lastN(evs []model.Event, n int) []model.Event {
	if len(evs) > n {
		return evs[len(evs)-n:]
	}
	return evs
}

func ruleRestarts(v *View) []Finding {
	var lines []string
	var subjects []string
	for _, p := range v.Meta.Pods {
		for _, c := range p.Containers {
			if c.StateReason == "CrashLoopBackOff" || (c.Restarts >= 3 && !c.LastFinished.IsZero() && c.LastFinished.After(v.From.Add(-30*time.Minute))) {
				lines = append(lines, fmt.Sprintf("%s/%s container %s: %d restarts, last %s (exit %d) %s",
					p.Namespace, p.Name, c.Name, c.Restarts, c.LastReason, c.LastExitCode, Ago(c.LastFinished)))
				subjects = append(subjects, "pod:"+p.UID)
			}
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{
		Severity: SevCrit, Category: "crash",
		Title:    fmt.Sprintf("%d container(s) restarting repeatedly", len(lines)),
		Detail:   top(lines, 10),
		Hint:     "kubectl capybara why-crash <pod> shows the flight recorder from the last crash",
		Subjects: subjects, Score: float64(len(lines)),
	}}
}

func ruleOOMAndMemory(v *View) []Finding {
	var out []Finding
	var near []string
	var reclaim []string
	for _, e := range v.PodEntities() {
		if r := e.Stats.Res; r != nil && r.MemMax > 0 {
			ratio := float64(r.MemCurrent) / float64(r.MemMax)
			if ratio >= 0.9 {
				near = append(near, fmt.Sprintf("%s: %s of %s (%s)", e.Endpoint.Display(), Bytes(float64(r.MemCurrent)), Bytes(float64(r.MemMax)), Pct(ratio)))
			}
		}
		if s := e.Stats.Sched; s != nil && s.ReclaimNs > 100e6 {
			reclaim = append(reclaim, fmt.Sprintf("%s: %s stalled in direct reclaim (%d stalls)", e.Endpoint.Display(), Dur(float64(s.ReclaimNs)/1e3), s.ReclaimCount))
		}
	}
	if len(near) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "memory",
			Title:  fmt.Sprintf("%d pod(s) above 90%% of their memory limit", len(near)),
			Detail: top(near, 10), Hint: "raise memory limits or fix the leak before the OOM killer does", Score: float64(len(near))})
	}
	if len(reclaim) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "memory",
			Title:  "pods stalled by direct memory reclaim (latency spikes)",
			Detail: top(reclaim, 10), Hint: "memory pressure on the cgroup or node; check limits and page cache usage", Score: float64(len(reclaim))})
	}
	return out
}

// ---------------------------------------------------------------- dns

func ruleNdots(v *View) []Finding {
	type item struct {
		e     *EntityView
		waste uint64
		q     uint64
	}
	var items []item
	var total uint64
	for _, e := range v.Entities {
		d := e.Stats.DNS
		if d == nil || d.NdotsWaste < 3 || float64(d.NdotsWaste) < 0.1*float64(d.Queries) {
			continue
		}
		items = append(items, item{e, d.NdotsWaste, d.Queries})
		total += d.NdotsWaste
	}
	if len(items) == 0 {
		return nil
	}
	sort.Slice(items, func(i, j int) bool { return items[i].waste > items[j].waste })
	f := Finding{
		Severity: SevWarn, Category: "dns",
		Title: fmt.Sprintf("ndots:5 search-path expansion wastes %s DNS lookups/s across %d workload(s)", Rate(v.PerSec(total)), len(items)),
		Hint: `names with dots (e.g. api.stripe.com) are first tried with every search domain and return NXDOMAIN. ` +
			`Set spec.dnsConfig.options: [{name: ndots, value: "2"}] or use fully qualified names with a trailing dot`,
		Score: float64(total),
	}
	for _, it := range top(items, 10) {
		f.Detail = append(f.Detail, fmt.Sprintf("%s: %d of %d queries wasted (%s), e.g. %s",
			it.e.Endpoint.Display(), it.waste, it.q, Pct(ratio(float64(it.waste), float64(it.q))), exampleNX(it.e.Stats.DNS, v.Opts.ClusterDomain)))
		f.Subjects = append(f.Subjects, it.e.ID)
	}
	return []Finding{f}
}

func exampleNX(d *model.DNSStats, cd string) string {
	best, n := "", uint64(0)
	for name, s := range d.Names {
		if s.NXDomain > n && strings.HasSuffix(name, cd) {
			best, n = name, s.NXDomain
		}
	}
	return best
}

func ruleDNSErrors(v *View) []Finding {
	var lines []string
	var subj []string
	sev := SevWarn
	for _, e := range v.Entities {
		d := e.Stats.DNS
		if d == nil || d.Queries < 5 {
			continue
		}
		bad := d.RCodes["SERVFAIL"] + d.RCodes["REFUSED"] + d.Timeouts
		r := ratio(float64(bad), float64(d.Queries))
		if bad < 3 || r < 0.02 {
			continue
		}
		if r > 0.2 {
			sev = SevCrit
		}
		var worst []string
		for name, s := range d.Names {
			if s.Errors+s.Timeouts > 0 {
				worst = append(worst, fmt.Sprintf("%s(%d)", name, s.Errors+s.Timeouts))
			}
		}
		sort.Strings(worst)
		lines = append(lines, fmt.Sprintf("%s: %s of lookups failing (SERVFAIL %d, REFUSED %d, timeout %d) %s",
			e.Endpoint.Display(), Pct(r), d.RCodes["SERVFAIL"], d.RCodes["REFUSED"], d.Timeouts, strings.Join(top(worst, 3), " ")))
		subj = append(subj, e.ID)
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{Severity: sev, Category: "dns", Title: fmt.Sprintf("DNS failures in %d workload(s)", len(lines)),
		Detail: top(lines, 10), Hint: "check CoreDNS health/logs, upstream resolvers and NetworkPolicies allowing UDP/TCP 53",
		Subjects: subj, Score: float64(len(lines))}}
}

func ruleDNSSlow(v *View) []Finding {
	var out []Finding
	var slow []string
	for _, e := range v.Entities {
		d := e.Stats.DNS
		if d == nil || d.Lat.Count < 20 {
			continue
		}
		if p99 := d.Lat.P99(); p99 > 100e3 {
			slow = append(slow, fmt.Sprintf("%s: p99 %s (p50 %s, %d lookups)", e.Endpoint.Display(), Dur(p99), Dur(d.Lat.P50()), d.Lat.Count))
		}
	}
	if len(slow) > 0 {
		sort.Strings(slow)
		out = append(out, Finding{Severity: SevWarn, Category: "dns", Title: "slow DNS resolution",
			Detail: top(slow, 10), Hint: "consider NodeLocal DNSCache, more CoreDNS replicas, or fixing ndots expansion", Score: float64(len(slow))})
	}
	// server side: CoreDNS replica outliers
	type srv struct {
		name string
		p99  float64
		n    uint64
	}
	var servers []srv
	for _, e := range v.Entities {
		if d := e.Stats.DNSServer; d != nil && d.Lat.Count >= 20 {
			servers = append(servers, srv{e.Endpoint.Display(), d.Lat.P99(), d.Lat.Count})
		}
	}
	if len(servers) >= 2 {
		sort.Slice(servers, func(i, j int) bool { return servers[i].p99 < servers[j].p99 })
		median := servers[len(servers)/2].p99
		for _, s := range servers {
			if s.p99 > 3*median && s.p99 > 20e3 {
				out = append(out, Finding{Severity: SevWarn, Category: "dns",
					Title: fmt.Sprintf("DNS server replica %s is slow: p99 %s vs median %s", s.name, Dur(s.p99), Dur(median)),
					Hint:  "the replica may be CPU throttled or on a noisy node; check its CPU limits and node", Score: s.p99})
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- tcp

func ruleRefused(v *View) []Finding {
	var edges []*Edge
	var total uint64
	for _, e := range v.Edges {
		if e.Stats.Refused >= 3 {
			edges = append(edges, e)
			total += e.Stats.Refused
		}
	}
	if len(edges) == 0 {
		return nil
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].Stats.Refused > edges[j].Stats.Refused })
	f := Finding{Severity: SevWarn, Category: "network",
		Title: fmt.Sprintf("%d connection attempts refused (%s/s)", total, Rate(v.PerSec(total))),
		Hint:  "nothing is listening on the target port: wrong targetPort, app not started yet, or a Service without ready endpoints",
		Score: float64(total)}
	for _, e := range top(edges, 10) {
		f.Detail = append(f.Detail, fmt.Sprintf("%s refused %d times", edgeName(e), e.Stats.Refused))
		f.Subjects = append(f.Subjects, e.Client.ID)
	}
	return []Finding{f}
}

func ruleTimeouts(v *View) []Finding {
	var edges []*Edge
	for _, e := range v.Edges {
		if e.Stats.Timeouts >= 2 {
			edges = append(edges, e)
		}
	}
	if len(edges) == 0 {
		return nil
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].Stats.Timeouts > edges[j].Stats.Timeouts })
	f := Finding{Severity: SevWarn, Category: "network",
		Title: fmt.Sprintf("connection attempts timing out on %d path(s)", len(edges)),
		Hint:  "SYNs are silently dropped: NetworkPolicy, security groups/firewall, a dead node or an overloaded listen backlog",
		Score: float64(len(edges))}
	for _, e := range top(edges, 10) {
		f.Detail = append(f.Detail, fmt.Sprintf("%s: %d timeouts, %d SYN retransmits", edgeName(e), e.Stats.Timeouts, e.Stats.SynRetrans))
	}
	return []Finding{f}
}

func ruleRetrans(v *View) []Finding {
	var out []Finding
	// per node
	nodeRetrans := map[string]uint64{}
	nodeSamples := map[string]uint64{}
	for _, e := range v.Edges {
		for _, n := range []string{e.Client.Node, e.Server.Node} {
			if n == "" {
				continue
			}
			nodeRetrans[n] += e.Stats.Retrans
			nodeSamples[n] += e.Stats.RTT.Count + e.Stats.Connects
		}
	}
	if len(nodeRetrans) >= 3 {
		var vals []float64
		for _, r := range nodeRetrans {
			vals = append(vals, float64(r))
		}
		sort.Float64s(vals)
		median := vals[len(vals)/2]
		for n, r := range nodeRetrans {
			if float64(r) > 3*median && v.PerSec(r) > 0.2 {
				out = append(out, Finding{Severity: SevWarn, Category: "network",
					Title: fmt.Sprintf("node %s has elevated TCP retransmits: %s/s (cluster median %s/s)", n, Rate(v.PerSec(r)), Rate(median/v.Seconds())),
					Hint:  "suspect the node's NIC, its host network, or an overloaded node; compare with `kubectl capybara nodes`",
					Score: float64(r)})
			}
		}
	}
	// per edge
	var lines []string
	for _, e := range v.Edges {
		conns := e.Stats.Connects + e.Stats.RTT.Count
		if e.Stats.Retrans >= 20 && conns > 0 && float64(e.Stats.Retrans)/float64(conns) > 0.5 {
			lines = append(lines, fmt.Sprintf("%s: %d retransmits (%s/s), RTT p99 %s", edgeName(e), e.Stats.Retrans, Rate(v.PerSec(e.Stats.Retrans)), Dur(e.Stats.RTT.P99())))
		}
	}
	if len(lines) > 0 {
		sort.Strings(lines)
		out = append(out, Finding{Severity: SevWarn, Category: "network", Title: "lossy network paths (high retransmits)",
			Detail: top(lines, 10), Hint: "packet loss between these endpoints: congestion, a bad link, or drops (see the drops panel)", Score: float64(len(lines))})
	}
	return out
}

func ruleMTU(v *View) []Finding {
	var lines []string
	for _, e := range v.Edges {
		s := e.Stats
		if s.Retrans >= 10 && float64(s.RetransLarge) > 0.8*float64(s.Retrans) && (s.Timeouts > 0 || s.RTT.P99() > 200e3) {
			lines = append(lines, fmt.Sprintf("%s: %d of %d retransmits are full-size segments", edgeName(e), s.RetransLarge, s.Retrans))
		}
		if s.MTUReduced > 0 {
			lines = append(lines, fmt.Sprintf("%s: path MTU reduced %d time(s) (ICMP fragmentation needed)", edgeName(e), s.MTUReduced))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	return []Finding{{Severity: SevWarn, Category: "network", Title: "possible MTU problems (large packets lost, small ones pass)",
		Detail: top(lines, 10), Hint: "check overlay/VPN MTU settings (e.g. VXLAN needs 50 bytes headroom) and that ICMP 'frag needed' is not blocked", Score: float64(len(lines))}}
}

func ruleDrops(v *View) []Finding {
	byReason := map[string]uint64{}
	examples := map[string]*model.Drop{}
	for _, d := range v.Drops {
		if benignDrops[d.Reason] {
			continue
		}
		byReason[d.Reason] += d.Count
		if ex, ok := examples[d.Reason]; !ok || d.Count > ex.Count {
			examples[d.Reason] = d
		}
	}
	if len(byReason) == 0 {
		return nil
	}
	sev := SevInfo
	var lines []string
	var total uint64
	for _, r := range model.SortedKeys(byReason) {
		n := byReason[r]
		total += n
		desc, bad := badDrops[r]
		if bad && r != "NO_SOCKET" {
			sev = SevWarn
		}
		ex := examples[r]
		line := fmt.Sprintf("%s: %d (%s/s), e.g. %s → %s:%d/%s", r, n, Rate(v.PerSec(n)), v.IPEndpoint(ex.Src, "").Display(), v.IPEndpoint(ex.Dst, "").Display(), ex.Port, ex.Proto)
		if desc != "" {
			line += " - " + desc
		}
		lines = append(lines, line)
	}
	return []Finding{{Severity: sev, Category: "network", Title: fmt.Sprintf("kernel dropped %d packets (%s/s)", total, Rate(v.PerSec(total))),
		Detail: top(lines, 10), Score: float64(total)}}
}

func ruleConntrack(v *View) []Finding {
	var out []Finding
	for _, n := range v.Nodes {
		s := n.Stats
		if s.ConntrackMax > 0 {
			r := float64(s.ConntrackCount) / float64(s.ConntrackMax)
			if r > 0.8 {
				sev := SevWarn
				if r > 0.95 {
					sev = SevCrit
				}
				out = append(out, Finding{Severity: sev, Category: "network",
					Title: fmt.Sprintf("node %s conntrack table %s full (%d/%d)", n.Name, Pct(r), s.ConntrackCount, s.ConntrackMax),
					Hint:  "new connections will be dropped when full; raise net.netfilter.nf_conntrack_max or reduce connection churn", Score: r})
			}
		}
		if s.ConntrackDrop+s.ConntrackEarlyDrop > 0 {
			out = append(out, Finding{Severity: SevCrit, Category: "network",
				Title: fmt.Sprintf("node %s dropped %d packets because conntrack was full", n.Name, s.ConntrackDrop+s.ConntrackEarlyDrop), Score: 1})
		}
		if s.ConntrackInsertFailed > 0 {
			out = append(out, Finding{Severity: SevWarn, Category: "network",
				Title: fmt.Sprintf("node %s: %d conntrack insert failures (SNAT source port races)", n.Name, s.ConntrackInsertFailed),
				Hint:  "typically causes random 1s/5s connect delays to Services; consider --random-fully masquerading or NodeLocal DNSCache for DNS", Score: float64(s.ConntrackInsertFailed)})
		}
	}
	return out
}

func ruleConnErrors(v *View) []Finding {
	var out []Finding
	var exhausted, unreach []string
	for _, e := range v.Entities {
		for errno, n := range e.Stats.ConnErrors {
			switch errno {
			case "EADDRNOTAVAIL":
				exhausted = append(exhausted, fmt.Sprintf("%s: %d connect() calls failed with EADDRNOTAVAIL", e.Endpoint.Display(), n))
			case "ENETUNREACH", "EHOSTUNREACH":
				unreach = append(unreach, fmt.Sprintf("%s: %d × %s", e.Endpoint.Display(), n, errno))
			}
		}
	}
	if len(exhausted) > 0 {
		out = append(out, Finding{Severity: SevCrit, Category: "network", Title: "ephemeral port exhaustion",
			Detail: top(exhausted, 10), Hint: "too many short-lived outbound connections: enable keep-alive/pooling or widen net.ipv4.ip_local_port_range", Score: float64(len(exhausted))})
	}
	if len(unreach) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "network", Title: "connect() failing with unreachable network/host",
			Detail: top(unreach, 10), Score: float64(len(unreach))})
	}
	return out
}

func ruleChurn(v *View) []Finding {
	var lines []string
	var score float64
	for _, e := range v.Edges {
		s := e.Stats
		if e.Side == "server" || s.Closes == 0 {
			continue
		}
		rate := v.PerSec(s.Connects)
		avgLife := float64(s.LifetimeUs) / float64(s.Closes)
		if rate >= 5 && avgLife < 1e6 {
			lines = append(lines, fmt.Sprintf("%s: %s new connections/s, average lifetime %s", edgeName(e), Rate(rate), Dur(avgLife)))
			score += rate
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevWarn, Category: "network", Title: "connection churn: clients open a new TCP connection per request",
		Detail: top(lines, 10), Hint: "enable HTTP keep-alive / connection pooling; churn costs a handshake RTT per request, conntrack entries and ephemeral ports", Score: score}}
}

func ruleCrossZone(v *View) []Finding {
	costs := CrossZoneCosts(v)
	if len(costs) == 0 {
		return nil
	}
	var total float64
	for _, c := range costs {
		total += c.MonthlyUSD
	}
	if total < 1 {
		return nil
	}
	f := Finding{Severity: SevInfo, Category: "cost",
		Title: fmt.Sprintf("cross-zone traffic ≈ %s/month at the current rate", Money(total)),
		Hint:  "use topology aware routing (service.kubernetes.io/topology-mode: Auto) or co-locate chatty workloads",
		Score: total}
	if total > 100 {
		f.Severity = SevWarn
	}
	for _, c := range top(costs, 8) {
		f.Detail = append(f.Detail, fmt.Sprintf("%s → %s (%s → %s): %s/s ≈ %s/month", c.Client, c.Server, c.ClientZone, c.ServerZone, Bytes(c.BytesPerSec), Money(c.MonthlyUSD)))
	}
	return []Finding{f}
}

func ruleAPIServer(v *View) []Finding {
	type agg struct {
		conns, bytes uint64
	}
	by := map[string]*agg{}
	for _, e := range v.Edges {
		isAPI := v.Meta.IsAPIServer(e.Server.IP) || (e.Server.Kind == KindService && e.Server.Namespace == "default" && e.Server.Name == "kubernetes")
		if !isAPI || e.Client.Kind != KindPod {
			continue
		}
		k := e.Client.WorkloadKey()
		a, ok := by[k]
		if !ok {
			a = &agg{}
			by[k] = a
		}
		a.conns += e.Stats.Connects
		a.bytes += e.Stats.BytesRx + e.Stats.BytesTx
	}
	var lines []string
	var score float64
	for k, a := range by {
		cr, br := v.PerSec(a.conns), v.PerSec(a.bytes)
		if cr > 1 || br > 1<<20 {
			lines = append(lines, fmt.Sprintf("%s: %s connections/s, %s/s", k, Rate(cr), Bytes(br)))
			score += br
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevWarn, Category: "network", Title: "workloads hammering the Kubernetes API server",
		Detail: top(lines, 10), Hint: "use shared informers/watches instead of polling LIST calls, and reuse client connections", Score: score}}
}

// ---------------------------------------------------------------- compute

func ruleRunQ(v *View) []Finding {
	var lines []string
	var subj []string
	var score float64
	for _, e := range v.PodEntities() {
		s := e.Stats.Sched
		if s == nil || s.RunQ.Count < 50 {
			continue
		}
		p99 := s.RunQ.P99()
		share := ratio(float64(s.OffNs[model.StateRunQ]), float64(s.OnCPUNs))
		if p99 < 20e3 || share < 0.05 {
			continue
		}
		line := fmt.Sprintf("%s: run queue p99 %s, waited %s for CPU per 1s on CPU", e.Endpoint.Display(), Dur(p99), Dur(share*1e6))
		if c := topCulprits(v, s, e.Endpoint.Node, 2); c != "" {
			line += "; CPU taken by " + c
		}
		lines = append(lines, line)
		subj = append(subj, e.ID)
		score += p99
	}
	if len(lines) == 0 {
		return nil
	}
	return []Finding{{Severity: SevWarn, Category: "cpu", Title: "pods waiting for CPU (noisy neighbours / CPU saturation)",
		Detail: top(lines, 10), Hint: "set CPU requests that reflect real usage, spread hot pods across nodes, or move the culprits", Subjects: subj, Score: score}}
}

func topCulprits(v *View, s *model.SchedStats, node string, n int) string {
	var parts []string
	for _, k := range top(model.SortedKeys(s.Culprits), n) {
		parts = append(parts, fmt.Sprintf("%s (%s)", v.EntityEndpoint(k, node).Display(), Dur(float64(s.Culprits[k])/1e3)))
	}
	return strings.Join(parts, ", ")
}

func ruleThrottle(v *View) []Finding {
	var lines []string
	var score float64
	for _, e := range v.PodEntities() {
		r := e.Stats.Res
		if r == nil || r.Periods < 10 {
			continue
		}
		pct := float64(r.Throttled) / float64(r.Periods)
		if pct < 0.25 {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: throttled in %s of CFS periods (%s throttled, limit %dm)", e.Endpoint.Display(), Pct(pct), Dur(float64(r.ThrottledUs)), r.CPUQuotaMilli))
		score += pct
	}
	if len(lines) == 0 {
		return nil
	}
	return []Finding{{Severity: SevWarn, Category: "cpu", Title: "CPU throttling (limits too low for bursts)",
		Detail: top(lines, 10), Hint: "throttling adds latency even at low average CPU; raise or remove CPU limits for latency-sensitive services", Score: score}}
}

func ruleDisk(v *View) []Finding {
	var lines []string
	for _, e := range v.Entities {
		io := e.Stats.IO
		if io == nil || io.Lat.Count < 20 {
			continue
		}
		if p99 := io.Lat.P99(); p99 > 50e3 {
			lines = append(lines, fmt.Sprintf("%s: block I/O p99 %s (%s read, %s written)", e.Endpoint.Display(), Dur(p99), Bytes(float64(io.ReadBytes)), Bytes(float64(io.WriteBytes))))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevWarn, Category: "disk", Title: "slow disk I/O", Detail: top(lines, 10),
		Hint: "check volume IOPS/throughput limits and noisy neighbours on the same disk (`kubectl capybara nodes`)", Score: float64(len(lines))}}
}

func ruleHTTP(v *View) []Finding {
	var out []Finding
	var errLines, slowLines []string
	sev := SevWarn
	for _, e := range v.Entities {
		for _, ep := range e.Stats.HTTP {
			if ep.Role != "server" && e.Stats.HTTP["server "+ep.Method+" "+ep.Path] != nil {
				continue
			}
			if ep.Count >= 10 {
				r := ratio(float64(ep.Errors()), float64(ep.Count))
				if r > 0.01 {
					if r > 0.1 {
						sev = SevCrit
					}
					errLines = append(errLines, fmt.Sprintf("%s %s %s %s: %s 5xx (%d/%d)", e.Endpoint.Display(), ep.Role, ep.Method, ep.Path, Pct(r), ep.Errors(), ep.Count))
				}
				if ep.Role == "server" && ep.Lat.P99() > 1e6 {
					slowLines = append(slowLines, fmt.Sprintf("%s %s %s: p99 %s (p50 %s)", e.Endpoint.Display(), ep.Method, ep.Path, Dur(ep.Lat.P99()), Dur(ep.Lat.P50())))
				}
			}
		}
	}
	if len(errLines) > 0 {
		sort.Strings(errLines)
		out = append(out, Finding{Severity: sev, Category: "http", Title: "HTTP 5xx errors", Detail: top(errLines, 10), Score: float64(len(errLines))})
	}
	if len(slowLines) > 0 {
		sort.Strings(slowLines)
		out = append(out, Finding{Severity: SevInfo, Category: "http", Title: "slow HTTP endpoints (p99 > 1s)", Detail: top(slowLines, 10), Score: float64(len(slowLines))})
	}
	return out
}

// ---------------------------------------------------------------- security

func ruleSecurity(v *View) []Finding {
	var sessions, shells []string
	for _, e := range v.Events {
		switch e.Type {
		case model.EvExecSession:
			sessions = append(sessions, fmt.Sprintf("%s %s: %s", e.Time.Format("15:04:05"), e.Endpoint.Display(), e.Message))
		case model.EvShell:
			shells = append(shells, fmt.Sprintf("%s %s: %s", e.Time.Format("15:04:05"), e.Endpoint.Display(), e.Message))
		}
	}
	var out []Finding
	if len(sessions) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "security", Title: fmt.Sprintf("%d interactive exec session(s) into containers", len(sessions)),
			Detail: top(sessions, 10), Hint: "kubectl exec -it into production pods; verify these were expected", Score: float64(len(sessions))})
	}
	if len(shells) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "security", Title: fmt.Sprintf("%d shell(s) spawned by application processes", len(shells)),
			Detail: top(shells, 10), Hint: "applications rarely need to spawn shells; this can indicate command injection", Score: float64(len(shells))})
	}
	return out
}

func ruleUndeclaredPorts(v *View) []Finding {
	und := UndeclaredPorts(v)
	if len(und) == 0 {
		return nil
	}
	var lines []string
	for _, u := range und {
		lines = append(lines, fmt.Sprintf("%s listens on %s:%d (%s) - not in containerPorts or any Service", u.Endpoint.Display(), u.Addr, u.Port, u.Comm))
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevInfo, Category: "security", Title: fmt.Sprintf("%d undeclared listening port(s)", len(lines)),
		Detail: top(lines, 10), Hint: "debug endpoints or unexpected services; declare them or turn them off", Score: float64(len(lines))}}
}

func ruleExternalEgress(v *View) []Finding {
	ext := ExternalEgress(v)
	if len(ext) == 0 {
		return nil
	}
	var lines []string
	for _, x := range ext {
		lines = append(lines, fmt.Sprintf("%s → %s (%s)", x.Workload, strings.Join(top(x.Destinations, 5), ", "), Bytes(float64(x.Bytes))))
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevInfo, Category: "security", Title: fmt.Sprintf("%d workload(s) talk to the internet", len(ext)),
		Detail: top(lines, 10), Hint: "`kubectl capybara netpol <workload>` generates an egress NetworkPolicy from observed traffic", Score: float64(len(ext))}}
}

func ruleCollectors(v *View) []Finding {
	var lines []string
	for _, n := range v.Nodes {
		for c, st := range n.Collectors {
			if st != "ok" && !strings.HasPrefix(st, "disabled") {
				lines = append(lines, fmt.Sprintf("%s/%s: %s", n.Name, c, firstLine(st)))
			}
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevInfo, Category: "agent", Title: "some collectors are not running", Detail: top(lines, 10),
		Hint: "older kernels lack some hooks; data from these collectors is missing", Score: 0}}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// ---------------------------------------------------------------- insights

func ruleOOMRisk(v *View) []Finding {
	var out []Finding
	for _, r := range OOMRisks(v) {
		if r.ETA > time.Hour {
			continue
		}
		sev := SevWarn
		if r.ETA < 15*time.Minute {
			sev = SevCrit
		}
		out = append(out, Finding{Severity: sev, Category: "memory",
			Title: fmt.Sprintf("%s will hit its memory limit in ~%s", r.Endpoint.Display(), r.ETA.Round(time.Minute)),
			Detail: []string{fmt.Sprintf("%s of %s, growing %s/min (linear fit R²=%.2f)",
				Bytes(float64(r.Current)), Bytes(float64(r.Limit)), Bytes(r.BytesPerSec*60), r.R2)},
			Hint:     "a steady climb towards the limit usually means a leak or an unbounded cache; the OOM killer will restart the container",
			Subjects: []string{r.Endpoint.ID}, Score: -r.ETA.Seconds()})
	}
	return out
}

func rulePolicyDenials(v *View) []Finding {
	ds := PolicyDenials(v)
	if len(ds) == 0 {
		return nil
	}
	var total uint64
	f := Finding{Severity: SevWarn, Category: "network",
		Hint: "packets dropped by a NetworkPolicy / firewall rule: allow the flow if it is expected, otherwise find out why the client tries it"}
	for _, d := range ds {
		total += d.Count
	}
	for _, d := range top(ds, 10) {
		f.Detail = append(f.Detail, fmt.Sprintf("%s → %s:%d/%s blocked %d times (%s)", d.Src.Display(), d.Dst.Display(), d.Port, d.Proto, d.Count, d.Reason))
		f.Subjects = append(f.Subjects, d.Src.ID)
	}
	f.Title = fmt.Sprintf("%d packets blocked by packet filtering on %d path(s)", total, len(ds))
	f.Score = float64(total)
	return []Finding{f}
}

func ruleAcceptQueue(v *View) []Finding {
	var over, slow []string
	for _, e := range v.PodEntities() {
		n := e.Stats.Net
		if n == nil {
			continue
		}
		if n.ListenOverflows+n.ListenDrops > 0 {
			over = append(over, fmt.Sprintf("%s: %d accept queue overflows, %d SYNs dropped", e.Endpoint.Display(), n.ListenOverflows, n.ListenDrops))
		}
		if n.ZeroWindowDrops+n.RcvQueueDrops > 0 || n.ToZeroWindowAdv > 10 {
			slow = append(slow, fmt.Sprintf("%s: closed its receive window %d times, %d packets dropped (zero window %d, receive queue %d)",
				e.Endpoint.Display(), n.ToZeroWindowAdv, n.ZeroWindowDrops+n.RcvQueueDrops, n.ZeroWindowDrops, n.RcvQueueDrops))
		}
	}
	var out []Finding
	if len(over) > 0 {
		sort.Strings(over)
		out = append(out, Finding{Severity: SevWarn, Category: "network", Title: "servers too slow to accept new connections (accept queue overflow)",
			Detail: top(over, 10), Hint: "clients see connect timeouts/retries; add replicas, accept faster (more acceptor threads) or raise the listen backlog and net.core.somaxconn",
			Score: float64(len(over))})
	}
	if len(slow) > 0 {
		sort.Strings(slow)
		out = append(out, Finding{Severity: SevWarn, Category: "network", Title: "pods not reading their sockets fast enough (zero window)",
			Detail: top(slow, 10), Hint: "the application is CPU starved, blocked, or receives faster than it processes; senders stall waiting for it",
			Score: float64(len(slow))})
	}
	return out
}

func ruleZeroWindow(v *View) []Finding {
	var lines []string
	for _, e := range v.Edges {
		if e.Stats.ZeroWindow >= 10 { // >= ~1s of stall (100ms samples)
			lines = append(lines, fmt.Sprintf("%s: peer window closed for ~%s", edgeName(e), (time.Duration(e.Stats.ZeroWindow)*100*time.Millisecond).Round(100*time.Millisecond)))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevWarn, Category: "network", Title: "transfers stalled by a slow receiver (zero window)", Detail: top(lines, 10),
		Hint: "the side being written to is not consuming data; check its CPU, GC pauses or downstream backpressure", Score: float64(len(lines))}}
}

func ruleSlowNodes(v *View) []Finding {
	m := BuildNodeMatrix(v)
	slow := m.SlowNodes()
	var out []Finding
	for n, p50 := range slow {
		out = append(out, Finding{Severity: SevWarn, Category: "network",
			Title: fmt.Sprintf("node %s: network latency to other nodes is high (median RTT p50 %s)", n, Dur(p50)),
			Hint:  "compare with `kubectl capybara nodes` (latency matrix): a single slow row/column points at that node's NIC, host network or overload",
			Score: p50})
	}
	return out
}

func ruleServiceBalance(v *View) []Finding {
	var lines []string
	var score float64
	for _, sb := range ServiceBalances(v) {
		if sb.Imbalance < 2 || (!sb.ByBytes && sb.Total < 20) {
			continue
		}
		busiest := sb.Backends[0]
		unit := "connections"
		if sb.ByBytes {
			unit = "bytes"
		}
		lines = append(lines, fmt.Sprintf("svc/%s: %s gets %s of %s across %d backends (fair share %s)",
			sb.Service, busiest.Pod.Display(), Pct(busiest.Share), unit, len(sb.Backends), Pct(1/float64(len(sb.Backends)))))
		score += sb.Imbalance
	}
	if len(lines) == 0 {
		return nil
	}
	return []Finding{{Severity: SevWarn, Category: "network", Title: "uneven load balancing across Service backends", Detail: top(lines, 10),
		Hint:  "long-lived connections (HTTP/2, gRPC, pooled clients) stick to one backend; use client-side balancing, a mesh, or cap connection age (e.g. gRPC MaxConnectionAge)",
		Score: score}}
}

func ruleRightsizing(v *View) []Finding {
	rows := Rightsize(v, DefaultPricing)
	var over, under []string
	var savings float64
	for _, r := range rows {
		switch r.Verdict {
		case "over":
			if r.MonthlyUSD >= 1 {
				over = append(over, fmt.Sprintf("%s (%d pods): request %dm / %s, uses peak %.0fm / %s → %dm / %s, saves ≈ %s/month",
					r.Workload, r.Pods, r.CPUReq, Bytes(float64(r.MemReq)), r.CPUPeak, Bytes(r.MemPeak), r.CPURec, Bytes(float64(r.MemRec)), Money(r.MonthlyUSD)))
				savings += r.MonthlyUSD
			}
		case "under":
			under = append(under, fmt.Sprintf("%s: peak %.0fm CPU vs request %dm, memory peak %s vs limit %s",
				r.Workload, r.CPUPeak, r.CPUReq, Bytes(r.MemPeak), Bytes(float64(r.MemLim))))
		}
	}
	var out []Finding
	note := ""
	if v.Seconds() < 3600 {
		note = fmt.Sprintf(" (based on %s of data: use -w 1h or longer before changing requests)", time.Duration(v.Seconds()*float64(time.Second)).Round(time.Second))
	}
	if len(over) > 0 {
		out = append(out, Finding{Severity: SevInfo, Category: "cost", Title: fmt.Sprintf("over-provisioned workloads: ≈ %s/month in unused requests%s", Money(savings), note),
			Detail: top(over, 10), Hint: "`kubectl capybara rightsize` lists recommendations for every workload", Score: savings})
	}
	if len(under) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "cpu", Title: "workloads using more than they request (risk of throttling, eviction or OOM)",
			Detail: top(under, 10), Hint: "raise requests to the observed peak so the scheduler places them correctly", Score: float64(len(under))})
	}
	return out
}

func ruleDB(v *View) []Finding {
	var errLines, slowLines []string
	var score float64
	for _, e := range v.Entities {
		for _, q := range e.Stats.DB {
			if q.Count < 10 {
				continue
			}
			if r := ratio(float64(q.Errors), float64(q.Count)); r > 0.01 {
				kinds := ""
				if len(q.ErrorKinds) > 0 {
					var ks []string
					for _, k := range model.SortedKeys(q.ErrorKinds) {
						ks = append(ks, fmt.Sprintf("%s %d", k, q.ErrorKinds[k]))
					}
					kinds = " [" + strings.Join(top(ks, 3), ", ") + "]"
				}
				errLines = append(errLines, fmt.Sprintf("%s %s: %s errors (%d/%d)%s %s", e.Endpoint.Display(), q.Proto, Pct(r), q.Errors, q.Count, kinds, q.Query))
				score += r * 10
			}
			if p99 := q.Lat.P99(); p99 > 500e3 {
				slowLines = append(slowLines, fmt.Sprintf("%s %s: p99 %s, %s/s: %s", e.Endpoint.Display(), q.Proto, Dur(p99), Rate(v.PerSec(q.Count)), q.Query))
				score += p99 / 1e6
			}
		}
	}
	var out []Finding
	if len(errLines) > 0 {
		sort.Strings(errLines)
		out = append(out, Finding{Severity: SevWarn, Category: "db", Title: "database requests failing", Detail: top(errLines, 10),
			Hint: "check the database logs for these statements (constraint violations, timeouts, permission errors)", Score: score})
	}
	if len(slowLines) > 0 {
		sort.Strings(slowLines)
		out = append(out, Finding{Severity: SevWarn, Category: "db", Title: "slow database statements (p99 > 500ms)", Detail: top(slowLines, 10),
			Hint: "`kubectl capybara db` ranks statements by total time; look for missing indexes, lock waits or N+1 patterns", Score: score})
	}
	return out
}

func ruleFiles(v *View) []Finding {
	var lines []string
	var score float64
	for _, e := range v.Entities {
		for _, f := range e.Stats.Files {
			if f.WaitNs < 1e9 && f.MaxNs < 500e6 {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s waited %s on %s (%s, %d slow ops, max %s)",
				e.Endpoint.Display(), Dur(float64(f.WaitNs)/1e3), f.Path, f.FSType, f.Ops(), Dur(float64(f.MaxNs)/1e3)))
			score += float64(f.WaitNs) / 1e9
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []Finding{{Severity: SevWarn, Category: "disk", Title: "pods blocked on slow file operations", Detail: top(lines, 10),
		Hint: "network filesystems (nfs, cifs) and throttled cloud volumes are the usual cause; fsync-heavy apps suffer most", Score: score}}
}
