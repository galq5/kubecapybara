package hub

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// Scope limits what a response carries so that clients of large clusters
// do not download every pod and connection of every node.
type Scope struct {
	// Namespace keeps entities of this namespace and connections with at
	// least one end in it.
	Namespace string
	// Top keeps the N busiest flows (plus the N with the most errors) and
	// the N busiest entities (plus the N with the most problems).
	Top int
}

// Active reports whether the scope filters anything.
func (s Scope) Active() bool { return s.Namespace != "" || s.Top > 0 }

type resolver struct {
	meta *k8smeta.Meta
	ns   string
}

func (r resolver) entityNS(id string) string {
	if uid, ok := strings.CutPrefix(id, "pod:"); ok && r.meta != nil {
		if p := r.meta.Pods[uid]; p != nil {
			return p.Namespace
		}
	}
	return ""
}

func (r resolver) ipNS(ip string) string {
	if r.meta == nil {
		return ""
	}
	if p := r.meta.PodByIP(ip); p != nil {
		return p.Namespace
	}
	if s := r.meta.ServiceByIP(ip); s != nil {
		return s.Namespace
	}
	return ""
}

func (r resolver) keepEntity(id string) bool { return r.ns == "" || r.entityNS(id) == r.ns }

func (r resolver) keepPair(p *model.Pair) bool {
	return r.ns == "" || r.entityNS(p.Owner) == r.ns || r.ipNS(p.Client) == r.ns || r.ipNS(p.Server) == r.ns
}

type flowKey struct {
	client, server string
	port           uint16
	scope          string
}

// Local addresses are shared by independent pod network namespaces.
func (r resolver) flowKey(p *model.Pair, node string) flowKey {
	k := flowKey{client: p.Client, server: p.Server, port: p.Port}
	a, _ := netip.ParseAddr(p.Client)
	b, _ := netip.ParseAddr(p.Server)
	if a.IsLoopback() || b.IsLoopback() {
		k.scope = node
		if uid, ok := strings.CutPrefix(p.Owner, "pod:"); ok {
			var pod *k8smeta.Pod
			if r.meta != nil {
				pod = r.meta.Pods[uid]
			}
			if pod == nil || !pod.HostNetwork {
				k.scope += "|" + p.Owner
			}
		}
	}
	return k
}

func pairErrors(p *model.Pair) uint64 {
	return p.Refused + p.Timeouts + p.SynRetrans + p.Retrans + p.RstSent + p.RstRcvd + p.ZeroWindow + p.MTUReduced
}

func entityLoad(e *model.EntityStats) uint64 {
	var v uint64
	if e.Sched != nil {
		v += e.Sched.OnCPUNs
	}
	if e.Res != nil {
		v += e.Res.MemCurrent / 1024 // KiB: comparable magnitude to µs of CPU
	}
	return v
}

func entityProblems(e *model.EntityStats) uint64 {
	var v uint64
	if e.Res != nil {
		v += e.Res.OOMKills*1_000_000 + e.Res.Throttled
	}
	for _, n := range e.ConnErrors {
		v += n
	}
	for _, h := range e.HTTP {
		v += h.Status["5xx"]
	}
	for _, q := range e.DB {
		v += q.Errors
	}
	if e.DNS != nil {
		v += e.DNS.Timeouts
		for rc, n := range e.DNS.RCodes {
			if rc != "NOERROR" {
				v += n
			}
		}
	}
	return v
}

// topKeys returns the union of the n highest keys by each score.
func topKeys[K comparable](scores map[K][2]uint64, n int) map[K]bool {
	keys := make([]K, 0, len(scores))
	for k := range scores {
		keys = append(keys, k)
	}
	out := map[K]bool{}
	for dim := 0; dim < 2; dim++ {
		sort.SliceStable(keys, func(i, j int) bool { return scores[keys[i]][dim] > scores[keys[j]][dim] })
		for i := 0; i < len(keys) && i < n; i++ {
			if scores[keys[i]][dim] > 0 || dim == 0 {
				out[keys[i]] = true
			}
		}
	}
	return out
}

// Apply returns scoped copies of snaps. The input snapshots (shared through
// the cache) are never modified; stats objects are shared read-only.
func Apply(snaps []*model.Snapshot, meta *k8smeta.Meta, sc Scope) []*model.Snapshot {
	if !sc.Active() {
		return snaps
	}
	r := resolver{meta: meta, ns: sc.Namespace}

	// 1. namespace filter decides candidates; 2. top-N ranks them globally.
	flows := map[flowKey][2]uint64{}
	ents := map[string][2]uint64{}
	for _, s := range snaps {
		for _, p := range s.Pairs {
			if !r.keepPair(p) {
				continue
			}
			k := r.flowKey(p, s.Node)
			v := flows[k]
			v[0] += p.BytesTx + p.BytesRx + p.Connects
			v[1] += pairErrors(p)
			flows[k] = v
		}
		for id, e := range s.Entities {
			if !r.keepEntity(id) {
				continue
			}
			v := ents[id]
			v[0] += entityLoad(e)
			v[1] += entityProblems(e)
			ents[id] = v
		}
	}
	keepFlow := func(k flowKey) bool { _, ok := flows[k]; return ok }
	keepEnt := func(id string) bool { _, ok := ents[id]; return ok }
	if sc.Top > 0 {
		if len(flows) > sc.Top {
			top := topKeys(flows, sc.Top)
			keepFlow = func(k flowKey) bool { return top[k] }
		}
		if len(ents) > sc.Top {
			top := topKeys(ents, sc.Top)
			keepEnt = func(id string) bool { return top[id] }
		}
	}

	out := make([]*model.Snapshot, 0, len(snaps))
	for _, s := range snaps {
		c := &model.Snapshot{
			Node: s.Node, Version: s.Version, From: s.From, To: s.To,
			Collectors: s.Collectors, NodeStats: s.NodeStats,
			Entities: map[string]*model.EntityStats{},
		}
		ips := map[string]bool{}
		for _, p := range s.Pairs {
			if keepFlow(r.flowKey(p, s.Node)) {
				c.Pairs = append(c.Pairs, p)
				ips[p.Client], ips[p.Server] = true, true
			}
		}
		for id, e := range s.Entities {
			if keepEnt(id) {
				c.Entities[id] = e
			}
		}
		// Things tied to an entity follow the namespace filter only: they are
		// rare and matter even for otherwise quiet pods (crashes, OOMs).
		for _, d := range s.Drops {
			if r.ns == "" || r.ipNS(d.Src) == r.ns || r.ipNS(d.Dst) == r.ns {
				c.Drops = append(c.Drops, d)
				ips[d.Src], ips[d.Dst] = true, true
			}
		}
		for _, e := range s.Events {
			if r.keepEntity(e.Entity) {
				c.Events = append(c.Events, e)
			}
		}
		for _, l := range s.Listens {
			if r.keepEntity(l.Entity) {
				c.Listens = append(c.Listens, l)
			}
		}
		for _, x := range s.Crashes {
			if r.keepEntity(x.Entity) {
				c.Crashes = append(c.Crashes, x)
			}
		}
		for _, x := range s.Startups {
			if r.keepEntity(x.Entity) {
				c.Startups = append(c.Startups, x)
			}
		}
		if s.Series != nil {
			c.Series = map[string][]model.ResourceSample{}
			for id, ser := range s.Series {
				if keepEnt(id) {
					c.Series[id] = ser
				}
			}
		}
		if s.DNSNames != nil {
			c.DNSNames = map[string]string{}
			for ip, n := range s.DNSNames {
				if ips[ip] {
					c.DNSNames[ip] = n
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// PruneMeta returns the part of meta a scoped response needs: every pod,
// Service, ReplicaSet and Deployment of the namespace, plus the pods and
// Services the returned data refers to (connection peers in other
// namespaces), with their workloads. Nodes are always complete.
func PruneMeta(meta *k8smeta.Meta, snaps []*model.Snapshot, ns string) *k8smeta.Meta {
	if meta == nil {
		return nil
	}
	out := &k8smeta.Meta{
		Loaded: meta.Loaded, ClusterDomain: meta.ClusterDomain, Nodes: meta.Nodes, APIServerIPs: meta.APIServerIPs,
		Pods: map[string]*k8smeta.Pod{}, ReplicaSets: map[string]*k8smeta.ReplicaSet{}, Deployments: map[string]*k8smeta.Deployment{},
	}
	addPod := func(p *k8smeta.Pod) {
		if p != nil {
			out.Pods[p.UID] = p
		}
	}
	svcs := map[*k8smeta.Service]bool{}
	addIP := func(ip string) {
		addPod(meta.PodByIP(ip))
		if s := meta.ServiceByIP(ip); s != nil {
			svcs[s] = true
		}
	}
	for _, s := range snaps {
		for id := range s.Entities {
			if uid, ok := strings.CutPrefix(id, "pod:"); ok {
				addPod(meta.Pods[uid])
			}
		}
		for _, p := range s.Pairs {
			addIP(p.Client)
			addIP(p.Server)
			if uid, ok := strings.CutPrefix(p.Owner, "pod:"); ok {
				addPod(meta.Pods[uid])
			}
		}
		for _, d := range s.Drops {
			addIP(d.Src)
			addIP(d.Dst)
		}
		for _, e := range s.Events {
			if uid, ok := strings.CutPrefix(e.Entity, "pod:"); ok {
				addPod(meta.Pods[uid])
			}
		}
	}
	if ns != "" {
		for _, p := range meta.Pods {
			if p.Namespace == ns {
				addPod(p)
			}
		}
	}
	for _, s := range meta.Services {
		if s.Namespace == ns {
			svcs[s] = true
		}
	}
	// Services in front of the kept pods (Service balance, netpol) and the
	// backends of referenced Services.
	byNS := map[string][]*k8smeta.Pod{}
	for _, p := range out.Pods {
		byNS[p.Namespace] = append(byNS[p.Namespace], p)
	}
	for _, s := range meta.Services {
		if svcs[s] || len(s.Selector) == 0 {
			continue
		}
		for _, p := range byNS[s.Namespace] {
			if k8smeta.Matches(s.Selector, p.Labels) {
				svcs[s] = true
				break
			}
		}
	}
	allByNS := map[string][]*k8smeta.Pod{}
	for _, p := range meta.Pods {
		allByNS[p.Namespace] = append(allByNS[p.Namespace], p)
	}
	for _, s := range meta.Services {
		if !svcs[s] {
			continue
		}
		out.Services = append(out.Services, s)
		if len(s.Selector) == 0 {
			continue
		}
		for _, p := range allByNS[s.Namespace] {
			if k8smeta.Matches(s.Selector, p.Labels) {
				addPod(p)
			}
		}
	}
	owners := map[string]bool{}
	for _, p := range out.Pods {
		if p.OwnerKind == "ReplicaSet" {
			owners[p.Namespace+"/"+p.OwnerName] = true
		}
	}
	for k, rs := range meta.ReplicaSets {
		if rs.Namespace == ns || owners[k] {
			out.ReplicaSets[k] = rs
		}
	}
	for k, d := range meta.Deployments {
		if d.Namespace == ns {
			out.Deployments[k] = d
		}
	}
	for _, rs := range out.ReplicaSets {
		if rs.Deployment != "" {
			k := rs.Namespace + "/" + rs.Deployment
			if d := meta.Deployments[k]; d != nil {
				out.Deployments[k] = d
			}
		}
	}
	out.Index()
	return out
}
