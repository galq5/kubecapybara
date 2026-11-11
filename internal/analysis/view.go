// Package analysis turns raw agent snapshots plus cluster metadata into
// named, merged views and runs diagnostics (doctor, rollout comparison,
// startup timelines, crash forensics, network policy suggestions, cost).
package analysis

import (
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// Kind is the kind of a network endpoint.
type Kind string

const (
	KindPod      Kind = "pod"
	KindService  Kind = "service"
	KindNode     Kind = "node"
	KindHost     Kind = "host" // a non-pod process on a node (kubelet, systemd service...)
	KindLocal    Kind = "localhost"
	KindExternal Kind = "external"
	KindUnknown  Kind = "unknown"
)

// Endpoint is a resolved network peer or workload.
type Endpoint struct {
	Kind      Kind   `json:"kind"`
	ID        string `json:"id"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Workload  string `json:"workload,omitempty"`
	Node      string `json:"node,omitempty"`
	Zone      string `json:"zone,omitempty"`
	IP        string `json:"ip,omitempty"`
	DNSName   string `json:"dnsName,omitempty"`
	Private   bool   `json:"private,omitempty"`
}

// Display returns a compact human name.
func (e Endpoint) Display() string {
	switch e.Kind {
	case KindPod:
		if e.Namespace == "" {
			return "pod/" + e.Name
		}
		return e.Namespace + "/" + e.Name
	case KindService:
		return "svc/" + e.Namespace + "/" + e.Name
	case KindNode:
		return "node/" + e.Name
	case KindHost:
		if e.Node != "" {
			return e.Name + "@" + e.Node
		}
		return e.Name
	case KindLocal:
		if e.Node == "" {
			return "localhost"
		}
		return "localhost@" + e.Node
	case KindExternal:
		if e.DNSName != "" {
			return e.DNSName
		}
		return e.IP
	}
	if e.IP != "" {
		return e.IP
	}
	return e.Name
}

// WorkloadKey groups pods of the same workload.
func (e Endpoint) WorkloadKey() string {
	if e.Kind == KindPod && e.Workload != "" {
		return e.Namespace + "/" + e.Workload
	}
	return e.Display()
}

// EntityView is an entity (pod or host cgroup) merged across nodes.
type EntityView struct {
	ID       string
	Endpoint Endpoint
	Pod      *k8smeta.Pod
	Stats    *model.EntityStats
}

// Edge is aggregated TCP traffic between two endpoints.
type Edge struct {
	Client    Endpoint
	Server    Endpoint
	Port      uint16
	Stats     *model.Pair
	Side      string // client, server or both
	CrossZone bool
	Nodes     []string
}

// EventView is an event with its resolved entity.
type EventView struct {
	model.Event
	Node     string
	Endpoint Endpoint
}

// CrashView is a crash report with its resolved entity.
type CrashView struct {
	model.CrashReport
	Node     string
	Endpoint Endpoint
}

// StartupView is a startup timeline with its resolved entity.
type StartupView struct {
	model.Startup
	Node     string
	Endpoint Endpoint
}

// ListenView is a listening socket with its resolved entity.
type ListenView struct {
	model.Listen
	Node     string
	Endpoint Endpoint
}

// NodeView is per-node health.
type NodeView struct {
	Name       string
	Zone       string
	Stats      model.NodeStats
	Collectors map[string]string
	Version    string
}

// Options tune the analysis.
type Options struct {
	ClusterDomain string
	CostPerGB     float64 // inter-zone transfer price per GB, per direction
}

// View is the merged, resolved picture of the cluster for a time window.
type View struct {
	From, To time.Time
	Opts     Options
	Meta     *k8smeta.Meta
	Snaps    []*model.Snapshot

	Entities map[string]*EntityView
	Edges    []*Edge
	Events   []EventView
	Crashes  []CrashView
	Startups []StartupView
	Listens  []ListenView
	Drops    []*model.Drop
	Nodes    map[string]*NodeView
	DNSNames map[string]string
	// Series holds resource samples (memory, CPU) per entity key, oldest first.
	Series map[string][]model.ResourceSample
}

// Seconds is the length of the window.
func (v *View) Seconds() float64 {
	s := v.To.Sub(v.From).Seconds()
	if s <= 0 {
		return 1
	}
	return s
}

// PerSec converts a counter over the window into a rate.
func (v *View) PerSec(n uint64) float64 { return float64(n) / v.Seconds() }

// Build merges snapshots and resolves names.
func Build(snaps []*model.Snapshot, meta *k8smeta.Meta, opts Options) *View {
	if opts.ClusterDomain == "" {
		opts.ClusterDomain = "cluster.local"
	}
	if opts.CostPerGB == 0 {
		opts.CostPerGB = 0.01
	}
	if meta == nil {
		meta = &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{}, Nodes: map[string]*k8smeta.Node{}}
		meta.Index()
	}
	v := &View{
		Opts:     opts,
		Meta:     meta,
		Snaps:    snaps,
		Entities: map[string]*EntityView{},
		Nodes:    map[string]*NodeView{},
		DNSNames: map[string]string{},
		Series:   map[string][]model.ResourceSample{},
	}
	for _, s := range snaps {
		if v.From.IsZero() || s.From.Before(v.From) {
			v.From = s.From
		}
		if s.To.After(v.To) {
			v.To = s.To
		}
		for ip, n := range s.DNSNames {
			v.DNSNames[ip] = n
		}
		v.Nodes[s.Node] = &NodeView{Name: s.Node, Zone: meta.ZoneOf(s.Node), Stats: s.NodeStats, Collectors: s.Collectors, Version: s.Version}
	}

	// listeners first: they resolve localhost connections
	listeners := map[string]string{} // node|port -> entity
	for _, s := range snaps {
		for _, l := range s.Listens {
			listeners[s.Node+"|"+itoa(int(l.Port))] = l.Entity
			v.Listens = append(v.Listens, ListenView{Listen: l, Node: s.Node, Endpoint: v.EntityEndpoint(l.Entity, s.Node)})
		}
	}

	for _, s := range snaps {
		for id, e := range s.Entities {
			key := v.entityKey(id, s.Node)
			ev, ok := v.Entities[key]
			if !ok {
				ev = &EntityView{ID: key, Endpoint: v.EntityEndpoint(id, s.Node), Stats: &model.EntityStats{ID: key}}
				if uid, ok := strings.CutPrefix(id, "pod:"); ok {
					ev.Pod = meta.Pods[uid]
				}
				v.Entities[key] = ev
			}
			ev.Stats.Merge(e)
		}
		for _, d := range s.Drops {
			v.Drops = append(v.Drops, d)
		}
		for _, e := range s.Events {
			v.Events = append(v.Events, EventView{Event: e, Node: s.Node, Endpoint: v.EntityEndpoint(e.Entity, s.Node)})
		}
		for _, c := range s.Crashes {
			v.Crashes = append(v.Crashes, CrashView{CrashReport: c, Node: s.Node, Endpoint: v.EntityEndpoint(c.Entity, s.Node)})
		}
		for _, st := range s.Startups {
			v.Startups = append(v.Startups, StartupView{Startup: st, Node: s.Node, Endpoint: v.EntityEndpoint(st.Entity, s.Node)})
		}
		for id, ser := range s.Series {
			k := v.entityKey(id, s.Node)
			v.Series[k] = append(v.Series[k], ser...)
		}
	}
	for k := range v.Series {
		ser := v.Series[k]
		sort.Slice(ser, func(i, j int) bool { return ser[i].Time.Before(ser[j].Time) })
	}
	sort.Slice(v.Events, func(i, j int) bool { return v.Events[i].Time.Before(v.Events[j].Time) })
	sort.Slice(v.Crashes, func(i, j int) bool { return v.Crashes[i].Time.After(v.Crashes[j].Time) })
	sort.Slice(v.Drops, func(i, j int) bool { return v.Drops[i].Count > v.Drops[j].Count })

	v.buildEdges(listeners)
	return v
}

func itoa(i int) string { return strconv.Itoa(i) }

// entityKey makes host entities unique per node.
func (v *View) entityKey(id, node string) string {
	if strings.HasPrefix(id, "pod:") {
		return id
	}
	return id + "@" + node
}

// EntityEndpoint resolves an agent entity ID on a node.
func (v *View) EntityEndpoint(id, node string) Endpoint {
	if uid, ok := strings.CutPrefix(id, "pod:"); ok {
		if p := v.Meta.Pods[uid]; p != nil {
			return v.podEndpoint(p)
		}
		short := uid
		if len(short) > 8 {
			short = short[:8]
		}
		return Endpoint{Kind: KindPod, ID: id, Name: short, Node: node, Zone: v.Meta.ZoneOf(node)}
	}
	if p, ok := strings.CutPrefix(id, "host:"); ok {
		name := path.Base(p)
		for _, suf := range []string{".service", ".scope", ".slice"} {
			name = strings.TrimSuffix(name, suf)
		}
		if p == "/" || name == "" || name == "." || name == "/" {
			name = "host"
		}
		return Endpoint{Kind: KindHost, ID: id + "@" + node, Name: name, Node: node, Zone: v.Meta.ZoneOf(node)}
	}
	return Endpoint{Kind: KindUnknown, ID: id + "@" + node, Name: id, Node: node, Zone: v.Meta.ZoneOf(node)}
}

func (v *View) podEndpoint(p *k8smeta.Pod) Endpoint {
	return Endpoint{
		Kind: KindPod, ID: "pod:" + p.UID, Namespace: p.Namespace, Name: p.Name,
		Workload: p.Workload, Node: p.Node, Zone: v.Meta.ZoneOf(p.Node), IP: p.IP,
	}
}

// IPEndpoint resolves a remote IP address.
func (v *View) IPEndpoint(ip, node string) Endpoint {
	addr, err := netip.ParseAddr(ip)
	if err == nil && addr.IsLoopback() {
		return Endpoint{Kind: KindLocal, ID: "local@" + node, Name: "localhost", Node: node, IP: ip, Zone: v.Meta.ZoneOf(node)}
	}
	if p := v.Meta.PodByIP(ip); p != nil {
		return v.podEndpoint(p)
	}
	if s := v.Meta.ServiceByIP(ip); s != nil {
		return Endpoint{Kind: KindService, ID: "svc:" + s.Namespace + "/" + s.Name, Namespace: s.Namespace, Name: s.Name, IP: ip}
	}
	if n := v.Meta.NodeByIP(ip); n != nil {
		return Endpoint{Kind: KindNode, ID: "node:" + n.Name, Name: n.Name, Node: n.Name, Zone: n.Zone, IP: ip}
	}
	e := Endpoint{Kind: KindExternal, ID: "ip:" + ip, IP: ip, DNSName: v.DNSNames[ip]}
	if err == nil && (addr.IsPrivate() || addr.IsLinkLocalUnicast()) {
		e.Private = true
		if e.DNSName == "" {
			e.Kind = KindUnknown
			e.Name = ip
		}
	}
	return e
}

type flowKey struct {
	client, server string
	port           uint16
	scope          string // node name for loopback flows
}

type flow struct {
	clientSide, serverSide *model.Pair
	clientOwner            string
	serverOwner            string
	nodes                  map[string]bool
}

func isLoopback(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.IsLoopback()
}

func (v *View) buildEdges(listeners map[string]string) {
	flows := map[flowKey]*flow{}
	for _, s := range v.Snaps {
		for _, p := range s.Pairs {
			k := flowKey{client: p.Client, server: p.Server, port: p.Port}
			if isLoopback(p.Client) || isLoopback(p.Server) {
				k.scope = s.Node
			}
			f, ok := flows[k]
			if !ok {
				f = &flow{nodes: map[string]bool{}}
				flows[k] = f
			}
			f.nodes[s.Node] = true
			if p.Side == "client" {
				if f.clientSide == nil {
					f.clientSide = p.Clone()
				} else {
					f.clientSide.Add(p)
				}
				f.clientOwner = v.preferOwner(f.clientOwner, p.Owner, s.Node)
			} else {
				if f.serverSide == nil {
					f.serverSide = p.Clone()
				} else {
					f.serverSide.Add(p)
				}
				f.serverOwner = v.preferOwner(f.serverOwner, p.Owner, s.Node)
			}
		}
	}

	edges := map[string]*Edge{}
	for k, f := range flows {
		var stats *model.Pair
		side := "client"
		switch {
		case f.clientSide != nil && f.serverSide != nil:
			stats = f.clientSide.Clone()
			// resets sent by the server are only visible server side
			stats.RstSent += f.serverSide.RstSent
			// the server socket sees the client's window (slow clients)
			stats.ZeroWindow += f.serverSide.ZeroWindow
			side = "both"
		case f.clientSide != nil:
			stats = f.clientSide.Clone()
		default:
			stats = f.serverSide.Clone()
			side = "server"
		}
		node := k.scope
		var anyNode string
		for n := range f.nodes {
			anyNode = n
		}
		if node == "" {
			node = anyNode
		}
		var client, server Endpoint
		if f.clientOwner != "" {
			client = v.ownerEndpoint(f.clientOwner, k.client)
		} else {
			client = v.IPEndpoint(k.client, node)
		}
		if f.serverOwner != "" {
			server = v.ownerEndpoint(f.serverOwner, k.server)
		} else {
			server = v.IPEndpoint(k.server, node)
			if server.Kind == KindLocal || server.Kind == KindNode {
				if owner, ok := listeners[node+"|"+itoa(int(k.port))]; ok {
					server = v.EntityEndpoint(owner, node)
				}
			}
		}
		ek := client.ID + "|" + server.ID + "|" + itoa(int(k.port))
		e, ok := edges[ek]
		if !ok {
			e = &Edge{Client: client, Server: server, Port: k.port, Stats: &model.Pair{}, Side: side}
			edges[ek] = e
		} else if e.Side != side {
			e.Side = "both"
		}
		e.Stats.Add(stats)
		for n := range f.nodes {
			e.Nodes = appendUniq(e.Nodes, n)
		}
	}
	for _, e := range edges {
		cz, sz := e.Client.Zone, e.Server.Zone
		e.CrossZone = cz != "" && sz != "" && cz != sz
		v.Edges = append(v.Edges, e)
	}
	sort.Slice(v.Edges, func(i, j int) bool {
		a, b := v.Edges[i], v.Edges[j]
		if a.Stats.Connects+a.Stats.RTT.Count != b.Stats.Connects+b.Stats.RTT.Count {
			return a.Stats.Connects+a.Stats.RTT.Count > b.Stats.Connects+b.Stats.RTT.Count
		}
		return a.Client.Display()+a.Server.Display() < b.Client.Display()+b.Server.Display()
	})
}

// preferOwner picks the owner of one side of a flow. Counters recorded
// without socket ownership (e.g. a reset answered for a connection in
// TIME_WAIT) come with the owner "unknown": a known owner of the same flow
// wins whatever the order of the pairs.
func (v *View) preferOwner(cur, owner, node string) string {
	if cur == "" || strings.HasPrefix(cur, "unknown\x00") && owner != "unknown" && owner != "" {
		return v.entityKeyNode(owner, node)
	}
	return cur
}

// entityKeyNode returns "<entity>\x00<node>" so ownerEndpoint can resolve it.
func (v *View) entityKeyNode(entity, node string) string { return entity + "\x00" + node }

func (v *View) ownerEndpoint(key, ip string) Endpoint {
	entity, node, _ := strings.Cut(key, "\x00")
	if entity == "unknown" || entity == "" {
		return v.IPEndpoint(ip, node)
	}
	e := v.EntityEndpoint(entity, node)
	// a host entity owning a socket with a pod IP is unusual; trust the IP
	if e.Kind == KindHost || e.Kind == KindUnknown {
		if p := v.Meta.PodByIP(ip); p != nil {
			return v.podEndpoint(p)
		}
	}
	if e.IP == "" {
		e.IP = ip
	}
	return e
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// Entity returns the merged view of an entity ID (e.g. "pod:<uid>").
func (v *View) Entity(id string) *EntityView { return v.Entities[id] }

// PodEntities returns entity views for pods, sorted by name.
func (v *View) PodEntities() []*EntityView {
	var out []*EntityView
	for _, e := range v.Entities {
		if e.Endpoint.Kind == KindPod {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint.Display() < out[j].Endpoint.Display() })
	return out
}

// EdgesOf returns edges where the entity is client or server.
func (v *View) EdgesOf(id string) (out, in []*Edge) {
	for _, e := range v.Edges {
		if e.Client.ID == id {
			out = append(out, e)
		}
		if e.Server.ID == id {
			in = append(in, e)
		}
	}
	return
}

// EventsOf returns events of an entity.
func (v *View) EventsOf(id string) []EventView {
	var out []EventView
	for _, e := range v.Events {
		if e.Endpoint.ID == id {
			out = append(out, e)
		}
	}
	return out
}
