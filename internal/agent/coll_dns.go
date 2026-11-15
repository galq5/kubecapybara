package agent

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/dnsparse"
	"github.com/galq5/kubecapybara/internal/model"
)

const dnsTimeout = 5 * time.Second

// dnsCollector: DNS latency, rcodes, timeouts, ndots waste and an IP->name
// cache, for both clients and DNS servers (e.g. CoreDNS replicas).
type dnsCollector struct {
	a     *Agent
	objs  bpf.DnsObjects
	links []link.Link
	rd    *ringbuf.Reader

	mu      sync.Mutex
	cur     *Window
	clients *dnsTable
	servers *dnsTable
}

type dnsKey struct {
	client, server         string
	clientPort, serverPort uint16
	id                     uint16
	cgroup                 uint64
}

type dnsPending struct {
	ts     uint64
	entity string
	name   string
	qtype  string
}

// dnsLoose is a query's identity without the server's address, which NAT can
// rewrite between the query and its reply.
type dnsLoose struct {
	client     string
	clientPort uint16
	id         uint16
	cgroup     uint64
}

func (k dnsKey) loose() dnsLoose { return dnsLoose{k.client, k.clientPort, k.id, k.cgroup} }

// dnsTable holds queries waiting for their reply. Replies match their query
// by server too, so one query sent to several resolvers matches each reply.
// A reply whose source no query went to falls back to the oldest query with
// the same client socket and ID: a host network client querying a Service
// through kube-proxy sends to the backend (DNAT happens before the egress
// hook) but its reply arrives from the Service IP (translated back before
// the ingress hook).
type dnsTable struct {
	byKey   map[dnsKey]dnsPending
	byLoose map[dnsLoose][]dnsKey
}

func newDNSTable() *dnsTable {
	return &dnsTable{byKey: map[dnsKey]dnsPending{}, byLoose: map[dnsLoose][]dnsKey{}}
}

func (t *dnsTable) put(k dnsKey, p dnsPending) {
	if _, ok := t.byKey[k]; !ok {
		l := k.loose()
		t.byLoose[l] = append(t.byLoose[l], k)
	}
	t.byKey[k] = p
}

func (t *dnsTable) take(k dnsKey) (dnsPending, bool) {
	p, ok := t.byKey[k]
	if !ok {
		keys := t.byLoose[k.loose()]
		if len(keys) == 0 {
			return dnsPending{}, false
		}
		k = keys[0]
		p = t.byKey[k]
	}
	t.remove(k)
	return p, true
}

func (t *dnsTable) remove(k dnsKey) {
	delete(t.byKey, k)
	l := k.loose()
	keys := t.byLoose[l]
	for i, x := range keys {
		if x == k {
			keys = append(keys[:i:i], keys[i+1:]...)
			break
		}
	}
	if len(keys) == 0 {
		delete(t.byLoose, l)
	} else {
		t.byLoose[l] = keys
	}
}

func (c *dnsCollector) Name() string { return "dns" }

func (c *dnsCollector) Start(a *Agent) error {
	c.a = a
	c.cur = NewWindow(time.Time{}, time.Time{})
	c.clients = newDNSTable()
	c.servers = newDNSTable()
	if err := bpf.LoadDnsObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	root := a.resolver.Root()
	if _, err := os.Stat(root); err != nil {
		return err
	}
	for _, x := range []struct {
		p *ebpf.Program
		t ebpf.AttachType
	}{
		{c.objs.DnsEgress, ebpf.AttachCGroupInetEgress},
		{c.objs.DnsIngress, ebpf.AttachCGroupInetIngress},
	} {
		lk, err := link.AttachCgroup(link.CgroupOptions{Path: root, Attach: x.t, Program: x.p})
		if err != nil {
			return fmt.Errorf("attach cgroup skb to %s: %w", root, err)
		}
		c.links = append(c.links, lk)
	}
	rd, err := ringbuf.NewReader(c.objs.DnsEvents)
	if err != nil {
		return err
	}
	c.rd = rd
	go c.read()
	return nil
}

func (c *dnsCollector) read() {
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		ev, ok := castSample[bpf.DnsDnsEvent](rec.RawSample)
		if !ok {
			continue
		}
		n := int(ev.Len)
		if n > len(ev.Data) {
			n = len(ev.Data)
		}
		msg, err := dnsparse.Parse(ev.Data[:n])
		if err != nil || msg.Name == "" {
			continue
		}
		c.handle(ev, msg)
	}
}

func (c *dnsCollector) handle(ev *bpf.DnsDnsEvent, msg *dnsparse.Message) {
	a := c.a
	entity := a.resolver.Entity(ev.Cgroup)
	src, dst := ip16(ev.Saddr), ip16(ev.Daddr)
	egress := ev.Egress == 1

	c.mu.Lock()
	defer c.mu.Unlock()

	if !msg.Response {
		p := dnsPending{ts: ev.Ts, entity: entity, name: msg.Name, qtype: msg.Type}
		key := dnsKey{src, dst, ev.Sport, ev.Dport, msg.ID, ev.Cgroup}
		if egress {
			c.clients.put(key, p)
			st := c.client(entity)
			st.Queries++
			st.Name(msg.Name).Count++
		} else {
			c.servers.put(key, p)
			st := c.server(entity)
			st.Queries++
			st.Name(msg.Name).Count++
		}
		return
	}

	key := dnsKey{dst, src, ev.Dport, ev.Sport, msg.ID, ev.Cgroup}
	var (
		pend dnsPending
		ok   bool
		st   *model.DNSStats
	)
	if !egress {
		pend, ok = c.clients.take(key)
		st = c.client(entity)
	} else {
		pend, ok = c.servers.take(key)
		st = c.server(entity)
	}
	if !ok {
		return
	}
	// ring buffer records of different CPUs can arrive slightly out of order
	var lat uint64
	if ev.Ts > pend.ts {
		lat = (ev.Ts - pend.ts) / 1000
	}
	st.Responses++
	st.Lat.Observe(lat)
	if st.RCodes == nil {
		st.RCodes = map[string]uint64{}
	}
	st.RCodes[msg.RCode]++
	nm := st.Name(pend.name)
	nm.LatSumUs += lat
	nm.Answered++

	isClient := !egress
	switch msg.RCode {
	case "NOERROR":
		for _, ans := range msg.Answers {
			a.rec.LearnName(ans.IP.String(), pend.name)
		}
	case "NXDOMAIN":
		nm.NXDomain++
		if isClient && dnsparse.IsSearchExpansion(pend.name, a.cfg.ClusterDomain) {
			st.NdotsWaste++
		}
	default:
		nm.Errors++
		if isClient {
			a.rec.Add(model.Event{
				Time: a.clock.wall(ev.Ts), Entity: entity, Type: model.EvDNSFail, Severity: model.SevWarn,
				Message: fmt.Sprintf("DNS %s %s -> %s (%s)", pend.qtype, pend.name, msg.RCode, time.Duration(lat)*time.Microsecond),
				Fields:  map[string]string{"name": pend.name, "rcode": msg.RCode},
			})
		}
	}
	if isClient && a.isStarting(entity) {
		a.rec.Add(model.Event{
			Time: a.clock.wall(ev.Ts), Entity: entity, Type: model.EvDNSQuery,
			Message: fmt.Sprintf("DNS %s %s -> %s in %s", pend.qtype, pend.name, msg.RCode, (time.Duration(lat) * time.Microsecond).Round(time.Microsecond)),
			Fields:  map[string]string{"name": pend.name, "rcode": msg.RCode, "latencyUs": fmt.Sprint(lat)},
		})
	}
}

func (c *dnsCollector) client(entity string) *model.DNSStats {
	e := c.cur.Entity(entity)
	if e.DNS == nil {
		e.DNS = &model.DNSStats{}
	}
	return e.DNS
}

func (c *dnsCollector) server(entity string) *model.DNSStats {
	e := c.cur.Entity(entity)
	if e.DNSServer == nil {
		e.DNSServer = &model.DNSStats{}
	}
	return e.DNSServer
}

func (c *dnsCollector) Collect(w *Window) {
	c.mu.Lock()
	// read the clock under the lock: a query recorded while we waited for it
	// is newer than an earlier reading, and now-p.ts would wrap around
	now := monoNow()
	for k, p := range c.clients.byKey {
		if now > p.ts && now-p.ts > uint64(dnsTimeout) {
			c.clients.remove(k)
			st := c.client(p.entity)
			st.Timeouts++
			st.Name(p.name).Timeouts++
			c.a.rec.Add(model.Event{
				Time: c.a.clock.wall(p.ts), Entity: p.entity, Type: model.EvDNSFail, Severity: model.SevWarn,
				Message: fmt.Sprintf("DNS %s %s timed out (no answer within %s)", p.qtype, p.name, dnsTimeout),
				Fields:  map[string]string{"name": p.name, "rcode": "TIMEOUT"},
			})
		}
	}
	for k, p := range c.servers.byKey {
		if now > p.ts && now-p.ts > uint64(dnsTimeout) {
			c.servers.remove(k)
			c.server(p.entity).Timeouts++
		}
	}
	cur := c.cur
	c.cur = NewWindow(time.Time{}, time.Time{})
	c.mu.Unlock()
	for id, e := range cur.Entities {
		w.Entity(id).Merge(e)
	}
}

func (c *dnsCollector) Close() error {
	if c.rd != nil {
		_ = c.rd.Close()
	}
	for _, l := range c.links {
		_ = l.Close()
	}
	return c.objs.Close()
}
