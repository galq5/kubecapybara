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
	clients map[dnsKey]dnsPending
	servers map[dnsKey]dnsPending
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

func (c *dnsCollector) Name() string { return "dns" }

func (c *dnsCollector) Start(a *Agent) error {
	c.a = a
	c.cur = NewWindow(time.Time{}, time.Time{})
	c.clients = map[dnsKey]dnsPending{}
	c.servers = map[dnsKey]dnsPending{}
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
			c.clients[key] = p
			st := c.client(entity)
			st.Queries++
			st.Name(msg.Name).Count++
		} else {
			c.servers[key] = p
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
		pend, ok = c.clients[key]
		delete(c.clients, key)
		st = c.client(entity)
	} else {
		pend, ok = c.servers[key]
		delete(c.servers, key)
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
	for k, p := range c.clients {
		if now > p.ts && now-p.ts > uint64(dnsTimeout) {
			delete(c.clients, k)
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
	for k, p := range c.servers {
		if now > p.ts && now-p.ts > uint64(dnsTimeout) {
			delete(c.servers, k)
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
