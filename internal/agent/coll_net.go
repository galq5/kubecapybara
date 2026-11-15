package agent

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/model"
)

const (
	netEvListen       = 1
	netEvConnectStart = 2
	netEvConnectDone  = 3
	netEvUnlisten     = 4
)

// netCollector: TCP pairs, connect errors, listens and startup connects.
type netCollector struct {
	a    *Agent
	objs bpf.NetObjects
	l    linker
	rd   *ringbuf.Reader

	mu    sync.Mutex
	young map[uint64]uint64 // cgroup -> expiry (monotonic ns)
}

func (c *netCollector) Name() string { return "net" }

func (c *netCollector) Start(a *Agent) error {
	c.a = a
	c.young = map[uint64]uint64{}
	if err := bpf.LoadNetObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	p := c.objs.NetPrograms
	required := []error{
		c.l.tracing(p.OnState, "tp_btf/inet_sock_set_state"),
		c.l.tracing(p.OnTcpProbe, "tp_btf/tcp_probe"),
		c.l.tracing(p.OnRetransmit, "tp_btf/tcp_retransmit_skb"),
		c.l.tracing(p.OnReceiveReset, "tp_btf/tcp_receive_reset"),
	}
	if err := errors.Join(required...); err != nil {
		return err
	}
	optional := []error{
		c.l.tracing(p.OnSendReset, "tp_btf/tcp_send_reset"),
		c.l.kprobe("tcp_v4_mtu_reduced", p.OnMtuReduced),
		c.l.kretprobe("tcp_v4_connect", p.OnV4ConnectRet),
		c.l.kretprobe("tcp_v6_connect", p.OnV6ConnectRet),
	}
	for _, err := range optional {
		if err != nil {
			a.log.Info("net: optional kprobe unavailable (MTU/connect errno stats disabled)", "err", err)
		}
	}
	rd, err := ringbuf.NewReader(c.objs.NetEvents)
	if err != nil {
		return err
	}
	c.rd = rd
	go c.readEvents()
	a.markSeenExisting()
	go scanExistingListeners(a)
	return nil
}

func (c *netCollector) markYoung(cgroup uint64, d time.Duration) {
	if c.objs.Young == nil {
		return
	}
	exp := monoNow() + uint64(d)
	c.mu.Lock()
	c.young[cgroup] = exp
	c.mu.Unlock()
	_ = c.objs.Young.Put(cgroup, exp)
}

func (c *netCollector) readEvents() {
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		ev, ok := castSample[bpf.NetNetEvent](rec.RawSample)
		if !ok {
			continue
		}
		c.handleEvent(ev)
	}
}

func (c *netCollector) handleEvent(ev *bpf.NetNetEvent) {
	a := c.a
	t := a.clock.wall(ev.Ts)
	info := a.resolver.Lookup(ev.Cgroup)
	comm := cstr(ev.Comm[:])
	addr := ip16(ev.Addr)
	switch ev.Type {
	case netEvListen:
		a.rec.Listen(model.Listen{Entity: info.Entity, Port: ev.Port, Addr: addr, Comm: comm, Time: t})
		a.rec.Add(model.Event{
			Time: t, Entity: info.Entity, Type: model.EvListen, PID: ev.Pid, Comm: comm,
			Message: fmt.Sprintf("listening on %s:%d", addr, ev.Port),
			Fields:  map[string]string{"port": fmt.Sprint(ev.Port)},
		})
	case netEvUnlisten:
		a.rec.Unlisten(info.Entity, ev.Port)
	case netEvConnectStart:
		a.rec.Add(model.Event{
			Time: t, Entity: info.Entity, Type: model.EvConnect, PID: ev.Pid, Comm: comm,
			Message: fmt.Sprintf("connect to %s:%d", addr, ev.Port),
			Fields:  map[string]string{"dst": addr, "port": fmt.Sprint(ev.Port), "phase": "start"},
		})
	case netEvConnectDone:
		lat := time.Duration(ev.LatencyUs) * time.Microsecond
		if ev.Result == 0 {
			a.rec.Add(model.Event{
				Time: t, Entity: info.Entity, Type: model.EvConnect, Comm: comm,
				Message: fmt.Sprintf("connected to %s:%d in %s", addr, ev.Port, lat.Round(time.Microsecond)),
				Fields:  map[string]string{"dst": addr, "port": fmt.Sprint(ev.Port), "phase": "done", "latencyUs": fmt.Sprint(ev.LatencyUs)},
			})
		} else {
			reason := "refused"
			if ev.Result == -110 {
				reason = "timed out"
			}
			a.rec.Add(model.Event{
				Time: t, Entity: info.Entity, Type: model.EvConnFail, Severity: model.SevWarn, Comm: comm,
				Message: fmt.Sprintf("connect to %s:%d %s after %s", addr, ev.Port, reason, lat.Round(time.Microsecond)),
				Fields:  map[string]string{"dst": addr, "port": fmt.Sprint(ev.Port), "result": reason},
			})
		}
	}
}

func (c *netCollector) Collect(w *Window) {
	a := c.a
	drainMap(c.objs.Pairs, func(k bpf.NetPairKey, v *bpf.NetPairVal) {
		side := "client"
		if k.Side == 2 {
			side = "server"
		}
		owner := "unknown"
		if k.Cgroup != 0 {
			owner = a.resolver.Entity(k.Cgroup)
		}
		p := &model.Pair{
			Client:       ip16(k.Saddr),
			Server:       ip16(k.Daddr),
			Port:         k.Dport,
			Side:         side,
			Owner:        owner,
			RTT:          model.HistFromSlots(v.Rtt.Slots[:], v.Rtt.Count, v.Rtt.Sum),
			Connect:      model.HistFromSlots(v.Connlat.Slots[:], v.Connlat.Count, v.Connlat.Sum),
			BytesTx:      v.BytesTx,
			BytesRx:      v.BytesRx,
			Connects:     v.Connects,
			Closes:       v.Closes,
			LifetimeUs:   v.LifetimeUs,
			Refused:      v.Refused,
			Timeouts:     v.Timeouts,
			SynRetrans:   v.SynRetrans,
			Retrans:      v.Retrans,
			RetransLarge: v.RetransLarge,
			RstSent:      v.RstSent,
			RstRcvd:      v.RstRcvd,
			MTUReduced:   v.MtuReduced,
			ZeroWindow:   v.ZeroWindow,
		}
		w.AddPair(p)
	})
	c.scanSockets(w)
	drainMap(c.objs.ConnErrs, func(k bpf.NetConnErrKey, v *uint64) {
		e := w.Entity(a.resolver.Entity(k.Cgroup))
		if e.ConnErrors == nil {
			e.ConnErrors = map[string]uint64{}
		}
		e.ConnErrors[errnoName(k.Err)] += *v
	})

	// forget listeners of pods whose cgroups are gone
	pods := a.resolver.Pods()
	a.rec.PruneListens(func(entity string) bool {
		uid, ok := strings.CutPrefix(entity, "pod:")
		if !ok {
			return true
		}
		_, alive := pods[uid]
		return alive
	})

	// expire young cgroups
	now := monoNow()
	c.mu.Lock()
	for cg, exp := range c.young {
		if exp < now {
			delete(c.young, cg)
			_ = c.objs.Young.Delete(cg)
		}
	}
	c.mu.Unlock()
}

// idleAfter: a connection without received data for this long is idle.
const idleAfter = 30 * time.Second

// scanSockets counts established and idle connections per pair from the
// kernel socket table (connection pool health).
func (c *netCollector) scanSockets(w *Window) {
	a := c.a
	now := monoNow()
	// counted per pair as the window keys it: sockets of several cgroups
	// (containers of one pod) belong to the same pair
	counts := map[model.PairKey]*model.Pair{}
	owners := map[uint64]string{}
	var (
		k  uint64
		si bpf.NetSkInfo
	)
	it := c.objs.Socks.Iterate()
	for it.Next(&k, &si) {
		if si.HasKey == 0 || si.EstNs == 0 {
			continue
		}
		key := si.Key
		side := "client"
		if key.Side == 2 {
			side = "server"
		}
		owner, ok := owners[key.Cgroup]
		if !ok {
			owner = "unknown"
			if key.Cgroup != 0 {
				owner = a.resolver.Entity(key.Cgroup)
			}
			owners[key.Cgroup] = owner
		}
		p := &model.Pair{Client: ip16(key.Saddr), Server: ip16(key.Daddr), Port: key.Dport, Side: side, Owner: owner}
		x := counts[p.Key()]
		if x == nil {
			x = p
			counts[p.Key()] = x
		}
		x.OpenConns++
		last := si.LastRttNs
		if last == 0 {
			last = si.EstNs
		}
		if now > last && now-last > uint64(idleAfter) {
			x.IdleConns++
		}
	}
	for _, p := range counts {
		w.AddPair(p)
	}
}

func (c *netCollector) Close() error {
	if c.rd != nil {
		_ = c.rd.Close()
	}
	c.l.close()
	return c.objs.Close()
}
