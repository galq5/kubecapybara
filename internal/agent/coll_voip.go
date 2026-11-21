package agent

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/model"
	"github.com/galq5/kubecapybara/internal/sipparse"
)

const (
	sipTimeout = 32 * time.Second // RFC 3261 Timer B/F (64*T1)
	// sipProceedingTimeout bounds an INVITE that got a provisional
	// response: a 1xx stops Timer B and the call may ring for a minute or
	// more before it is answered (RFC 3261 Timer C, > 3 minutes).
	sipProceedingTimeout = 3 * time.Minute
	sipCallMaxAge        = 12 * time.Hour // forget calls whose BYE we missed
	rtpStreamIdle        = time.Minute
	sipMaxPending        = 200000
	sipMaxCalls          = 200000
	defaultRTPLow        = 16384
	defaultRTPHigh       = 32768
)

// voipCollector: SIP signalling (setup latency, response codes, answer
// ratio, calls) and RTP media quality (loss, jitter, one-way audio).
type voipCollector struct {
	a     *Agent
	objs  bpf.VoipObjects
	links []link.Link
	rd    *ringbuf.Reader

	mu   sync.Mutex
	sip  *sipTracker
	prev map[bpf.VoipRtpKey]rtpCounters
	// codecs learned from SDP (payload type -> name), node-wide
	codecs map[uint8]sipparse.Codec
	// entities with RTP in the previous interval (to zero their gauges)
	rtpActive map[string]bool
	// consecutive intervals each outbound stream had no inbound media
	oneWayRuns map[string]int
}

func (c *voipCollector) Name() string { return "voip" }

func (c *voipCollector) Start(a *Agent) error {
	c.a = a
	c.sip = newSIPTracker()
	c.prev = map[bpf.VoipRtpKey]rtpCounters{}
	c.codecs = map[uint8]sipparse.Codec{}
	c.rtpActive = map[string]bool{}
	c.oneWayRuns = map[string]int{}
	for pt, cd := range sipparse.Static {
		c.codecs[uint8(pt)] = cd
	}
	spec, err := bpf.LoadVoip()
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	var ports [4]uint16
	copy(ports[:], a.cfg.SIPPorts)
	lo, hi := a.cfg.RTPPortLow, a.cfg.RTPPortHigh
	if lo == 0 || hi == 0 {
		lo, hi = defaultRTPLow, defaultRTPHigh
	}
	for name, v := range map[string]any{"sip_ports": ports, "rtp_lo": lo, "rtp_hi": hi} {
		if err := spec.Variables[name].Set(v); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}
	if err := spec.LoadAndAssign(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	for pt, cd := range sipparse.Static {
		_ = c.objs.PtClock.Put(uint32(pt), uint32(cd.Clock))
	}
	root := a.resolver.Root()
	if _, err := os.Stat(root); err != nil {
		return err
	}
	for _, x := range []struct {
		p *ebpf.Program
		t ebpf.AttachType
	}{
		{c.objs.VoipEgress, ebpf.AttachCGroupInetEgress},
		{c.objs.VoipIngress, ebpf.AttachCGroupInetIngress},
	} {
		lk, err := link.AttachCgroup(link.CgroupOptions{Path: root, Attach: x.t, Program: x.p})
		if err != nil {
			return fmt.Errorf("attach cgroup skb to %s: %w", root, err)
		}
		c.links = append(c.links, lk)
	}
	rd, err := ringbuf.NewReader(c.objs.SipEvents)
	if err != nil {
		return err
	}
	c.rd = rd
	go c.read()
	a.log.Info("voip monitoring enabled", "sipPorts", a.cfg.SIPPorts, "rtpPorts", fmt.Sprintf("%d-%d", lo, hi))
	return nil
}

func (c *voipCollector) read() {
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		ev, ok := castSample[bpf.VoipSipEvent](rec.RawSample)
		if !ok {
			continue
		}
		n := min(int(ev.Len), len(ev.Data))
		msg, err := sipparse.Parse(ev.Data[:n])
		if err != nil {
			continue
		}
		entity := c.a.resolver.Entity(ev.Cgroup)
		peer := ip16(ev.Daddr)
		if ev.Egress == 0 {
			peer = ip16(ev.Saddr)
		}
		c.mu.Lock()
		if msg.SDP != nil {
			c.learnCodecs(msg.SDP)
		}
		evt := c.sip.handle(entity, peer, ev.Ts, ev.Egress == 1, msg)
		c.mu.Unlock()
		if evt != nil {
			evt.Time = c.a.clock.wall(ev.Ts)
			c.a.rec.Add(*evt)
		}
	}
}

// learnCodecs records dynamic payload types (Opus, AMR...) so that jitter is
// computed with the right clock rate. The mapping is node-wide: two calls
// using the same dynamic type for different codecs share the last one seen.
func (c *voipCollector) learnCodecs(s *sipparse.SDP) {
	for pt, cd := range s.Codecs {
		if pt < 0 || pt > 127 || cd.Clock <= 0 {
			continue
		}
		if c.codecs[uint8(pt)] != cd {
			c.codecs[uint8(pt)] = cd
			_ = c.objs.PtClock.Put(uint32(pt), uint32(cd.Clock))
		}
	}
}

func (c *voipCollector) Collect(w *Window) {
	now := monoNow()
	c.mu.Lock()
	cur, evs := c.sip.collect(now)
	// the reader goroutine adds codecs learned from SDP under c.mu
	codecs := maps.Clone(c.codecs)
	c.mu.Unlock()
	for _, ev := range evs {
		ev.Time = c.a.clock.wall(now)
		c.a.rec.Add(ev)
	}
	for id, st := range cur {
		e := w.Entity(id)
		if e.SIP == nil {
			e.SIP = &model.SIPStats{}
		}
		e.SIP.Merge(st)
	}

	// RTP: deltas of the in-kernel per-stream counters
	var key bpf.VoipRtpKey
	var val bpf.VoipRtpVal
	var stale []bpf.VoipRtpKey
	samples := map[string][]rtpSample{}
	seen := map[bpf.VoipRtpKey]bool{}
	it := c.objs.RtpStreams.Iterate()
	for it.Next(&key, &val) {
		seen[key] = true
		if now > val.LastSeen && now-val.LastSeen > uint64(rtpStreamIdle) {
			stale = append(stale, key)
			continue
		}
		cnt := rtpCountersOf(&val)
		d := rtpDelta(c.prev[key], cnt, c.prev[key].Packets > 0)
		c.prev[key] = cnt
		if d.Packets == 0 {
			continue
		}
		entity := c.a.resolver.Entity(key.Cgroup)
		samples[entity] = append(samples[entity], rtpSample{
			egress: key.Egress == 1, ssrc: key.Ssrc, peer: ip16(val.Raddr), peerPort: val.Rport, localPort: val.Lport,
			codec: codecs[val.Pt].Name, d: d, jitterUs: val.JitterNs / 1000, jitterMaxUs: val.JitterMaxNs / 1000,
		})
	}
	for _, k := range stale {
		_ = c.objs.RtpStreams.Delete(k)
		delete(c.prev, k)
	}
	for k := range c.prev {
		if !seen[k] {
			delete(c.prev, k) // evicted by the LRU
		}
	}
	active := map[string]bool{}
	runs := map[string]int{}
	for entity, ss := range samples {
		markOneWay(entity, ss, c.oneWayRuns, runs)
	}
	c.oneWayRuns = runs
	for entity, ss := range samples {
		active[entity] = true
		e := w.Entity(entity)
		if e.RTP == nil {
			e.RTP = &model.RTPStats{}
		}
		e.RTP.Merge(rtpStats(ss))
	}
	for entity := range c.rtpActive {
		if e := w.Entity(entity); !active[entity] && e.RTP == nil {
			e.RTP = &model.RTPStats{} // media stopped: report zero streams once
		}
	}
	c.rtpActive = active
}

func (c *voipCollector) Close() error {
	if c.rd != nil {
		_ = c.rd.Close()
	}
	for _, l := range c.links {
		_ = l.Close()
	}
	return c.objs.Close()
}

// ---------------------------------------------------------------- RTP maths

type rtpCounters struct {
	Packets, Expected, OOO, Resets uint64
}

func rtpCountersOf(v *bpf.VoipRtpVal) rtpCounters {
	c := rtpCounters{Packets: v.Packets, OOO: v.Ooo, Resets: v.Resets}
	if v.Init != 0 {
		ext := uint64(v.Cycles) + uint64(v.MaxSeq)
		if ext >= uint64(v.BaseSeq) {
			c.Expected = ext - uint64(v.BaseSeq) + 1
		}
	}
	return c
}

type rtpDeltaT struct {
	Packets, Expected, Lost, OOO uint64
}

// rtpDelta returns what happened between two reads of a stream's counters.
// After a source restart (sequence reset) the expected count restarts: that
// interval reports no loss.
func rtpDelta(prev, cur rtpCounters, hadPrev bool) rtpDeltaT {
	d := rtpDeltaT{Packets: sub(cur.Packets, prev.Packets), OOO: sub(cur.OOO, prev.OOO)}
	if !hadPrev {
		d.Expected = cur.Expected
		d.Lost = sub(cur.Expected, cur.Packets)
		return d
	}
	if cur.Resets != prev.Resets || cur.Expected < prev.Expected {
		d.Expected = d.Packets
		return d
	}
	d.Expected = sub(cur.Expected, prev.Expected)
	lostPrev := int64(prev.Expected) - int64(prev.Packets)
	lostCur := int64(cur.Expected) - int64(cur.Packets)
	if lostCur > lostPrev {
		d.Lost = uint64(lostCur - lostPrev)
	}
	if d.Lost > d.Expected {
		d.Lost = d.Expected
	}
	return d
}

type rtpSample struct {
	egress              bool
	ssrc                uint32
	peer                string
	peerPort, localPort uint16
	codec               string
	d                   rtpDeltaT
	jitterUs            uint64
	jitterMaxUs         uint64
	oneWay              bool
}

// oneWayIntervals is how long an outbound stream must get no inbound media
// from its peer before it counts as one-way audio: at the end of a call one
// side routinely stops sending a moment before the other.
const oneWayIntervals = 2

// markOneWay flags outbound streams whose peer has sent no RTP to this
// entity for oneWayIntervals consecutive intervals. prev holds the run
// lengths of the previous interval; next receives this interval's.
func markOneWay(entity string, ss []rtpSample, prev, next map[string]int) {
	inbound := map[string]bool{}
	for _, s := range ss {
		if !s.egress {
			inbound[s.peer] = true
		}
	}
	for i := range ss {
		s := &ss[i]
		if !s.egress || inbound[s.peer] {
			continue
		}
		k := entity + "|" + strconv.FormatUint(uint64(s.ssrc), 10)
		next[k] = prev[k] + 1
		s.oneWay = next[k] >= oneWayIntervals
	}
}

// rtpStats aggregates the active streams of one entity in one interval.
func rtpStats(ss []rtpSample) *model.RTPStats {
	r := &model.RTPStats{}
	for _, s := range ss {
		st := &model.RTPStream{SSRC: s.ssrc, Peer: s.peer, PeerPort: s.peerPort, LocalPort: s.localPort, Codec: s.codec, Packets: s.d.Packets}
		if s.egress {
			st.Dir = "out"
			r.PacketsOut += s.d.Packets
			r.StreamsOut++
			if s.oneWay {
				st.OneWay = true
				r.OneWay++
			}
		} else {
			st.Dir = "in"
			r.PacketsIn += s.d.Packets
			r.StreamsIn++
			r.Expected += s.d.Expected
			r.Lost += s.d.Lost
			r.OutOfOrder += s.d.OOO
			r.Jitter.Observe(s.jitterUs)
			r.JitterMaxUs = max(r.JitterMaxUs, s.jitterMaxUs)
			st.Expected, st.Lost, st.JitterUs, st.JitterMaxUs = s.d.Expected, s.d.Lost, s.jitterUs, s.jitterMaxUs
		}
		r.Streams = append(r.Streams, st)
	}
	r.Streams = model.SortStreams(r.Streams)
	return r
}

// ---------------------------------------------------------------- SIP state

type sipTxKey struct {
	entity, callID string
	cseq           uint32
	method, role   string
}

type sipTx struct {
	ts             uint64
	first, ringing bool
	uri, peer      string
}

type sipCall struct {
	entity string
	start  uint64
}

// sipTracker matches SIP requests and responses per entity.
type sipTracker struct {
	lastActive map[string]bool
	cur        map[string]*model.SIPStats
	pending    map[sipTxKey]*sipTx
	calls      map[string]*sipCall // entity|call-id
}

func newSIPTracker() *sipTracker {
	return &sipTracker{cur: map[string]*model.SIPStats{}, pending: map[sipTxKey]*sipTx{}, calls: map[string]*sipCall{}}
}

func (t *sipTracker) stats(entity string) *model.SIPStats {
	s, ok := t.cur[entity]
	if !ok {
		s = &model.SIPStats{}
		t.cur[entity] = s
	}
	return s
}

// handle processes one message seen by entity; egress is true when the
// entity sent it. It returns an event for notable failures.
func (t *sipTracker) handle(entity, peer string, ts uint64, egress bool, m *sipparse.Message) *model.Event {
	st := t.stats(entity)
	if egress && m.UserAgent != "" {
		st.UserAgent = m.UserAgent
	}
	callKey := entity + "|" + m.CallID
	if m.Request {
		if m.Method == "ACK" {
			return nil // no response; part of the INVITE transaction
		}
		role := "uas"
		if egress {
			role = "uac"
		}
		ms := st.Method(role, m.Method)
		k := sipTxKey{entity, m.CallID, m.CSeq, m.Method, role}
		if _, dup := t.pending[k]; dup {
			ms.Retrans++
			return nil
		}
		ms.Requests++
		if len(t.pending) < sipMaxPending {
			t.pending[k] = &sipTx{ts: ts, uri: m.URI, peer: peer}
		}
		if m.Method == "BYE" {
			if c, ok := t.calls[callKey]; ok {
				st.CallsEnded++
				if ts > c.start {
					st.CallSeconds += (ts - c.start) / uint64(time.Second)
				}
				delete(t.calls, callKey)
			}
		}
		return nil
	}

	role := "uac" // a response we receive answers our request
	if egress {
		role = "uas"
	}
	k := sipTxKey{entity, m.CallID, m.CSeq, m.Method, role}
	tx, ok := t.pending[k]
	if !ok {
		return nil // retransmitted response or request not seen
	}
	ms := st.Method(role, m.Method)
	lat := uint64(0)
	if ts > tx.ts {
		lat = (ts - tx.ts) / 1000
	}
	if !tx.first {
		tx.first = true
		ms.FirstResp.Observe(lat)
	}
	if ms.Codes == nil {
		ms.Codes = map[string]uint64{}
	}
	if (m.Status == 180 || m.Status == 183) && m.Method == "INVITE" && !tx.ringing {
		tx.ringing = true
		ms.Ringing.Observe(lat)
		ms.Codes[strconv.Itoa(m.Status)]++
	}
	if m.Status < 200 {
		return nil
	}
	ms.Final.Observe(lat)
	ms.Codes[strconv.Itoa(m.Status)]++
	delete(t.pending, k)
	if m.Method == "INVITE" && m.Status < 300 {
		if _, exists := t.calls[callKey]; !exists && len(t.calls) < sipMaxCalls {
			t.calls[callKey] = &sipCall{entity: entity, start: ts}
		}
	}
	if m.Method == "INVITE" && (m.Status >= 500 || m.Status == 408) {
		dir := "to"
		if role == "uas" {
			dir = "from"
		}
		return &model.Event{
			Entity: entity, Type: model.EvSIP, Severity: model.SevWarn,
			Message: fmt.Sprintf("SIP INVITE %s %s %s failed: %d %s after %s", tx.uri, dir, tx.peer, m.Status, m.Reason,
				roundLatency(time.Duration(lat)*time.Microsecond)),
			Fields: map[string]string{"code": strconv.Itoa(m.Status), "role": role, "peer": tx.peer},
		}
	}
	return nil
}

// collect returns the interval's stats and timeout events and resets.
func (t *sipTracker) collect(now uint64) (map[string]*model.SIPStats, []model.Event) {
	var evs []model.Event
	for k, tx := range t.pending {
		timeout := sipTimeout
		if k.method == "INVITE" && tx.first {
			timeout = sipProceedingTimeout // ringing: not a lost INVITE
		}
		if now > tx.ts && now-tx.ts > uint64(timeout) {
			delete(t.pending, k)
			t.stats(k.entity).Method(k.role, k.method).Timeouts++
			if k.method == "INVITE" && k.role == "uac" {
				evs = append(evs, model.Event{
					Entity: k.entity, Type: model.EvSIP, Severity: model.SevWarn,
					Message: fmt.Sprintf("SIP INVITE %s to %s got no final response within %s", tx.uri, tx.peer, timeout),
					Fields:  map[string]string{"code": "timeout", "role": k.role, "peer": tx.peer},
				})
			}
		}
	}
	active := map[string]uint64{}
	for k, c := range t.calls {
		if now > c.start && now-c.start > uint64(sipCallMaxAge) {
			delete(t.calls, k)
			continue
		}
		active[c.entity]++
	}
	for entity, n := range active {
		t.stats(entity).CallsActive = n
	}
	for entity := range t.lastActive {
		if active[entity] == 0 {
			t.stats(entity) // calls ended: report zero active calls once
		}
	}
	t.lastActive = map[string]bool{}
	for entity := range active {
		t.lastActive[entity] = true
	}
	cur := t.cur
	t.cur = map[string]*model.SIPStats{}
	return cur, evs
}
