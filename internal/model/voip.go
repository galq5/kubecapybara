package model

import "sort"

// SIPStats aggregates SIP signalling of an entity (e.g. a FreeSWITCH pod).
type SIPStats struct {
	// Methods by "<role> <METHOD>": role uac when this entity sent the
	// request, uas when it received it.
	Methods map[string]*SIPMethod `json:"methods,omitempty"`
	// CallsActive is the highest number of established calls (INVITE
	// answered, no BYE yet) seen in the range.
	CallsActive uint64 `json:"callsActive,omitempty"`
	CallsEnded  uint64 `json:"callsEnded,omitempty"`
	CallSeconds uint64 `json:"callSeconds,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
}

// SIPMethod aggregates transactions of one method and role.
type SIPMethod struct {
	Method   string            `json:"method"`
	Role     string            `json:"role"` // uac or uas
	Requests uint64            `json:"requests"`
	Retrans  uint64            `json:"retrans,omitempty"`  // retransmitted requests
	Timeouts uint64            `json:"timeouts,omitempty"` // no final response within 32s
	Codes    map[string]uint64 `json:"codes,omitempty"`    // final (and 18x) status codes
	// FirstResp: request to first response (usually 100 Trying).
	FirstResp Hist `json:"firstResp"`
	// Ringing: INVITE to 180/183 (post-dial delay).
	Ringing Hist `json:"ringing"`
	// Final: request to final response (>= 200).
	Final Hist `json:"final"`
}

// Finals returns the number of final responses and how many were 2xx.
func (m *SIPMethod) Finals() (total, ok uint64) {
	for c, n := range m.Codes {
		if len(c) == 3 && c[0] >= '2' {
			total += n
			if c[0] == '2' {
				ok += n
			}
		}
	}
	return
}

// Merge adds o into m.
func (m *SIPMethod) Merge(o *SIPMethod) {
	m.Method, m.Role = o.Method, o.Role
	m.Requests += o.Requests
	m.Retrans += o.Retrans
	m.Timeouts += o.Timeouts
	if len(o.Codes) > 0 && m.Codes == nil {
		m.Codes = map[string]uint64{}
	}
	for c, n := range o.Codes {
		m.Codes[c] += n
	}
	m.FirstResp.Add(o.FirstResp)
	m.Ringing.Add(o.Ringing)
	m.Final.Add(o.Final)
}

// Method returns (creating) the stats of a method and role.
func (s *SIPStats) Method(role, method string) *SIPMethod {
	if s.Methods == nil {
		s.Methods = map[string]*SIPMethod{}
	}
	k := role + " " + method
	m, ok := s.Methods[k]
	if !ok {
		m = &SIPMethod{Method: method, Role: role}
		s.Methods[k] = m
	}
	return m
}

// Merge adds o into s.
func (s *SIPStats) Merge(o *SIPStats) {
	for _, m := range o.Methods {
		s.Method(m.Role, m.Method).Merge(m)
	}
	if o.CallsActive > s.CallsActive {
		s.CallsActive = o.CallsActive
	}
	s.CallsEnded += o.CallsEnded
	s.CallSeconds += o.CallSeconds
	if o.UserAgent != "" {
		s.UserAgent = o.UserAgent
	}
}

// RTPStats aggregates RTP media of an entity.
type RTPStats struct {
	PacketsIn  uint64 `json:"packetsIn,omitempty"`
	PacketsOut uint64 `json:"packetsOut,omitempty"`
	// Expected and Lost count inbound packets (from sequence numbers).
	Expected   uint64 `json:"expected,omitempty"`
	Lost       uint64 `json:"lost,omitempty"`
	OutOfOrder uint64 `json:"outOfOrder,omitempty"`
	// StreamsIn/Out/OneWay are gauges: the highest count in the range.
	StreamsIn  uint64 `json:"streamsIn,omitempty"`
	StreamsOut uint64 `json:"streamsOut,omitempty"`
	// OneWay counts outbound streams to a peer that sends nothing back.
	OneWay uint64 `json:"oneWay,omitempty"`
	// Jitter holds one sample (µs) per inbound stream per collection interval.
	Jitter      Hist         `json:"jitter"`
	JitterMaxUs uint64       `json:"jitterMaxUs,omitempty"`
	Streams     []*RTPStream `json:"streams,omitempty"` // worst streams
}

// RTPStream is the state of one RTP stream.
type RTPStream struct {
	SSRC        uint32 `json:"ssrc"`
	Dir         string `json:"dir"` // in or out
	Peer        string `json:"peer"`
	PeerPort    uint16 `json:"peerPort,omitempty"`
	LocalPort   uint16 `json:"localPort,omitempty"`
	Codec       string `json:"codec,omitempty"`
	Packets     uint64 `json:"packets"`
	Expected    uint64 `json:"expected,omitempty"`
	Lost        uint64 `json:"lost,omitempty"`
	JitterUs    uint64 `json:"jitterUs,omitempty"`
	JitterMaxUs uint64 `json:"jitterMaxUs,omitempty"`
	OneWay      bool   `json:"oneWay,omitempty"`
}

// LossRatio returns lost/expected.
func (s *RTPStream) LossRatio() float64 {
	if s.Expected == 0 {
		return 0
	}
	return float64(s.Lost) / float64(s.Expected)
}

// LossRatio returns lost/expected for inbound media.
func (r *RTPStats) LossRatio() float64 {
	if r.Expected == 0 {
		return 0
	}
	return float64(r.Lost) / float64(r.Expected)
}

// MaxStreams bounds RTPStats.Streams.
const MaxStreams = 10

// SortStreams orders streams worst first (one-way, loss, jitter) and keeps
// MaxStreams.
func SortStreams(st []*RTPStream) []*RTPStream {
	sort.SliceStable(st, func(i, j int) bool {
		a, b := st[i], st[j]
		if a.OneWay != b.OneWay {
			return a.OneWay
		}
		if la, lb := a.LossRatio(), b.LossRatio(); la != lb {
			return la > lb
		}
		return a.JitterUs > b.JitterUs
	})
	if len(st) > MaxStreams {
		st = st[:MaxStreams]
	}
	return st
}

// Merge adds o into r.
func (r *RTPStats) Merge(o *RTPStats) {
	r.PacketsIn += o.PacketsIn
	r.PacketsOut += o.PacketsOut
	r.Expected += o.Expected
	r.Lost += o.Lost
	r.OutOfOrder += o.OutOfOrder
	r.StreamsIn = max(r.StreamsIn, o.StreamsIn)
	r.StreamsOut = max(r.StreamsOut, o.StreamsOut)
	r.OneWay = max(r.OneWay, o.OneWay)
	r.Jitter.Add(o.Jitter)
	r.JitterMaxUs = max(r.JitterMaxUs, o.JitterMaxUs)
	// streams: accumulate per (ssrc, dir)
	idx := map[[2]uint64]*RTPStream{}
	for _, s := range r.Streams {
		idx[streamKey(s)] = s
	}
	for _, s := range o.Streams {
		if cur, ok := idx[streamKey(s)]; ok {
			cur.Packets += s.Packets
			cur.Expected += s.Expected
			cur.Lost += s.Lost
			cur.JitterUs = s.JitterUs // latest
			cur.JitterMaxUs = max(cur.JitterMaxUs, s.JitterMaxUs)
			cur.OneWay = s.OneWay
			continue
		}
		c := *s
		r.Streams = append(r.Streams, &c)
		idx[streamKey(s)] = &c
	}
	r.Streams = SortStreams(r.Streams)
}

func streamKey(s *RTPStream) [2]uint64 {
	d := uint64(0)
	if s.Dir == "out" {
		d = 1
	}
	return [2]uint64{uint64(s.SSRC), d}
}
