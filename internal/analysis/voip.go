package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/galq5/kubecapybara/internal/model"
)

// VoIPRow summarises the SIP signalling and RTP media of one entity.
type VoIPRow struct {
	Entity    string
	Endpoint  Endpoint
	UserAgent string
	// INVITE transactions (both roles)
	Attempts  uint64 // INVITEs with a final response or a timeout
	Answered  uint64
	Failed    uint64 // 5xx/6xx and timeouts
	UserBusy  uint64 // 486/480/487/603: the callee, not the system
	ASR       float64
	Retrans   uint64
	Requests  uint64 // all SIP requests
	Codes     map[string]uint64
	Ringing   model.Hist // post-dial delay
	FirstResp model.Hist // to 100 Trying
	Setup     model.Hist // to final response
	Active    uint64
	Ended     uint64
	AvgCall   float64 // seconds
	RTP       *model.RTPStats
	// CPUWait is the time waiting for a CPU per second on CPU (jitter
	// often comes from CPU starvation of the media threads).
	CPUWait float64
}

var userCodes = map[string]bool{"486": true, "480": true, "487": true, "603": true, "404": true}

// VoIP returns one row per entity with SIP or RTP activity, busiest first.
func VoIP(v *View) []VoIPRow {
	var out []VoIPRow
	for _, e := range v.Entities {
		st := e.Stats
		if st.SIP == nil && (st.RTP == nil || st.RTP.PacketsIn+st.RTP.PacketsOut == 0) {
			continue
		}
		r := VoIPRow{Entity: e.ID, Endpoint: e.Endpoint, RTP: st.RTP, Codes: map[string]uint64{}}
		if sp := st.SIP; sp != nil {
			r.UserAgent, r.Active, r.Ended = sp.UserAgent, sp.CallsActive, sp.CallsEnded
			if sp.CallsEnded > 0 {
				r.AvgCall = float64(sp.CallSeconds) / float64(sp.CallsEnded)
			}
			for _, m := range sp.Methods {
				r.Requests += m.Requests
				r.Retrans += m.Retrans
				if m.Method != "INVITE" {
					continue
				}
				for c, n := range m.Codes {
					r.Codes[c] += n
				}
				total, ok := m.Finals()
				r.Attempts += total + m.Timeouts
				r.Answered += ok
				r.Failed += m.Timeouts
				for c, n := range m.Codes {
					switch {
					case userCodes[c]:
						r.UserBusy += n
					case c >= "500" || c == "408":
						r.Failed += n
					}
				}
				r.Ringing.Add(m.Ringing)
				r.FirstResp.Add(m.FirstResp)
				r.Setup.Add(m.Final)
			}
			if r.Attempts > 0 {
				r.ASR = float64(r.Answered) / float64(r.Attempts)
			}
		}
		if s := st.Sched; s != nil && s.OnCPUNs > 0 {
			r.CPUWait = float64(s.OffNs[model.StateRunQ]) / float64(s.OnCPUNs)
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Attempts != b.Attempts {
			return a.Attempts > b.Attempts
		}
		return a.Endpoint.Display() < b.Endpoint.Display()
	})
	return out
}

// TopCodes formats the most frequent final codes ("503×4 486×2").
func (r VoIPRow) TopCodes(n int) string {
	type kv struct {
		code  string
		count uint64
	}
	var all []kv
	for c, k := range r.Codes {
		if c != "180" && c != "183" {
			all = append(all, kv{c, k})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].count != all[j].count {
			return all[i].count > all[j].count
		}
		return all[i].code < all[j].code
	})
	var parts []string
	for i, x := range all {
		if i == n {
			break
		}
		parts = append(parts, fmt.Sprintf("%s×%d", x.code, x.count))
	}
	return strings.Join(parts, " ")
}

// Voice quality thresholds (ITU-T G.114/G.1020 rules of thumb).
const (
	rtpLossCrit = 0.05
	sipPDDWarn  = 5e6 // µs post-dial delay p50
)

func ruleVoIP(v *View) []Finding {
	var (
		out                                 []Finding
		fail, slow, retrans, loss, one, jit []string
		failSubj, lossSubj, oneSubj, jitSub []string
		failScore, lossScore                float64
		lossSev                             = SevWarn
	)
	for _, r := range VoIP(v) {
		name := r.Endpoint.Display()
		if r.Attempts >= 5 && float64(r.Failed) >= 0.1*float64(r.Attempts) {
			fail = append(fail, fmt.Sprintf("%s: %d of %d call attempts failed (%s), answer ratio %s",
				name, r.Failed, r.Attempts, r.TopCodes(3), Pct(r.ASR)))
			failSubj = append(failSubj, r.Entity)
			failScore += float64(r.Failed)
		}
		if r.Ringing.Count >= 5 && r.Ringing.P50() > sipPDDWarn {
			slow = append(slow, fmt.Sprintf("%s: post-dial delay p50 %s (INVITE → ringing)", name, Dur(r.Ringing.P50())))
		}
		if r.Requests >= 20 && float64(r.Retrans) >= 0.05*float64(r.Requests) {
			retrans = append(retrans, fmt.Sprintf("%s: %d of %d SIP requests retransmitted", name, r.Retrans, r.Requests))
		}
		rtp := r.RTP
		if rtp == nil {
			continue
		}
		if rtp.Expected >= 500 && rtp.LossRatio() >= v.th("rtp-loss-ratio") {
			line := fmt.Sprintf("%s: %s of inbound RTP packets lost (%d of %d)", name, Pct(rtp.LossRatio()), rtp.Lost, rtp.Expected)
			if w := worstStream(rtp); w != nil && w.Lost > 0 {
				line += fmt.Sprintf("; worst stream from %s:%d (%s, %s lost)", w.Peer, w.PeerPort, nonEmpty(w.Codec, "?"), Pct(w.LossRatio()))
			}
			loss = append(loss, line)
			lossSubj = append(lossSubj, r.Entity)
			lossScore += rtp.LossRatio() * 100
			if rtp.LossRatio() >= rtpLossCrit {
				lossSev = SevCrit
			}
		}
		if rtp.Jitter.Count >= 5 && rtp.Jitter.P90() >= v.th("rtp-jitter-ms")*1e3 {
			line := fmt.Sprintf("%s: RTP jitter p90 %s, max %s", name, Dur(rtp.Jitter.P90()), Dur(float64(rtp.JitterMaxUs)))
			if r.CPUWait >= 0.05 {
				line += fmt.Sprintf("; the pod also waits %s for CPU per 1s on CPU", Dur(r.CPUWait*1e6))
			}
			jit = append(jit, line)
			jitSub = append(jitSub, r.Entity)
		}
		if rtp.OneWay > 0 {
			var peers []string
			for _, s := range rtp.Streams {
				if s.OneWay {
					peers = append(peers, fmt.Sprintf("%s:%d", s.Peer, s.PeerPort))
				}
			}
			one = append(one, fmt.Sprintf("%s: sends RTP to %s but receives nothing back", name, strings.Join(top(peers, 3), ", ")))
			oneSubj = append(oneSubj, r.Entity)
		}
	}
	if len(fail) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "voip", Rule: "sip-failures", Title: "SIP calls failing (5xx/6xx or no answer)",
			Detail: fail, Subjects: failSubj, Score: failScore,
			Hint: "503: overloaded or no route/gateway (check sessions-per-second and max-sessions limits); 408/timeouts: the peer is unreachable or SIP packets are dropped (MTU: large INVITEs over UDP fragment)"})
	}
	if len(slow) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "voip", Rule: "sip-slow-setup", Title: "slow call setup (long post-dial delay)",
			Detail: slow, Hint: "check DNS (NAPTR/SRV lookups), database lookups in the dialplan and the upstream carrier's own latency"})
	}
	if len(retrans) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "voip", Rule: "sip-retransmissions", Title: "SIP retransmissions (requests not answered in time)",
			Detail: retrans, Hint: "packet loss on the signalling path or a peer too slow to answer within 500ms (T1); compare with network drops and CPU wait"})
	}
	if len(loss) > 0 {
		out = append(out, Finding{Severity: lossSev, Category: "voip", Rule: "rtp-loss", Title: "RTP packet loss (audible above ~1%)",
			Detail: loss, Subjects: lossSubj, Score: lossScore,
			Hint: "look for drops (kubectl capybara doctor: drops / NIC ring), CPU throttling of the media pod, and loss upstream of the node"})
	}
	if len(jit) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "voip", Rule: "rtp-jitter", Title: "high RTP jitter (choppy audio)",
			Detail: jit, Subjects: jitSub,
			Hint: "jitter added inside the node usually means CPU starvation: give the media pod guaranteed CPU (requests = limits, static CPU manager) and avoid CFS throttling"})
	}
	if len(one) > 0 {
		out = append(out, Finding{Severity: SevWarn, Category: "voip", Rule: "rtp-one-way", Title: "one-way audio (media sent but nothing received)",
			Detail: one, Subjects: oneSubj,
			Hint: "typically NAT/SDP problems (wrong ext-rtp-ip, private address in SDP), a firewall or NetworkPolicy blocking the RTP port range, or a call on hold"})
	}
	return out
}

func worstStream(r *model.RTPStats) *model.RTPStream {
	var w *model.RTPStream
	for _, s := range r.Streams {
		if s.Dir == "in" && (w == nil || s.LossRatio() > w.LossRatio()) {
			w = s
		}
	}
	return w
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
