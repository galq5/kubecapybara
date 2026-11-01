package render

import (
	"fmt"
	"io"

	"github.com/galq5/kubecapybara/internal/analysis"
)

// VoIP renders SIP call statistics and RTP media quality per pod.
func VoIP(w io.Writer, st Style, v *analysis.View, f Filter) {
	var rows []analysis.VoIPRow
	for _, r := range analysis.VoIP(v) {
		if f.ns(r.Endpoint) && f.match(r.Endpoint.Display(), r.UserAgent) {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, st.Dim("no SIP or RTP traffic observed (agent --voip; SIP on --sip-ports, RTP on --rtp-ports; TLS/SRTP signalling is not visible)"))
		return
	}

	fmt.Fprintln(w, st.Title("Calls (SIP)"))
	t := &Table{Headers: []string{"POD", "ATTEMPTS", "ANSWERED", "ASR", "FAILED", "PEAK CALLS", "AVG CALL", "PDD p50", "TRYING p99", "RETRANS", "CODES"},
		Right: map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true}, MaxCol: 40}
	for _, r := range rows {
		if r.Requests == 0 {
			continue
		}
		asr := "-"
		if r.Attempts > 0 {
			asr = analysis.Pct(r.ASR)
			if r.ASR < 0.5 && r.Attempts >= 5 {
				asr = st.Warn(asr)
			}
		}
		failed := fmt.Sprint(r.Failed)
		if r.Failed > 0 {
			failed = st.Warn(failed)
		}
		avg, pdd, trying := "-", "-", "-"
		if r.Ended > 0 {
			avg = analysis.Dur(r.AvgCall * 1e6)
		}
		if r.Ringing.Count > 0 {
			pdd = analysis.Dur(r.Ringing.P50())
		}
		if r.FirstResp.Count > 0 {
			trying = analysis.Dur(r.FirstResp.P99())
		}
		retr := fmt.Sprint(r.Retrans)
		if r.Requests >= 20 && float64(r.Retrans) >= 0.05*float64(r.Requests) {
			retr = st.Warn(retr)
		}
		t.AddRow(r.Endpoint.Display(), fmt.Sprint(r.Attempts), fmt.Sprint(r.Answered), asr, failed, fmt.Sprint(r.Active), avg, pdd, trying, retr, r.TopCodes(4))
	}
	t.Render(w, st)
	fmt.Fprintln(w, st.Dim("ASR = answered / attempts; PDD = post-dial delay (INVITE → 180/183); TRYING = INVITE → first response; busy/no-answer (486/480/487/603) are not failures"))

	fmt.Fprintln(w)
	fmt.Fprintln(w, st.Title("Media (RTP)"))
	t = &Table{Headers: []string{"POD", "STREAMS IN/OUT", "PKTS/s IN", "LOSS", "JITTER p50", "JITTER max", "ONE-WAY", "CPU WAIT", "WORST STREAM"},
		Right: map[int]bool{2: true, 3: true, 4: true, 5: true, 6: true, 7: true}, MaxCol: 50}
	for _, r := range rows {
		m := r.RTP
		if m == nil || m.PacketsIn+m.PacketsOut == 0 {
			continue
		}
		loss := analysis.Pct(m.LossRatio())
		if m.LossRatio() >= 0.01 && m.Expected >= 500 {
			loss = st.Warn(loss)
		}
		jp50 := "-"
		if m.Jitter.Count > 0 {
			jp50 = analysis.Dur(m.Jitter.P50())
			if m.Jitter.P50() >= 30e3 {
				jp50 = st.Warn(jp50)
			}
		}
		one := fmt.Sprint(m.OneWay)
		if m.OneWay > 0 {
			one = st.Warn(one)
		}
		wait := "-"
		if r.CPUWait > 0 {
			wait = analysis.Dur(r.CPUWait*1e6) + "/s"
		}
		worst := ""
		if len(m.Streams) > 0 {
			s := m.Streams[0]
			worst = fmt.Sprintf("%s %s:%d %s", s.Dir, s.Peer, s.PeerPort, s.Codec)
			switch {
			case s.OneWay:
				worst += " one-way"
			case s.Expected > 0:
				worst += " loss " + analysis.Pct(s.LossRatio())
			}
		}
		t.AddRow(r.Endpoint.Display(), fmt.Sprintf("%d/%d", m.StreamsIn, m.StreamsOut), analysis.Rate(v.PerSec(m.PacketsIn)), loss,
			jp50, analysis.Dur(float64(m.JitterMaxUs)), one, wait, worst)
	}
	t.Render(w, st)
	fmt.Fprintln(w, st.Dim("loss and jitter are measured on inbound media (RFC 3550); audio degrades above ~1% loss or ~30ms jitter; CPU WAIT = time the pod waited for a CPU per second on CPU"))
}
