package analysis

import (
	"testing"

	"github.com/galq5/kubecapybara/internal/model"
)

func voipView(sip *model.SIPStats, rtp *model.RTPStats, runqNs uint64) *View {
	st := &model.EntityStats{ID: "pod:fs", SIP: sip, RTP: rtp,
		Sched: &model.SchedStats{OnCPUNs: 1e9, OffNs: map[string]uint64{model.StateRunQ: runqNs}}}
	return &View{Entities: map[string]*EntityView{"pod:fs": {ID: "pod:fs", Stats: st,
		Endpoint: Endpoint{Kind: KindPod, Namespace: "voice", Name: "freeswitch-0", Workload: "StatefulSet/freeswitch"}}}}
}

func byRule(fs []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		out[f.Rule] = f
	}
	return out
}

func TestVoIPRows(t *testing.T) {
	sip := &model.SIPStats{}
	inv := sip.Method("uas", "INVITE")
	inv.Requests, inv.Retrans, inv.Timeouts = 20, 3, 1
	inv.Codes = map[string]uint64{"200": 10, "486": 4, "503": 5, "180": 9}
	for i := 0; i < 9; i++ {
		inv.Ringing.Observe(8e6) // 8s post-dial delay
	}
	rows := VoIP(voipView(sip, nil, 0))
	if len(rows) != 1 {
		t.Fatalf("rows %d", len(rows))
	}
	r := rows[0]
	if r.Attempts != 20 || r.Answered != 10 || r.Failed != 6 || r.UserBusy != 4 || r.ASR != 0.5 {
		t.Fatalf("%+v", r)
	}
	if got := r.TopCodes(2); got != "200×10 503×5" {
		t.Fatalf("top codes %q", got)
	}
	f := byRule(ruleVoIP(voipView(sip, nil, 0)))
	if sf, ok := f["sip-failures"]; !ok {
		t.Error("missing sip-failures")
	} else if d := sf.Detail[0]; contains(d, "200×") || !contains(d, "503×5") {
		t.Errorf("failure detail should list failure codes only: %s", d)
	}
	if _, ok := f["sip-slow-setup"]; !ok {
		t.Error("missing sip-slow-setup")
	}
	if _, ok := f["sip-retransmissions"]; !ok {
		t.Error("missing sip-retransmissions")
	}
}

func TestVoIPMediaRules(t *testing.T) {
	rtp := &model.RTPStats{PacketsIn: 9000, PacketsOut: 10000, Expected: 10000, Lost: 600, StreamsIn: 1, StreamsOut: 2, OneWay: 1,
		JitterMaxUs: 80000, Streams: []*model.RTPStream{
			{SSRC: 1, Dir: "out", Peer: "203.0.113.9", PeerPort: 30000, OneWay: true},
			{SSRC: 2, Dir: "in", Peer: "198.51.100.7", PeerPort: 20000, Codec: "PCMA", Expected: 10000, Lost: 600},
		}}
	for i := 0; i < 10; i++ {
		rtp.Jitter.Observe(45e3)
	}
	f := byRule(ruleVoIP(voipView(nil, rtp, 2e8)))
	loss, ok := f["rtp-loss"]
	if !ok || loss.Severity != SevCrit {
		t.Fatalf("rtp-loss %+v", loss)
	}
	if j := f["rtp-jitter"]; len(j.Detail) != 1 || !contains(j.Detail[0], "waits") {
		t.Fatalf("jitter should mention CPU wait: %+v", j)
	}
	if o := f["rtp-one-way"]; len(o.Detail) != 1 || !contains(o.Detail[0], "203.0.113.9:30000") {
		t.Fatalf("one-way %+v", o)
	}
	// healthy media: nothing
	ok2 := &model.RTPStats{PacketsIn: 9990, Expected: 10000, Lost: 10, StreamsIn: 1}
	for i := 0; i < 10; i++ {
		ok2.Jitter.Observe(3e3)
	}
	if fs := ruleVoIP(voipView(nil, ok2, 0)); len(fs) != 0 {
		t.Fatalf("healthy media flagged: %+v", fs)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
