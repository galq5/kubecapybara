package agent

import (
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
	"github.com/galq5/kubecapybara/internal/sipparse"
)

func sipReq(method, callID string, cseq uint32) *sipparse.Message {
	return &sipparse.Message{Request: true, Method: method, URI: "sip:1000@pbx", CallID: callID, CSeq: cseq}
}

func sipResp(code int, method, callID string, cseq uint32) *sipparse.Message {
	return &sipparse.Message{Status: code, Reason: "x", Method: method, CallID: callID, CSeq: cseq}
}

const ms = uint64(time.Millisecond)

func TestSIPTrackerCall(t *testing.T) {
	tr := newSIPTracker()
	fs := "pod:fs"
	// FreeSWITCH places a call (uac): INVITE, retransmit, 100, 180, 200, later BYE
	tr.handle(fs, "10.0.0.9", 0, true, sipReq("INVITE", "c1", 1))
	tr.handle(fs, "10.0.0.9", 500*ms, true, sipReq("INVITE", "c1", 1)) // retransmission
	tr.handle(fs, "10.0.0.9", 520*ms, false, sipResp(100, "INVITE", "c1", 1))
	tr.handle(fs, "10.0.0.9", 2000*ms, false, sipResp(180, "INVITE", "c1", 1))
	tr.handle(fs, "10.0.0.9", 9000*ms, false, sipResp(200, "INVITE", "c1", 1))
	tr.handle(fs, "10.0.0.9", 9001*ms, false, sipResp(200, "INVITE", "c1", 1)) // retransmitted 200: ignored
	tr.handle(fs, "10.0.0.9", 9002*ms, true, sipReq("ACK", "c1", 1))

	cur, evs := tr.collect(10000 * ms)
	if len(evs) != 0 {
		t.Fatalf("events %v", evs)
	}
	inv := cur[fs].Methods["uac INVITE"]
	if inv == nil || inv.Requests != 1 || inv.Retrans != 1 {
		t.Fatalf("invite %+v", inv)
	}
	if inv.Codes["200"] != 1 || inv.Codes["180"] != 1 || len(inv.Codes) != 2 {
		t.Fatalf("codes %v", inv.Codes)
	}
	if p := inv.FirstResp.P50(); p < 262e3 || p > 525e3 { // log2 bucket of 520ms
		t.Fatalf("first response %v µs", p)
	}
	if inv.Ringing.Count != 1 || inv.Final.Count != 1 || inv.Final.Sum < 8_900_000 {
		t.Fatalf("ringing/final %+v %+v", inv.Ringing, inv.Final)
	}
	if cur[fs].CallsActive != 1 {
		t.Fatalf("active calls %d", cur[fs].CallsActive)
	}

	// remote hangs up 60s later (BYE received: uas transaction)
	tr.handle(fs, "10.0.0.9", 69000*ms, false, sipReq("BYE", "c1", 2))
	tr.handle(fs, "10.0.0.9", 69001*ms, true, sipResp(200, "BYE", "c1", 2))
	cur, _ = tr.collect(70000 * ms)
	s := cur[fs]
	if s.CallsEnded != 1 || s.CallSeconds != 60 || s.CallsActive != 0 {
		t.Fatalf("call end %+v", s)
	}
	if bye := s.Methods["uas BYE"]; bye == nil || bye.Codes["200"] != 1 {
		t.Fatalf("bye %+v", s.Methods)
	}
}

func TestSIPTrackerFailuresAndTimeouts(t *testing.T) {
	tr := newSIPTracker()
	fs := "pod:fs"
	// inbound call rejected by us (uas): event
	tr.handle(fs, "10.0.0.7", 0, false, sipReq("INVITE", "c2", 1))
	ev := tr.handle(fs, "10.0.0.7", 30*ms, true, sipResp(503, "INVITE", "c2", 1))
	if ev == nil || ev.Type != model.EvSIP || ev.Fields["code"] != "503" || ev.Fields["role"] != "uas" {
		t.Fatalf("event %+v", ev)
	}
	// busy is a normal outcome: no event
	tr.handle(fs, "10.0.0.7", 0, true, sipReq("INVITE", "c3", 1))
	if ev := tr.handle(fs, "10.0.0.7", 10*ms, false, sipResp(486, "INVITE", "c3", 1)); ev != nil {
		t.Fatalf("486 produced an event: %v", ev)
	}
	// unanswered outbound INVITE times out
	tr.handle(fs, "10.0.0.8", 1000*ms, true, sipReq("INVITE", "c4", 1))
	cur, evs := tr.collect(40000 * ms)
	if inv := cur[fs].Methods["uac INVITE"]; inv.Timeouts != 1 || inv.Codes["486"] != 1 {
		t.Fatalf("uac invite %+v", inv)
	}
	if len(evs) != 1 || evs[0].Fields["code"] != "timeout" {
		t.Fatalf("timeout events %v", evs)
	}
	if tot, ok := cur[fs].Methods["uas INVITE"].Finals(); tot != 1 || ok != 0 {
		t.Fatalf("finals %d %d", tot, ok)
	}
}

func TestRTPDelta(t *testing.T) {
	// first read: 100 expected, 97 received
	d := rtpDelta(rtpCounters{}, rtpCounters{Packets: 97, Expected: 100}, false)
	if d.Expected != 100 || d.Lost != 3 || d.Packets != 97 {
		t.Fatalf("first %+v", d)
	}
	// next interval: 250 more expected, 245 more received -> 5 lost
	d = rtpDelta(rtpCounters{Packets: 97, Expected: 100}, rtpCounters{Packets: 342, Expected: 350}, true)
	if d.Expected != 250 || d.Lost != 5 {
		t.Fatalf("next %+v", d)
	}
	// late packets arriving (received catches up): no negative loss
	d = rtpDelta(rtpCounters{Packets: 342, Expected: 350}, rtpCounters{Packets: 400, Expected: 400}, true)
	if d.Lost != 0 || d.Expected != 50 {
		t.Fatalf("catch-up %+v", d)
	}
	// source restarted: no bogus loss
	d = rtpDelta(rtpCounters{Packets: 400, Expected: 400}, rtpCounters{Packets: 450, Expected: 20, Resets: 1}, true)
	if d.Lost != 0 || d.Expected != 50 {
		t.Fatalf("reset %+v", d)
	}
}

func TestRTPStatsOneWay(t *testing.T) {
	sample := func() []rtpSample {
		return []rtpSample{
			{egress: false, ssrc: 1, peer: "10.0.0.9", d: rtpDeltaT{Packets: 240, Expected: 250, Lost: 10}, jitterUs: 4000, jitterMaxUs: 9000},
			{egress: true, ssrc: 2, peer: "10.0.0.9", d: rtpDeltaT{Packets: 250}},
			{egress: true, ssrc: 3, peer: "10.0.0.50", d: rtpDeltaT{Packets: 250}}, // nothing comes back
		}
	}
	// first interval without inbound media: not yet one-way (end-of-call race)
	runs := map[string]int{}
	ss := sample()
	markOneWay("pod:fs", ss, map[string]int{}, runs)
	if r := rtpStats(ss); r.OneWay != 0 {
		t.Fatalf("one-way after a single interval: %+v", r)
	}
	ss = sample()
	next := map[string]int{}
	markOneWay("pod:fs", ss, runs, next)
	r := rtpStats(ss)
	if r.StreamsIn != 1 || r.StreamsOut != 2 || r.OneWay != 1 || r.Lost != 10 || r.Expected != 250 || r.JitterMaxUs != 9000 {
		t.Fatalf("%+v", r)
	}
	if r.Streams[0].SSRC != 3 || !r.Streams[0].OneWay {
		t.Fatalf("worst stream first: %+v", r.Streams[0])
	}
	// window merge keeps per-stream totals
	agg := &model.RTPStats{}
	agg.Merge(r)
	agg.Merge(r)
	for _, s := range agg.Streams {
		if s.SSRC == 1 && (s.Expected != 500 || s.Lost != 20) {
			t.Fatalf("merged stream %+v", s)
		}
	}
	if agg.StreamsOut != 2 || agg.Lost != 20 {
		t.Fatalf("merged %+v", agg)
	}
}
