package sipparse

import (
	"strings"
	"testing"
)

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

func TestInviteWithSDP(t *testing.T) {
	m, err := Parse(crlf(`INVITE sip:1000@pbx.example.com SIP/2.0
Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK776asdhds
From: <sip:alice@example.com>;tag=1928301774
To: <sip:1000@pbx.example.com>
i: a84b4c76e66710@10.0.0.5
CSeq: 314159 INVITE
User-Agent: FreeSWITCH-mod_sofia/1.10.11
c: application/sdp

v=0
o=- 1 1 IN IP4 10.0.0.5
c=IN IP4 10.0.0.5
m=audio 16500 RTP/AVP 111 0 8 101
a=rtpmap:111 opus/48000/2
a=rtpmap:101 telephone-event/8000
m=video 16502 RTP/AVP 96
a=rtpmap:96 VP8/90000
`))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Request || m.Method != "INVITE" || m.CallID != "a84b4c76e66710@10.0.0.5" || m.CSeq != 314159 || m.FromTag != "1928301774" {
		t.Fatalf("%+v", m)
	}
	if m.UserAgent != "FreeSWITCH-mod_sofia/1.10.11" {
		t.Fatalf("ua %q", m.UserAgent)
	}
	s := m.SDP
	if s == nil || s.Addr != "10.0.0.5" || s.AudioPort != 16500 {
		t.Fatalf("sdp %+v", s)
	}
	if s.Codecs[111] != (Codec{"opus", 48000}) || s.Codecs[0].Name != "PCMU" || s.Codecs[101].Clock != 8000 {
		t.Fatalf("codecs %+v", s.Codecs)
	}
	if _, ok := s.Codecs[96]; ok {
		t.Fatal("video codec in audio map")
	}
}

func TestResponse(t *testing.T) {
	m, err := Parse(crlf(`SIP/2.0 486 Busy Here
Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK776asdhds
To: <sip:1000@pbx.example.com>;tag=a6c85cf
Call-ID: a84b4c76e66710@10.0.0.5
CSeq: 314159 INVITE
Content-Length: 0

`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Request || m.Status != 486 || m.Reason != "Busy Here" || m.Method != "INVITE" || m.ToTag != "a6c85cf" {
		t.Fatalf("%+v", m)
	}
}

func TestTruncatedAndGarbage(t *testing.T) {
	full := crlf("BYE sip:a@b SIP/2.0\nCall-ID: x1\nCSeq: 2 BYE\nVia: SIP/2.0/UDP 1.2.3.4;branch=z9h")
	if m, err := Parse(full); err != nil || m.Method != "BYE" || m.CSeq != 2 {
		t.Fatalf("truncated: %+v %v", m, err)
	}
	for _, s := range []string{"", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "SIP/2.0 999 Nope\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n", "\x80\x00garbage",
		"INVITE sip:a SIP/2.0\r\nCSeq: 1 INVITE\r\n"} {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
