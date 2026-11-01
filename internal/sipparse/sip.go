// Package sipparse parses SIP messages (RFC 3261) and the parts of their
// SDP bodies (RFC 4566) that matter for monitoring. Input may be truncated
// (the agent copies the first 1 KiB of each packet): whatever is complete
// is returned.
package sipparse

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// Message is a parsed SIP request or response.
type Message struct {
	Request bool
	Method  string // request method, or the CSeq method of a response
	URI     string
	Status  int
	Reason  string

	CallID    string
	CSeq      uint32
	FromTag   string
	ToTag     string
	UserAgent string
	SDP       *SDP
}

// SDP holds the media description of a session.
type SDP struct {
	Addr      string // c= connection address
	AudioPort int
	Codecs    map[int]Codec // payload type -> codec (rtpmap and static types)
}

// Codec is an RTP payload format.
type Codec struct {
	Name  string
	Clock int
}

// Static RTP payload types (RFC 3551) that matter for voice.
var Static = map[int]Codec{
	0: {"PCMU", 8000}, 3: {"GSM", 8000}, 4: {"G723", 8000}, 8: {"PCMA", 8000},
	9: {"G722", 8000}, 13: {"CN", 8000}, 18: {"G729", 8000},
}

var methods = map[string]bool{
	"INVITE": true, "ACK": true, "BYE": true, "CANCEL": true, "OPTIONS": true, "REGISTER": true,
	"PRACK": true, "SUBSCRIBE": true, "NOTIFY": true, "PUBLISH": true, "INFO": true, "REFER": true,
	"MESSAGE": true, "UPDATE": true,
}

var compact = map[string]string{"i": "call-id", "f": "from", "t": "to", "c": "content-type", "l": "content-length", "v": "via", "m": "contact"}

// ErrNotSIP is returned for payloads that are not SIP.
var ErrNotSIP = errors.New("not a SIP message")

// Parse parses one SIP message.
func Parse(b []byte) (*Message, error) {
	head, body, _ := bytes.Cut(b, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	if len(lines) == 0 {
		return nil, ErrNotSIP
	}
	m := &Message{}
	first := strings.Fields(lines[0])
	switch {
	case len(first) >= 2 && strings.HasPrefix(first[0], "SIP/2.0"):
		code, err := strconv.Atoi(first[1])
		if err != nil || code < 100 || code > 699 {
			return nil, ErrNotSIP
		}
		m.Status = code
		m.Reason = strings.Join(first[2:], " ")
	case len(first) == 3 && methods[first[0]] && first[2] == "SIP/2.0":
		m.Request, m.Method, m.URI = true, first[0], first[1]
	default:
		return nil, ErrNotSIP
	}
	ctype := ""
	for _, l := range lines[1:] {
		name, val, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if full, ok := compact[name]; ok {
			name = full
		}
		val = strings.TrimSpace(val)
		switch name {
		case "call-id":
			m.CallID = val
		case "cseq":
			f := strings.Fields(val)
			if len(f) == 2 {
				n, _ := strconv.ParseUint(f[0], 10, 32)
				m.CSeq = uint32(n)
				if !m.Request {
					m.Method = f[1]
				}
			}
		case "from":
			m.FromTag = param(val, "tag")
		case "to":
			m.ToTag = param(val, "tag")
		case "user-agent", "server":
			if m.UserAgent == "" {
				m.UserAgent = val
			}
		case "content-type":
			ctype = strings.ToLower(val)
		}
	}
	if m.CallID == "" || m.Method == "" {
		return nil, ErrNotSIP
	}
	if strings.HasPrefix(ctype, "application/sdp") && len(body) > 0 {
		m.SDP = ParseSDP(body)
	}
	return m, nil
}

func param(v, key string) string {
	for _, p := range strings.Split(v, ";")[1:] {
		k, val, _ := strings.Cut(strings.TrimSpace(p), "=")
		if strings.EqualFold(k, key) {
			return val
		}
	}
	return ""
}

// ParseSDP extracts the connection address, audio port and codecs.
func ParseSDP(b []byte) *SDP {
	s := &SDP{Codecs: map[int]Codec{}}
	inAudio := false
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimRight(l, "\r")
		if len(l) < 2 || l[1] != '=' {
			continue
		}
		v := l[2:]
		switch l[0] {
		case 'c':
			if f := strings.Fields(v); len(f) == 3 && (s.Addr == "" || inAudio) {
				s.Addr = strings.SplitN(f[2], "/", 2)[0]
			}
		case 'm':
			f := strings.Fields(v)
			inAudio = len(f) >= 4 && f[0] == "audio"
			if inAudio {
				s.AudioPort, _ = strconv.Atoi(strings.SplitN(f[1], "/", 2)[0])
				for _, pt := range f[3:] {
					if n, err := strconv.Atoi(pt); err == nil {
						if c, ok := Static[n]; ok {
							s.Codecs[n] = c
						}
					}
				}
			}
		case 'a':
			if !inAudio {
				continue
			}
			if rest, ok := strings.CutPrefix(v, "rtpmap:"); ok {
				ptS, enc, _ := strings.Cut(rest, " ")
				pt, err := strconv.Atoi(ptS)
				parts := strings.Split(enc, "/")
				if err != nil || len(parts) < 2 {
					continue
				}
				clock, _ := strconv.Atoi(parts[1])
				s.Codecs[pt] = Codec{Name: parts[0], Clock: clock}
			}
		}
	}
	return s
}
