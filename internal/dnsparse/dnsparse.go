// Package dnsparse parses (possibly truncated) DNS messages captured from the
// wire and implements Kubernetes specific heuristics such as detecting
// wasted search-path expansions caused by `ndots:5`.
package dnsparse

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Message is the subset of a DNS message kubecapybara cares about.
type Message struct {
	ID       uint16
	Response bool
	RCode    string
	Name     string // first question, lowercase, without trailing dot
	Type     string
	Answers  []Answer
}

// Answer is an address record.
type Answer struct {
	Name string
	IP   netip.Addr
	TTL  uint32
}

// RCode names.
var rcodes = map[dnsmessage.RCode]string{
	dnsmessage.RCodeSuccess:        "NOERROR",
	dnsmessage.RCodeFormatError:    "FORMERR",
	dnsmessage.RCodeServerFailure:  "SERVFAIL",
	dnsmessage.RCodeNameError:      "NXDOMAIN",
	dnsmessage.RCodeNotImplemented: "NOTIMP",
	dnsmessage.RCodeRefused:        "REFUSED",
}

// Parse parses a DNS message. Truncated answer sections are tolerated:
// whatever could be parsed is returned.
func Parse(b []byte) (*Message, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return nil, err
	}
	m := &Message{ID: h.ID, Response: h.Response}
	if rc, ok := rcodes[h.RCode]; ok {
		m.RCode = rc
	} else {
		m.RCode = h.RCode.String()
	}
	q, err := p.Question()
	if err != nil {
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return m, nil
		}
		return nil, err
	}
	m.Name = Normalize(q.Name.String())
	m.Type = strings.TrimPrefix(q.Type.String(), "Type")
	if !h.Response {
		return m, nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return m, nil
	}
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return m, nil
			}
			m.Answers = append(m.Answers, Answer{Name: Normalize(ah.Name.String()), IP: netip.AddrFrom4(r.A), TTL: ah.TTL})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return m, nil
			}
			m.Answers = append(m.Answers, Answer{Name: Normalize(ah.Name.String()), IP: netip.AddrFrom16(r.AAAA), TTL: ah.TTL})
		default:
			if err := p.SkipAnswer(); err != nil {
				return m, nil
			}
		}
	}
	return m, nil
}

// Normalize lowercases a name and strips the trailing dot.
func Normalize(n string) string {
	return strings.TrimSuffix(strings.ToLower(n), ".")
}

// IsSearchExpansion reports whether an NXDOMAIN name looks like a lookup that
// only happened because the resolver appended a cluster search domain to a
// name that already contained dots (the classic ndots:5 problem), e.g.
//
//	api.stripe.com.default.svc.cluster.local
//	api.stripe.com.svc.cluster.local
//	api.stripe.com.cluster.local
func IsSearchExpansion(name, clusterDomain string) bool {
	name = Normalize(name)
	cd := Normalize(clusterDomain)
	if !strings.HasSuffix(name, "."+cd) {
		return false
	}
	rest := strings.TrimSuffix(name, "."+cd)
	switch {
	case strings.HasSuffix(rest, ".svc"):
		// <x>.<ns>.svc -> legit service lookups have exactly <svc>.<ns>
		rest = strings.TrimSuffix(rest, ".svc")
		labels := strings.Split(rest, ".")
		if len(labels) >= 3 {
			return true
		}
		// "<host.tld>.svc" (search "svc.cluster.local") e.g. google.com.svc
		return len(labels) == 2 && looksLikeTLD(labels[1])
	case rest == "svc":
		return false
	case strings.HasSuffix(rest, ".pod"):
		return false
	default:
		// <anything with a dot>.cluster.local (search "cluster.local")
		return strings.Contains(rest, ".")
	}
}

// Only TLDs that are implausible as namespace names: lookups of missing
// services in namespaces such as "app", "dev" or "internal" ("api.app.svc...")
// must not be reported as search-path waste.
var tlds = map[string]bool{"com": true, "net": true, "org": true, "edu": true, "gov": true}

func looksLikeTLD(s string) bool { return tlds[s] }
