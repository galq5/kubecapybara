package dnsparse

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func build(t *testing.T, resp bool, rcode dnsmessage.RCode, name string, answers ...netip.Addr) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, Response: resp, RCode: rcode})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	n := dnsmessage.MustNewName(name)
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, a := range answers {
		if err := b.AResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: a.As4()}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParse(t *testing.T) {
	q := build(t, false, dnsmessage.RCodeSuccess, "Example.COM.")
	m, err := Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	if m.Response || m.Name != "example.com" || m.ID != 42 || m.Type != "A" {
		t.Fatalf("bad query parse: %+v", m)
	}
	ip := netip.MustParseAddr("10.1.2.3")
	r := build(t, true, dnsmessage.RCodeSuccess, "example.com.", ip, netip.MustParseAddr("10.1.2.4"))
	m, err = Parse(r)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Response || m.RCode != "NOERROR" || len(m.Answers) != 2 || m.Answers[0].IP != ip {
		t.Fatalf("bad response parse: %+v", m)
	}
	// truncated answers still return the question
	m, err = Parse(r[:len(r)-3])
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "example.com" || len(m.Answers) != 1 {
		t.Fatalf("truncated parse: %+v", m)
	}
	nx := build(t, true, dnsmessage.RCodeNameError, "foo.bar.")
	m, _ = Parse(nx)
	if m.RCode != "NXDOMAIN" {
		t.Fatalf("rcode %s", m.RCode)
	}
}

func TestIsSearchExpansion(t *testing.T) {
	cases := map[string]bool{
		"api.stripe.com.default.svc.cluster.local":   true,
		"payments.default.default.svc.cluster.local": true,
		"api.stripe.com.svc.cluster.local":           true,
		"api.stripe.com.cluster.local":               true,
		"payments.default.svc.cluster.local":         false,
		"payments.svc.cluster.local":                 false,
		"10-0-0-1.default.pod.cluster.local":         false,
		"api.stripe.com":                             false,
		"google.com.svc.cluster.local":               true,
		"api.app.svc.cluster.local":                  false, // namespace "app", missing service
		"web.dev.svc.cluster.local":                  false,
	}
	for name, want := range cases {
		if got := IsSearchExpansion(name, "cluster.local"); got != want {
			t.Errorf("IsSearchExpansion(%q) = %v, want %v", name, got, want)
		}
	}
}
