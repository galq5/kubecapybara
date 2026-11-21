package model

import (
	"strconv"
	"testing"
)

// Collectors bound cardinality per collection interval; merging many
// intervals (minute rollups, an hour long query) must keep the bound and
// lose no requests or failures.
func TestMergeBoundsHTTPRoutesAndDNSNames(t *testing.T) {
	agg := &EntityStats{}
	for w := 0; w < 5; w++ {
		e := &EntityStats{HTTP: map[string]*HTTPEndpoint{}, DNS: &DNSStats{Names: map[string]*DNSName{}}}
		for i := 0; i < MaxHTTPEndpoints; i++ {
			p := "/w" + strconv.Itoa(w) + "/r" + strconv.Itoa(i)
			e.HTTP["server GET "+p] = &HTTPEndpoint{Role: "server", Method: "GET", Path: p, Count: 1, Status: map[string]uint64{"5xx": 1}}
		}
		for i := 0; i < MaxDNSNames; i++ {
			e.DNS.Names["n"+strconv.Itoa(w)+"-"+strconv.Itoa(i)+".example"] = &DNSName{Count: 1, Timeouts: 1}
		}
		agg.Merge(e)
	}
	var reqs, errs uint64
	for _, ep := range agg.HTTP {
		reqs += ep.Count
		errs += ep.Errors()
	}
	if len(agg.HTTP) > MaxHTTPEndpoints+1 || reqs != 5*MaxHTTPEndpoints || errs != reqs {
		t.Fatalf("%d routes, %d requests, %d errors", len(agg.HTTP), reqs, errs)
	}
	if o := agg.HTTP["server GET (other)"]; o == nil || o.Path != "(other)" || o.Count != 4*MaxHTTPEndpoints {
		t.Fatalf("overflow route %+v", o)
	}
	var timeouts uint64
	for _, n := range agg.DNS.Names {
		timeouts += n.Timeouts
	}
	if len(agg.DNS.Names) > MaxDNSNames+1 || timeouts != 5*MaxDNSNames {
		t.Fatalf("%d names, %d timeouts", len(agg.DNS.Names), timeouts)
	}
}
