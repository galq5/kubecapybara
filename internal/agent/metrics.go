package agent

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
)

// metrics keeps cumulative Prometheus series derived from collected windows.
// Pod entities carry a pod_uid label that can be joined with
// kube_pod_info{uid=...} from kube-state-metrics.
type metrics struct {
	a       *Agent
	mu      sync.Mutex
	vals    map[string]*promSeries
	types   map[string]string
	help    map[string]string
	maxIdle time.Duration
}

type promSeries struct {
	name    string
	labels  string
	value   float64
	hist    *model.Hist
	updated time.Time
}

func newMetrics(a *Agent) *metrics {
	return &metrics{a: a, vals: map[string]*promSeries{}, types: map[string]string{}, help: map[string]string{}, maxIdle: 30 * time.Minute}
}

func labels(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(kv[i])
		b.WriteByte('=')
		b.WriteString(strconv.Quote(kv[i+1]))
	}
	return b.String()
}

func entityLabels(entity string, extra ...string) string {
	kv := []string{"entity", entity}
	if uid, ok := strings.CutPrefix(entity, "pod:"); ok {
		kv = append(kv, "pod_uid", uid)
	}
	return labels(append(kv, extra...)...)
}

func (m *metrics) series(typ, name, help, lbls string, now time.Time) *promSeries {
	m.types[name] = typ
	m.help[name] = help
	key := name + "{" + lbls + "}"
	s, ok := m.vals[key]
	if !ok {
		s = &promSeries{name: name, labels: lbls}
		m.vals[key] = s
	}
	s.updated = now
	return s
}

func (m *metrics) counter(name, help, lbls string, v float64, now time.Time) {
	if v == 0 {
		if _, ok := m.vals[name+"{"+lbls+"}"]; !ok {
			return
		}
	}
	m.series("counter", name, help, lbls, now).value += v
}

func (m *metrics) gauge(name, help, lbls string, v float64, now time.Time) {
	m.series("gauge", name, help, lbls, now).value = v
}

func (m *metrics) histogram(name, help, lbls string, h model.Hist, now time.Time) {
	if h.Count == 0 {
		return
	}
	s := m.series("histogram", name, help, lbls, now)
	if s.hist == nil {
		s.hist = &model.Hist{}
	}
	s.hist.Add(h)
}

func (m *metrics) observe(w *Window) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	for id, e := range w.Entities {
		el := entityLabels(id)
		if s := e.Sched; s != nil {
			m.counter("capybara_oncpu_seconds_total", "Thread time spent on CPU.", el, float64(s.OnCPUNs)/1e9, now)
			for state, ns := range s.OffNs {
				m.counter("capybara_offcpu_seconds_total", "Thread time spent off CPU, by state (runq = waiting for a CPU).", entityLabels(id, "state", state), float64(ns)/1e9, now)
			}
			m.histogram("capybara_runqueue_latency_seconds", "Scheduler run queue latency.", el, s.RunQ, now)
			m.counter("capybara_direct_reclaim_seconds_total", "Time stalled in direct memory reclaim.", el, float64(s.ReclaimNs)/1e9, now)
		}
		if io := e.IO; io != nil {
			m.counter("capybara_block_read_bytes_total", "Block I/O bytes read.", el, float64(io.ReadBytes), now)
			m.counter("capybara_block_write_bytes_total", "Block I/O bytes written.", el, float64(io.WriteBytes), now)
			m.histogram("capybara_block_latency_seconds", "Block I/O latency.", el, io.Lat, now)
		}
		if d := e.DNS; d != nil {
			for rc, n := range d.RCodes {
				m.counter("capybara_dns_responses_total", "DNS responses received, by rcode.", entityLabels(id, "rcode", rc), float64(n), now)
			}
			m.counter("capybara_dns_queries_total", "DNS queries sent.", el, float64(d.Queries), now)
			m.counter("capybara_dns_timeouts_total", "DNS queries without an answer within 5s.", el, float64(d.Timeouts), now)
			m.counter("capybara_dns_ndots_waste_total", "NXDOMAIN lookups caused by search-path expansion (ndots).", el, float64(d.NdotsWaste), now)
			m.histogram("capybara_dns_latency_seconds", "DNS client latency.", el, d.Lat, now)
		}
		if d := e.DNSServer; d != nil {
			m.counter("capybara_dns_server_queries_total", "DNS queries answered by this entity.", el, float64(d.Queries), now)
			m.histogram("capybara_dns_server_latency_seconds", "DNS server processing latency.", el, d.Lat, now)
		}
		for _, ep := range e.HTTP {
			for class, n := range ep.Status {
				m.counter("capybara_http_requests_total", "HTTP/1.x requests.", entityLabels(id, "role", ep.Role, "method", ep.Method, "path", ep.Path, "status", class), float64(n), now)
			}
			m.histogram("capybara_http_latency_seconds", "HTTP/1.x request latency.", entityLabels(id, "role", ep.Role, "method", ep.Method, "path", ep.Path), ep.Lat, now)
		}
		for errno, n := range e.ConnErrors {
			m.counter("capybara_connect_errors_total", "connect() failures by errno.", entityLabels(id, "errno", errno), float64(n), now)
		}
		if r := e.Res; r != nil {
			m.gauge("capybara_memory_bytes", "Pod memory.current.", el, float64(r.MemCurrent), now)
			m.counter("capybara_cpu_throttled_periods_total", "CFS periods throttled.", el, float64(r.Throttled), now)
		}
	}
	for _, p := range w.Pairs {
		pl := labels("client", p.Client, "server", p.Server, "port", strconv.Itoa(int(p.Port)), "side", p.Side, "owner", p.Owner)
		m.histogram("capybara_tcp_rtt_seconds", "Smoothed TCP RTT samples.", pl, p.RTT, now)
		m.histogram("capybara_tcp_connect_seconds", "TCP handshake latency.", pl, p.Connect, now)
		m.counter("capybara_tcp_connections_total", "Established TCP connections.", pl, float64(p.Connects), now)
		m.counter("capybara_tcp_refused_total", "Connection attempts refused (RST).", pl, float64(p.Refused), now)
		m.counter("capybara_tcp_connect_timeouts_total", "Connection attempts that failed without RST.", pl, float64(p.Timeouts), now)
		m.counter("capybara_tcp_retransmits_total", "TCP segment retransmissions.", pl, float64(p.Retrans), now)
		m.counter("capybara_tcp_tx_bytes_total", "TCP bytes sent by the local socket.", pl, float64(p.BytesTx), now)
		m.counter("capybara_tcp_rx_bytes_total", "TCP bytes received by the local socket.", pl, float64(p.BytesRx), now)
	}
	for _, d := range w.Drops {
		m.counter("capybara_packet_drops_total", "Dropped packets by kernel drop reason.", labels("reason", d.Reason, "proto", d.Proto), float64(d.Count), now)
	}
	n := w.Node
	m.gauge("capybara_conntrack_entries", "Conntrack table entries.", "", float64(n.ConntrackCount), now)
	m.gauge("capybara_conntrack_max", "Conntrack table size.", "", float64(n.ConntrackMax), now)
	m.counter("capybara_conntrack_insert_failed_total", "Conntrack insert failures (SNAT port races).", "", float64(n.ConntrackInsertFailed), now)

	for k, s := range m.vals {
		if now.Sub(s.updated) > m.maxIdle {
			delete(m.vals, k)
		}
	}
}

func (m *metrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byName := map[string][]*promSeries{}
	for _, s := range m.vals {
		byName[s.name] = append(byName[s.name], s)
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, m.help[name], name, m.types[name])
		ss := byName[name]
		sort.Slice(ss, func(i, j int) bool { return ss[i].labels < ss[j].labels })
		for _, s := range ss {
			if s.hist != nil {
				writeHist(w, name, s.labels, s.hist)
				continue
			}
			fmt.Fprintf(w, "%s%s %s\n", name, braces(s.labels), strconv.FormatFloat(s.value, 'g', -1, 64))
		}
	}
}

func braces(l string) string {
	if l == "" {
		return ""
	}
	return "{" + l + "}"
}

func writeHist(w io.Writer, name, lbls string, h *model.Hist) {
	sep := ""
	if lbls != "" {
		sep = ","
	}
	var cum uint64
	for i := 0; i < model.HistSlots; i++ {
		if i < len(h.B) {
			cum += h.B[i]
		}
		le := math.Ldexp(1, i) / 1e6 // slot i upper bound: 2^i us
		fmt.Fprintf(w, "%s_bucket{%s%sle=\"%s\"} %d\n", name, lbls, sep, strconv.FormatFloat(le, 'g', -1, 64), cum)
	}
	fmt.Fprintf(w, "%s_bucket{%s%sle=\"+Inf\"} %d\n", name, lbls, sep, h.Count)
	fmt.Fprintf(w, "%s_sum%s %s\n", name, braces(lbls), strconv.FormatFloat(float64(h.Sum)/1e6, 'g', -1, 64))
	fmt.Fprintf(w, "%s_count%s %d\n", name, braces(lbls), h.Count)
}
