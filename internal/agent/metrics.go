package agent

import (
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
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

// labelEscaper escapes a label value for the Prometheus text format, which
// knows only these three escapes (strconv.Quote also emits \t, \xNN and
// \uNNNN, which strict parsers reject, failing the whole scrape).
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

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
		b.WriteString(`="`)
		b.WriteString(labelEscaper.Replace(strings.ToValidUTF8(kv[i+1], "\uFFFD")))
		b.WriteByte('"')
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
		if sp := e.SIP; sp != nil {
			for _, ms := range sp.Methods {
				ml := entityLabels(id, "role", ms.Role, "method", ms.Method)
				m.counter("capybara_sip_requests_total", "SIP requests (retransmissions excluded).", ml, float64(ms.Requests), now)
				m.counter("capybara_sip_retransmissions_total", "Retransmitted SIP requests.", ml, float64(ms.Retrans), now)
				m.counter("capybara_sip_timeouts_total", "SIP transactions without a final response within 32s.", ml, float64(ms.Timeouts), now)
				for code, n := range ms.Codes {
					m.counter("capybara_sip_responses_total", "SIP final and ringing responses, by code.", entityLabels(id, "role", ms.Role, "method", ms.Method, "code", code), float64(n), now)
				}
				m.histogram("capybara_sip_setup_seconds", "SIP request to final response.", ml, ms.Final, now)
				if ms.Method == "INVITE" {
					m.histogram("capybara_sip_post_dial_delay_seconds", "INVITE to 180/183 ringing.", ml, ms.Ringing, now)
				}
			}
			m.gauge("capybara_sip_calls_active", "Established SIP calls.", el, float64(sp.CallsActive), now)
			m.counter("capybara_sip_call_seconds_total", "Duration of ended SIP calls.", el, float64(sp.CallSeconds), now)
		}
		if r := e.RTP; r != nil {
			m.counter("capybara_rtp_packets_received_total", "Inbound RTP packets.", el, float64(r.PacketsIn), now)
			m.counter("capybara_rtp_packets_sent_total", "Outbound RTP packets.", el, float64(r.PacketsOut), now)
			m.counter("capybara_rtp_packets_expected_total", "Inbound RTP packets expected from sequence numbers.", el, float64(r.Expected), now)
			m.counter("capybara_rtp_packets_lost_total", "Inbound RTP packets lost.", el, float64(r.Lost), now)
			m.histogram("capybara_rtp_jitter_seconds", "Inbound RTP interarrival jitter (one sample per stream and interval).", el, r.Jitter, now)
			m.gauge("capybara_rtp_streams", "Active RTP streams.", entityLabels(id, "direction", "in"), float64(r.StreamsIn), now)
			m.gauge("capybara_rtp_streams", "Active RTP streams.", entityLabels(id, "direction", "out"), float64(r.StreamsOut), now)
			m.gauge("capybara_rtp_one_way_streams", "Outbound RTP streams whose peer sends nothing back.", el, float64(r.OneWay), now)
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
		for _, q := range e.DB {
			ql := entityLabels(id, "db", q.Proto, "statement", q.Query)
			m.counter("capybara_db_requests_total", "Client database requests (plaintext Postgres/MySQL/Redis).", ql, float64(q.Count), now)
			m.counter("capybara_db_errors_total", "Client database requests answered with an error.", ql, float64(q.Errors), now)
			m.histogram("capybara_db_latency_seconds", "Client database request latency.", ql, q.Lat, now)
		}
		for _, f := range e.Files {
			fl := entityLabels(id, "path", f.Path, "fs", f.FSType)
			m.counter("capybara_slow_file_ops_total", "File operations slower than the agent threshold.", fl, float64(f.Ops()), now)
			m.counter("capybara_slow_file_wait_seconds_total", "Time spent in slow file operations.", fl, float64(f.WaitNs)/1e9, now)
		}
		if n := e.Net; n != nil {
			m.counter("capybara_tcp_listen_overflows_total", "Accept queue overflows in the pod network namespace.", el, float64(n.ListenOverflows), now)
			m.counter("capybara_tcp_listen_drops_total", "SYNs dropped by listeners in the pod network namespace.", el, float64(n.ListenDrops), now)
			m.counter("capybara_tcp_zero_window_drops_total", "Packets dropped because the receive window was closed.", el, float64(n.ZeroWindowDrops), now)
			m.counter("capybara_tcp_rcvq_drops_total", "Packets dropped because the receive queue was full.", el, float64(n.RcvQueueDrops), now)
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
		m.counter("capybara_tcp_zero_window_seconds_total", "Approximate time the peer's receive window was closed.", pl, float64(p.ZeroWindow)/10, now)
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
	byName := map[string][]promSeries{}
	for _, s := range m.vals {
		series := *s
		if s.hist != nil {
			hist := *s.hist
			hist.B = slices.Clone(hist.B)
			series.hist = &hist
		}
		byName[s.name] = append(byName[s.name], series)
	}
	help, types := maps.Clone(m.help), maps.Clone(m.types)
	m.mu.Unlock()
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help[name], name, types[name])
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
