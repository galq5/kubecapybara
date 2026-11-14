// Package hub implements capybara-hub, the aggregator for large clusters.
//
// Without it every client (kubectl capybara, the controller) fetches every
// agent through the API server pod proxy and LISTs all pods on its own. The
// hub instead
//
//   - discovers agents and builds cluster metadata from informers (one watch
//     instead of repeated LIST calls),
//   - fetches agents directly by pod IP with bounded concurrency, coalescing
//     identical concurrent requests and caching results for an interval,
//   - scopes responses to a namespace and/or the top N flows and entities and
//     prunes the metadata accordingly, and gzips them,
//   - forwards profile and hardware counter requests to the right agent.
//
// A client then makes one request per refresh, through one Service.
package hub

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	appslisters "k8s.io/client-go/listers/apps/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// TokenHeader carries the API token (the agent token is reused).
const TokenHeader = "X-Capybara-Token"

// Config configures the hub.
type Config struct {
	AgentNamespace string
	AgentSelector  string
	AgentPort      int
	// Token authenticates the hub to agents and clients to the hub.
	Token         string
	ClusterDomain string
	// Concurrency bounds parallel agent requests (default 64).
	Concurrency int
	// AgentTimeout bounds one agent snapshot request (default 20s).
	AgentTimeout time.Duration
	// CacheTTL is how long a fan-out result is reused (default 5s, the agent
	// collection interval).
	CacheTTL time.Duration
	// MetaRefresh bounds how often metadata is rebuilt from the informer
	// caches (default 10s).
	MetaRefresh time.Duration
	// DefaultTop applies when a request does not set top (0: unlimited).
	DefaultTop int
}

// Hub serves aggregated agent data.
type Hub struct {
	cfg  Config
	cs   kubernetes.Interface
	log  *slog.Logger
	sel  labels.Selector
	http *http.Client

	pods   corelisters.PodLister
	svcs   corelisters.ServiceLister
	nodes  corelisters.NodeLister
	rss    appslisters.ReplicaSetLister
	deps   appslisters.DeploymentLister
	slices discoverylisters.EndpointSliceLister
	synced []cache.InformerSynced
	start  func(stop <-chan struct{})
	ready  atomic.Bool

	metaMu sync.Mutex
	meta   *k8smeta.Meta

	cacheMu sync.Mutex
	cache   map[cacheKey]*entry

	changesMu sync.Mutex
	changes   []k8smeta.Change
	changesAt time.Time

	stats struct {
		requests, cacheHits, fanouts, agentErrors atomic.Uint64
		lastFanoutMs, agents                      atomic.Int64
	}
}

type cacheKey struct {
	from, to int64
	lite     bool
}

type entry struct {
	done  chan struct{}
	at    time.Time
	snaps []*model.Snapshot
	errs  []string
}

// New creates a hub and registers its informers. Call Start before serving.
func New(cfg Config, cs kubernetes.Interface, log *slog.Logger) (*Hub, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 64
	}
	if cfg.AgentTimeout <= 0 {
		cfg.AgentTimeout = 20 * time.Second
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Second
	}
	if cfg.MetaRefresh <= 0 {
		cfg.MetaRefresh = 10 * time.Second
	}
	if cfg.ClusterDomain == "" {
		cfg.ClusterDomain = "cluster.local"
	}
	sel, err := labels.Parse(cfg.AgentSelector)
	if err != nil {
		return nil, fmt.Errorf("agent selector: %w", err)
	}
	h := &Hub{
		cfg: cfg, cs: cs, log: log, sel: sel, cache: map[cacheKey]*entry{},
		http: &http.Client{Transport: &http.Transport{
			Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		}},
	}
	f := informers.NewSharedInformerFactoryWithOptions(cs, 0, informers.WithTransform(slim))
	h.pods = f.Core().V1().Pods().Lister()
	h.svcs = f.Core().V1().Services().Lister()
	h.nodes = f.Core().V1().Nodes().Lister()
	h.rss = f.Apps().V1().ReplicaSets().Lister()
	h.deps = f.Apps().V1().Deployments().Lister()
	fd := informers.NewSharedInformerFactoryWithOptions(cs, 0, informers.WithNamespace("default"),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = "kubernetes.io/service-name=kubernetes" }))
	h.slices = fd.Discovery().V1().EndpointSlices().Lister()
	h.synced = []cache.InformerSynced{
		f.Core().V1().Pods().Informer().HasSynced, f.Core().V1().Services().Informer().HasSynced,
		f.Core().V1().Nodes().Informer().HasSynced, f.Apps().V1().ReplicaSets().Informer().HasSynced,
		f.Apps().V1().Deployments().Informer().HasSynced, fd.Discovery().V1().EndpointSlices().Informer().HasSynced,
	}
	h.start = func(stop <-chan struct{}) { f.Start(stop); fd.Start(stop) }
	return h, nil
}

// slim drops what the hub never reads from cached objects (managed fields,
// most annotations, volumes): at tens of thousands of pods the informer
// cache is the hub's main memory cost.
func slim(obj any) (any, error) {
	if m, ok := obj.(metav1.Object); ok {
		m.SetManagedFields(nil)
		if a := m.GetAnnotations(); len(a) > 0 {
			keep := map[string]string{}
			if r, ok := a["deployment.kubernetes.io/revision"]; ok {
				keep["deployment.kubernetes.io/revision"] = r
			}
			m.SetAnnotations(keep)
		}
	}
	if p, ok := obj.(*corev1.Pod); ok {
		p.Spec.Volumes = nil
		for i := range p.Spec.Containers {
			p.Spec.Containers[i].Env, p.Spec.Containers[i].VolumeMounts = nil, nil
		}
	}
	return obj, nil
}

// Start runs the informers and waits for their caches.
func (h *Hub) Start(ctx context.Context) error {
	h.start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), h.synced...) {
		return errors.New("informer caches did not sync")
	}
	h.ready.Store(true)
	return nil
}

// ---------------------------------------------------------------- metadata

// Meta returns cluster metadata, rebuilt from the informer caches at most
// every MetaRefresh.
func (h *Hub) Meta() *k8smeta.Meta {
	h.metaMu.Lock()
	defer h.metaMu.Unlock()
	if h.meta != nil && time.Since(h.meta.Loaded) < h.cfg.MetaRefresh {
		return h.meta
	}
	var o k8smeta.Objects
	o.Nodes, _ = h.nodes.List(labels.Everything())
	o.Pods, _ = h.pods.List(labels.Everything())
	o.Services, _ = h.svcs.List(labels.Everything())
	o.ReplicaSets, _ = h.rss.List(labels.Everything())
	o.Deployments, _ = h.deps.List(labels.Everything())
	var sl []*discoveryv1.EndpointSlice
	sl, _ = h.slices.List(labels.Everything())
	o.APIServer = sl
	h.meta = k8smeta.FromObjects(o, h.cfg.ClusterDomain)
	return h.meta
}

// agents returns running agent pods.
func (h *Hub) agents() []*corev1.Pod {
	pods, _ := h.pods.Pods(h.cfg.AgentNamespace).List(h.sel)
	var out []*corev1.Pod
	for _, p := range pods {
		if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" && p.DeletionTimestamp == nil {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Spec.NodeName < out[j].Spec.NodeName })
	h.stats.agents.Store(int64(len(out)))
	return out
}

// ---------------------------------------------------------------- fan-out

func (h *Hub) agentURL(p *corev1.Pod, path string, q url.Values) string {
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(p.Status.PodIP, strconv.Itoa(h.cfg.AgentPort)), Path: path, RawQuery: q.Encode()}
	return u.String()
}

func (h *Hub) agentGet(ctx context.Context, p *corev1.Pod, path string, q url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.agentURL(p, path, q), nil)
	if err != nil {
		return nil, 0, err
	}
	if h.cfg.Token != "" {
		req.Header.Set(TokenHeader, h.cfg.Token)
	}
	resp, err := h.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, err
}

// roundRange aligns a range to the cache granularity so that clients
// refreshing at slightly different moments share one fan-out.
func (h *Hub) roundRange(from, to time.Time, lite bool) (time.Time, time.Time) {
	g := h.cfg.CacheTTL
	if lite && to.Sub(from) >= 10*time.Minute {
		g = time.Minute // baselines: coarse and slowly changing
	}
	return from.Truncate(g), to.Truncate(g)
}

// Snapshots returns one snapshot per agent for [from, to].
func (h *Hub) Snapshots(ctx context.Context, from, to time.Time, lite bool) ([]*model.Snapshot, []string) {
	from, to = h.roundRange(from, to, lite)
	key := cacheKey{from.Unix(), to.Unix(), lite}
	ttl := h.cfg.CacheTTL
	if lite {
		ttl = time.Minute
	}
	h.cacheMu.Lock()
	for k, e := range h.cache { // expire
		select {
		case <-e.done:
			if time.Since(e.at) > 2*time.Minute {
				delete(h.cache, k)
			}
		default:
		}
	}
	e, ok := h.cache[key]
	if ok {
		select {
		case <-e.done:
			if time.Since(e.at) > ttl {
				ok = false
			}
		default: // in flight: wait for it
		}
	}
	if ok {
		h.stats.cacheHits.Add(1)
	} else {
		e = &entry{done: make(chan struct{})}
		h.cache[key] = e
		go h.fanout(e, from, to, lite)
	}
	h.cacheMu.Unlock()
	select {
	case <-e.done:
		return e.snaps, e.errs
	case <-ctx.Done():
		return nil, []string{ctx.Err().Error()}
	}
}

// fanout fetches all agents. It is detached from the request context: other
// requests may be waiting for the same result.
func (h *Hub) fanout(e *entry, from, to time.Time, lite bool) {
	defer close(e.done)
	start := time.Now()
	h.stats.fanouts.Add(1)
	q := url.Values{"from": {strconv.FormatInt(from.Unix(), 10)}, "to": {strconv.FormatInt(to.Unix(), 10)}}
	if lite {
		q.Set("lite", "1")
	}
	agents := h.agents()
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, h.cfg.Concurrency)
	)
	for _, p := range agents {
		wg.Add(1)
		go func(p *corev1.Pod) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), h.cfg.AgentTimeout)
			defer cancel()
			b, code, err := h.agentGet(ctx, p, "/v1/snapshot", q)
			var snap model.Snapshot
			if err == nil && code != http.StatusOK {
				err = fmt.Errorf("%d: %s", code, strings.TrimSpace(string(b)))
			}
			if err == nil {
				err = json.Unmarshal(b, &snap)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				h.stats.agentErrors.Add(1)
				e.errs = append(e.errs, fmt.Sprintf("agent %s (node %s): %v", p.Name, p.Spec.NodeName, err))
				return
			}
			if snap.Node == "" {
				snap.Node = p.Spec.NodeName
			}
			e.snaps = append(e.snaps, &snap)
		}(p)
	}
	wg.Wait()
	if len(agents) == 0 {
		e.errs = append(e.errs, fmt.Sprintf("no running agents in namespace %q (selector %q)", h.cfg.AgentNamespace, h.cfg.AgentSelector))
	}
	sort.Slice(e.snaps, func(i, j int) bool { return e.snaps[i].Node < e.snaps[j].Node })
	sort.Strings(e.errs)
	e.at = time.Now()
	h.stats.lastFanoutMs.Store(time.Since(start).Milliseconds())
}

// Changes returns cluster changes since a time. The underlying event and
// ConfigMap LISTs run at most every 30s whatever the number of clients.
func (h *Hub) Changes(ctx context.Context, since time.Time) ([]k8smeta.Change, error) {
	h.changesMu.Lock()
	defer h.changesMu.Unlock()
	if h.changes == nil || time.Since(h.changesAt) > 30*time.Second {
		ch, err := k8smeta.LoadChanges(ctx, h.cs, h.Meta(), time.Now().Add(-24*time.Hour))
		if err != nil {
			if h.changes == nil {
				return nil, err
			}
		} else {
			h.changes, h.changesAt = ch, time.Now()
		}
	}
	var out []k8smeta.Change
	for _, c := range h.changes {
		if !c.Time.Before(since) {
			out = append(out, c)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- HTTP API

// SnapshotsResponse is the body of /v1/snapshots.
type SnapshotsResponse struct {
	Snapshots []*model.Snapshot `json:"snapshots"`
	Errors    []string          `json:"errors,omitempty"`
	// Meta is set when requested with meta=1 (pruned for scoped requests).
	Meta *k8smeta.Meta `json:"meta,omitempty"`
	// Agents is the number of agents asked.
	Agents int `json:"agents"`
	// Scoped is true when the snapshots (and Meta) were scoped.
	Scoped bool `json:"scoped,omitempty"`
}

// Handler returns the hub HTTP API:
//
//	GET /healthz, /readyz, /metrics
//	GET /v1/status
//	GET /v1/snapshots?from=&to=&lite=1&namespace=&top=&meta=1
//	GET /v1/meta?namespace=
//	GET /v1/changes?since=
//	GET /v1/podevents?namespace=&uid=
//	GET /v1/profile?node=&entity=&seconds=&hz=
//	GET /v1/counters?node=&entity=&seconds=
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !h.ready.Load() {
			http.Error(w, "caches syncing", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/metrics", h.metrics)
	api := func(f http.HandlerFunc) http.HandlerFunc { return h.auth(h.whenReady(gzipped(f))) }
	mux.HandleFunc("/v1/status", api(h.status))
	mux.HandleFunc("/v1/snapshots", api(h.snapshots))
	mux.HandleFunc("/v1/meta", api(h.metaHandler))
	mux.HandleFunc("/v1/changes", api(h.changesHandler))
	mux.HandleFunc("/v1/podevents", api(h.podEvents))
	mux.HandleFunc("/v1/profile", api(h.forward("/v1/profile", 120)))
	mux.HandleFunc("/v1/counters", api(h.forward("/v1/counters", 60)))
	return mux
}

func (h *Hub) auth(f http.HandlerFunc) http.HandlerFunc {
	if h.cfg.Token == "" {
		return f
	}
	want := []byte(h.cfg.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(TokenHeader)), want) != 1 {
			http.Error(w, "missing or invalid "+TokenHeader, http.StatusUnauthorized)
			return
		}
		f(w, r)
	}
}

func (h *Hub) whenReady(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.stats.requests.Add(1)
		if !h.ready.Load() {
			http.Error(w, "hub is starting (informer caches syncing)", http.StatusServiceUnavailable)
			return
		}
		f(w, r)
	}
}

type gzipWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (g *gzipWriter) Write(b []byte) (int, error) { return g.gz.Write(b) }

// gzipped compresses responses for clients accepting gzip: snapshot JSON
// compresses about 10x.
func gzipped(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			f(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
		defer gz.Close()
		f(&gzipWriter{ResponseWriter: w, gz: gz}, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func parseTime(s string, def time.Time) (time.Time, error) {
	if s == "" {
		return def, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Parse(time.RFC3339, s)
}

func (h *Hub) scope(q url.Values) (Scope, error) {
	sc := Scope{Namespace: q.Get("namespace"), Top: h.cfg.DefaultTop}
	if t := q.Get("top"); t != "" {
		n, err := strconv.Atoi(t)
		if err != nil || n < 0 {
			return sc, fmt.Errorf("invalid top %q", t)
		}
		sc.Top = n
	}
	return sc, nil
}

func (h *Hub) snapshots(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now()
	to, err := parseTime(q.Get("to"), now)
	if err != nil {
		http.Error(w, "to: "+err.Error(), http.StatusBadRequest)
		return
	}
	from, err := parseTime(q.Get("from"), to.Add(-time.Minute))
	if err != nil {
		http.Error(w, "from: "+err.Error(), http.StatusBadRequest)
		return
	}
	sc, err := h.scope(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	snaps, errs := h.Snapshots(r.Context(), from, to, q.Get("lite") == "1")
	resp := SnapshotsResponse{Errors: errs, Agents: int(h.stats.agents.Load()), Scoped: sc.Active()}
	var meta *k8smeta.Meta
	if sc.Active() || q.Get("meta") == "1" {
		meta = h.Meta()
	}
	resp.Snapshots = Apply(snaps, meta, sc)
	if q.Get("meta") == "1" {
		if sc.Active() {
			resp.Meta = PruneMeta(meta, resp.Snapshots, sc.Namespace)
		} else {
			resp.Meta = meta
		}
	}
	if resp.Snapshots == nil {
		resp.Snapshots = []*model.Snapshot{}
	}
	writeJSON(w, resp)
}

func (h *Hub) metaHandler(w http.ResponseWriter, r *http.Request) {
	m := h.Meta()
	ns := r.URL.Query().Get("namespace")
	etag := fmt.Sprintf(`"%x-%s"`, m.Loaded.UnixNano(), ns)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	if ns != "" {
		m = PruneMeta(m, nil, ns)
	}
	writeJSON(w, m)
}

func (h *Hub) changesHandler(w http.ResponseWriter, r *http.Request) {
	since, err := parseTime(r.URL.Query().Get("since"), time.Now().Add(-time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ch, err := h.Changes(r.Context(), since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, ch)
}

func (h *Hub) podEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("namespace") == "" || q.Get("uid") == "" {
		http.Error(w, "namespace and uid are required", http.StatusBadRequest)
		return
	}
	ev, err := k8smeta.LoadPodEvents(r.Context(), h.cs, q.Get("namespace"), q.Get("uid"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, ev)
}

// forward relays a request to the agent of ?node=.
func (h *Hub) forward(path string, maxSeconds int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		node := q.Get("node")
		q.Del("node")
		var agent *corev1.Pod
		for _, p := range h.agents() {
			if p.Spec.NodeName == node {
				agent = p
				break
			}
		}
		if agent == nil {
			http.Error(w, "no agent running on node "+node, http.StatusNotFound)
			return
		}
		secs, _ := strconv.Atoi(q.Get("seconds"))
		if secs <= 0 || secs > maxSeconds {
			secs = maxSeconds
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(secs)*time.Second+30*time.Second)
		defer cancel()
		b, code, err := h.agentGet(ctx, agent, path, q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if code != http.StatusOK {
			http.Error(w, strings.TrimSpace(string(b)), code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}
}

func (h *Hub) status(w http.ResponseWriter, _ *http.Request) {
	agents := h.agents()
	nodes := make([]string, 0, len(agents))
	for _, p := range agents {
		nodes = append(nodes, p.Spec.NodeName)
	}
	writeJSON(w, map[string]any{
		"agents": len(agents), "nodes": nodes, "lastFanoutMs": h.stats.lastFanoutMs.Load(),
		"fanouts": h.stats.fanouts.Load(), "cacheHits": h.stats.cacheHits.Load(), "agentErrors": h.stats.agentErrors.Load(),
	})
}

func (h *Hub) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP capybara_hub_agents Running agents known to the hub.\n# TYPE capybara_hub_agents gauge\ncapybara_hub_agents %d\n", h.stats.agents.Load())
	fmt.Fprintf(w, "# HELP capybara_hub_fanout_last_seconds Duration of the last agent fan-out.\n# TYPE capybara_hub_fanout_last_seconds gauge\ncapybara_hub_fanout_last_seconds %.3f\n", float64(h.stats.lastFanoutMs.Load())/1000)
	fmt.Fprintf(w, "# HELP capybara_hub_fanouts_total Agent fan-outs.\n# TYPE capybara_hub_fanouts_total counter\ncapybara_hub_fanouts_total %d\n", h.stats.fanouts.Load())
	fmt.Fprintf(w, "# HELP capybara_hub_cache_hits_total Requests served from a cached or in-flight fan-out.\n# TYPE capybara_hub_cache_hits_total counter\ncapybara_hub_cache_hits_total %d\n", h.stats.cacheHits.Load())
	fmt.Fprintf(w, "# HELP capybara_hub_agent_errors_total Failed agent requests.\n# TYPE capybara_hub_agent_errors_total counter\ncapybara_hub_agent_errors_total %d\n", h.stats.agentErrors.Load())
	fmt.Fprintf(w, "# HELP capybara_hub_requests_total API requests.\n# TYPE capybara_hub_requests_total counter\ncapybara_hub_requests_total %d\n", h.stats.requests.Load())
}
