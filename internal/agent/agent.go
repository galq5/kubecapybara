// Package agent implements the per-node kubecapybara agent: it loads the eBPF
// collectors, aggregates their data into time windows and serves it over HTTP.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/galq5/kubecapybara/internal/cgroups"
	"github.com/galq5/kubecapybara/internal/model"
)

// Config configures the agent.
type Config struct {
	Node          string
	Listen        string
	Interval      time.Duration
	FineRetention time.Duration
	Retention     time.Duration
	CgroupRoot    string // cgroup v2 mount; autodetected when empty
	HostPrefix    string // where the host filesystem is mounted (e.g. /host)
	ProcRoot      string // host /proc (requires hostPID)
	EnableL7      bool
	EnableFiles   bool          // time read/write/fsync on regular files
	FileThreshold time.Duration // report file operations slower than this
	EnableVoIP    bool          // SIP signalling and RTP media quality
	SIPPorts      []uint16      // SIP ports (UDP and TCP), up to 4
	RTPPortLow    uint16        // RTP port range (local port)
	RTPPortHigh   uint16
	Disable       map[string]bool
	ClusterDomain string
	Version       string
	// StateDir, when set, persists history and crash reports across restarts.
	StateDir string
	// Token, when set, must be sent in the X-Capybara-Token header to use
	// the /v1 API (healthz and metrics stay open).
	Token string
	Log   *slog.Logger
}

// Collector is one data source.
type Collector interface {
	Name() string
	Start(a *Agent) error
	Collect(w *Window)
	Close() error
}

// Agent is the node agent.
type Agent struct {
	saveMu   sync.Mutex
	cfg      Config
	log      *slog.Logger
	resolver *cgroups.Resolver
	store    *Store
	rec      *Recorder
	clock    clock
	metrics  *metrics

	collectors []Collector
	statusMu   sync.RWMutex
	status     map[string]string

	net      *netCollector
	profiler *profileCollector

	seenMu sync.Mutex
	seen   map[string]bool
}

// New creates an agent.
func New(cfg Config) (*Agent, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.FineRetention == 0 {
		cfg.FineRetention = 15 * time.Minute
	}
	if cfg.Retention == 0 {
		cfg.Retention = 6 * time.Hour
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.ClusterDomain == "" {
		cfg.ClusterDomain = "cluster.local"
	}
	root := cfg.CgroupRoot
	if root == "" {
		var err error
		root, err = cgroups.DetectRoot(cfg.HostPrefix)
		if err != nil {
			return nil, err
		}
	}
	a := &Agent{
		cfg:      cfg,
		log:      cfg.Log,
		resolver: cgroups.NewResolver(root),
		store:    NewStore(cfg.FineRetention, cfg.Retention),
		rec:      NewRecorder(),
		clock:    newClock(),
		status:   map[string]string{},
		seen:     map[string]bool{},
	}
	a.metrics = newMetrics(a)
	a.net = &netCollector{}
	a.profiler = &profileCollector{}
	a.collectors = []Collector{
		a.net,
		&dropCollector{},
		&dnsCollector{},
		&schedCollector{},
		&ioCollector{},
		&procCollector{},
		&cgroupfsCollector{},
		&netstatCollector{},
		&nodeCollector{},
		a.profiler,
	}
	if cfg.EnableL7 {
		a.collectors = append(a.collectors, &httpCollector{})
	} else {
		a.setStatus("http", "disabled (enable with --l7)")
	}
	if cfg.EnableFiles {
		a.collectors = append(a.collectors, &filesCollector{})
	} else {
		a.setStatus("files", "disabled (enable with --files)")
	}
	if cfg.EnableVoIP {
		a.collectors = append(a.collectors, &voipCollector{})
	} else {
		a.setStatus("voip", "disabled (enable with --voip)")
	}
	a.log.Info("cgroup v2 root", "path", root)
	return a, nil
}

func (a *Agent) setStatus(name, s string) {
	a.statusMu.Lock()
	a.status[name] = s
	a.statusMu.Unlock()
}

// Status returns collector states.
func (a *Agent) Status() map[string]string {
	a.statusMu.RLock()
	defer a.statusMu.RUnlock()
	out := make(map[string]string, len(a.status))
	for k, v := range a.status {
		out[k] = v
	}
	return out
}

// Start loads all collectors. Failing collectors are disabled, not fatal.
func (a *Agent) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		a.log.Warn("removing memlock rlimit failed", "err", err)
	}
	var started []Collector
	for _, c := range a.collectors {
		if a.cfg.Disable[c.Name()] {
			a.setStatus(c.Name(), "disabled")
			continue
		}
		if err := c.Start(a); err != nil {
			a.log.Warn("collector failed to start", "collector", c.Name(), "err", err)
			a.setStatus(c.Name(), "error: "+err.Error())
			_ = c.Close()
			continue
		}
		a.setStatus(c.Name(), "ok")
		started = append(started, c)
	}
	a.collectors = started
	if len(started) == 0 {
		return errors.New("no collector could be started (are we privileged?)")
	}
	return nil
}

// Run starts collectors, the HTTP server and the collection loop. It blocks
// until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.LoadState(); err != nil {
		a.log.Warn("could not restore state", "err", err)
	}
	if err := a.Start(); err != nil {
		return err
	}
	defer a.Close()
	var save sync.WaitGroup
	saving := make(chan struct{}, 1)
	defer func() {
		save.Wait()
		if err := a.SaveState(); err != nil {
			a.log.Warn("could not save state", "err", err)
		}
	}()
	lastSave := time.Now()

	if a.cfg.Token == "" {
		a.log.Warn("API authentication disabled: anyone who can reach the agent port can read process command lines and traffic data; set CAPYBARA_TOKEN")
	}
	srv := &http.Server{Addr: a.cfg.Listen, Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		a.log.Info("serving API", "addr", a.cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	t := time.NewTicker(a.cfg.Interval)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
			return nil
		case err := <-errCh:
			return err
		case now := <-t.C:
			a.Tick(last, now)
			last = now
			if a.cfg.StateDir != "" && now.Sub(lastSave) >= time.Minute && len(saving) == 0 {
				lastSave = now
				saving <- struct{}{}
				save.Add(1)
				go func() {
					defer save.Done()
					defer func() { <-saving }()
					if err := a.SaveState(); err != nil {
						a.log.Warn("could not save state", "err", err)
					}
				}()
			}
		}
	}
}

// Tick collects one window.
func (a *Agent) Tick(start, end time.Time) {
	w := NewWindow(start, end)
	for _, c := range a.collectors {
		func() {
			defer func() {
				if r := recover(); r != nil {
					a.log.Error("collector panic", "collector", c.Name(), "panic", r)
				}
			}()
			c.Collect(w)
		}()
	}
	a.rec.Prune(end)
	a.store.Add(w)
	a.metrics.observe(w)
}

// Close detaches all programs.
func (a *Agent) Close() {
	for _, c := range a.collectors {
		_ = c.Close()
	}
}

// Snapshot returns aggregated data for [from, to]. A lite snapshot carries
// only the aggregated metrics (no events, DNS name cache, listeners, crash
// reports or startup traces), which is all a baseline comparison needs.
func (a *Agent) Snapshot(from, to time.Time, lite bool) *model.Snapshot {
	w := a.store.Query(from, to)
	snap := w.ToSnapshot()
	snap.Node = a.cfg.Node
	snap.Version = a.cfg.Version
	snap.Collectors = a.Status()
	if !lite {
		snap.DNSNames = a.rec.Names()
		snap.Events = a.rec.Events(from, to, "", 5000)
		snap.Listens = a.rec.Listens()
		snap.Crashes = a.rec.Crashes(from, to)
		snap.Startups = a.rec.Startups(from, to)
		snap.Series = a.rec.Series(from, to)
	}
	if snap.From.IsZero() {
		snap.From = from
	}
	if snap.To.IsZero() {
		snap.To = to
	}
	return snap
}

// noteCgroup is called when an exec is seen in a cgroup. New containers
// (created within the last minute) start a startup timeline and get their
// connects traced for a few minutes.
func (a *Agent) noteCgroup(id uint64, at time.Time) *cgroups.Info {
	info := a.resolver.Lookup(id)
	if info.PodUID == "" {
		return info
	}
	a.seenMu.Lock()
	seen := a.seen[info.Path]
	a.seen[info.Path] = true
	a.seenMu.Unlock()
	if seen {
		return info
	}
	if !info.Created.IsZero() && at.Sub(info.Created) < time.Minute {
		a.rec.BeginStartup(info.Entity, info.Created)
		a.net.markYoung(info.ID, startupWindow)
		a.rec.Add(model.Event{
			Time: info.Created, Entity: info.Entity, Type: "container_start",
			Message: fmt.Sprintf("container cgroup created %s", shortID(info.ContainerID)),
		})
	}
	return info
}

func (a *Agent) isStarting(entity string) bool {
	return a.rec.IsStarting(entity, time.Now())
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// markSeenExisting marks all cgroups that exist at startup as already seen,
// so that only containers started after the agent produce startup timelines.
func (a *Agent) markSeenExisting() {
	a.resolver.Scan()
	pods := a.resolver.Pods()
	a.seenMu.Lock()
	defer a.seenMu.Unlock()
	for uid := range pods {
		for _, id := range a.resolver.IDsForEntity("pod:" + uid) {
			info := a.resolver.Lookup(id)
			if time.Since(info.Created) > time.Minute {
				a.seen[info.Path] = true
			}
		}
	}
}

func sortedStrings(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
