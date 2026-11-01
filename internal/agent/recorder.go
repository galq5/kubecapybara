package agent

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/galq5/kubecapybara/internal/model"
)

const (
	maxEvents       = 20000
	maxCrashes      = 100
	maxStartups     = 300
	startupWindow   = 3 * time.Minute
	maxStartupEvs   = 200
	seriesLen       = 120
	crashLookback   = 2 * time.Minute
	maxDNSNames     = 20000
	dnsNameLifetime = 2 * time.Hour
)

// Recorder is the flight recorder: a bounded history of notable events,
// per-entity resource samples, crash reports and startup timelines.
type Recorder struct {
	mu       sync.Mutex
	events   []model.Event
	head     int
	full     bool
	crashes  []model.CrashReport
	startups map[string]*model.Startup
	listens  map[string]model.Listen
	series   map[string][]model.ResourceSample
	dnsNames map[string]dnsName
	lastCrash map[string]time.Time
}

type dnsName struct {
	name string
	seen time.Time
}

// NewRecorder creates an empty recorder.
func NewRecorder() *Recorder {
	return &Recorder{
		events:    make([]model.Event, maxEvents),
		startups:  map[string]*model.Startup{},
		listens:   map[string]model.Listen{},
		series:    map[string][]model.ResourceSample{},
		dnsNames:  map[string]dnsName{},
		lastCrash: map[string]time.Time{},
	}
}

// Add records an event.
func (r *Recorder) Add(ev model.Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if ev.Severity == "" {
		ev.Severity = model.SevInfo
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[r.head] = ev
	r.head = (r.head + 1) % maxEvents
	if r.head == 0 {
		r.full = true
	}
	if st, ok := r.startups[ev.Entity]; ok && ev.Time.Sub(st.FirstSeen) < startupWindow && len(st.Events) < maxStartupEvs {
		st.Events = append(st.Events, ev)
	}
}

// eventsLocked returns events in chronological order.
func (r *Recorder) eventsLocked() []model.Event {
	if !r.full {
		return append([]model.Event(nil), r.events[:r.head]...)
	}
	out := make([]model.Event, 0, maxEvents)
	out = append(out, r.events[r.head:]...)
	return append(out, r.events[:r.head]...)
}

// Events returns events in [from, to], optionally filtered by entity.
func (r *Recorder) Events(from, to time.Time, entity string, limit int) []model.Event {
	r.mu.Lock()
	all := r.eventsLocked()
	r.mu.Unlock()
	var out []model.Event
	for _, ev := range all {
		if ev.Time.Before(from) || ev.Time.After(to) {
			continue
		}
		if entity != "" && ev.Entity != entity {
			continue
		}
		out = append(out, ev)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// BeginStartup starts collecting a startup timeline for a new entity.
func (r *Recorder) BeginStartup(entity string, firstSeen time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.startups[entity]; ok {
		return false
	}
	if len(r.startups) >= maxStartups {
		var oldest string
		var ot time.Time
		for k, v := range r.startups {
			if oldest == "" || v.FirstSeen.Before(ot) {
				oldest, ot = k, v.FirstSeen
			}
		}
		delete(r.startups, oldest)
	}
	r.startups[entity] = &model.Startup{Entity: entity, FirstSeen: firstSeen}
	return true
}

// IsStarting reports whether an entity is within its startup window.
func (r *Recorder) IsStarting(entity string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.startups[entity]
	return ok && now.Sub(st.FirstSeen) < startupWindow
}

// Startups returns startup timelines that began in [from, to].
func (r *Recorder) Startups(from, to time.Time) []model.Startup {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.Startup
	for _, st := range r.startups {
		if st.FirstSeen.Before(from.Add(-startupWindow)) || st.FirstSeen.After(to) {
			continue
		}
		c := *st
		c.Events = append([]model.Event(nil), st.Events...)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.Before(out[j].FirstSeen) })
	return out
}

// Listen records a listening socket.
func (r *Recorder) Listen(l model.Listen) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listens[fmt.Sprintf("%s|%d", l.Entity, l.Port)] = l
}

// Listens returns all known listening sockets.
func (r *Recorder) Listens() []model.Listen {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]model.Listen, 0, len(r.listens))
	for _, l := range r.listens {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Entity != out[j].Entity {
			return out[i].Entity < out[j].Entity
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// Sample appends a resource sample for an entity.
func (r *Recorder) Sample(entity string, s model.ResourceSample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ser := append(r.series[entity], s)
	if len(ser) > seriesLen {
		ser = ser[len(ser)-seriesLen:]
	}
	r.series[entity] = ser
}

// Crash freezes a crash report for an entity (deduplicated per 10s).
func (r *Recorder) Crash(entity, reason string, at time.Time) {
	r.mu.Lock()
	if last, ok := r.lastCrash[entity]; ok && at.Sub(last) < 10*time.Second {
		// merge reason into the latest report
		for i := len(r.crashes) - 1; i >= 0; i-- {
			if r.crashes[i].Entity == entity {
				if !strings.Contains(r.crashes[i].Reason, reason) {
					r.crashes[i].Reason += "; " + reason
				}
				break
			}
		}
		r.mu.Unlock()
		return
	}
	r.lastCrash[entity] = at
	all := r.eventsLocked()
	series := append([]model.ResourceSample(nil), r.series[entity]...)
	r.mu.Unlock()

	var evs []model.Event
	for _, ev := range all {
		if ev.Entity == entity && !ev.Time.Before(at.Add(-crashLookback)) && !ev.Time.After(at.Add(5*time.Second)) {
			evs = append(evs, ev)
		}
	}
	rep := model.CrashReport{Entity: entity, Time: at, Reason: reason, Events: evs, Series: series}
	r.mu.Lock()
	r.crashes = append(r.crashes, rep)
	if len(r.crashes) > maxCrashes {
		r.crashes = r.crashes[len(r.crashes)-maxCrashes:]
	}
	r.mu.Unlock()
}

// Crashes returns crash reports in [from, to].
func (r *Recorder) Crashes(from, to time.Time) []model.CrashReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.CrashReport
	for _, c := range r.crashes {
		if c.Time.Before(from) || c.Time.After(to) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// LearnName remembers that ip resolved from name.
func (r *Recorder) LearnName(ip, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if len(r.dnsNames) >= maxDNSNames {
		for k, v := range r.dnsNames {
			if now.Sub(v.seen) > dnsNameLifetime || len(r.dnsNames) >= maxDNSNames {
				delete(r.dnsNames, k)
			}
			if len(r.dnsNames) < maxDNSNames*9/10 {
				break
			}
		}
	}
	r.dnsNames[ip] = dnsName{name: name, seen: now}
}

// Names returns the ip->name cache.
func (r *Recorder) Names() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.dnsNames))
	for ip, n := range r.dnsNames {
		out[ip] = n.name
	}
	return out
}
