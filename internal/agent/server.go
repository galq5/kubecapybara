package agent

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Handler returns the agent HTTP API:
//
//	GET  /healthz
//	GET  /v1/status
//	GET  /v1/snapshot?window=60s | ?from=<unix|rfc3339>&to=<unix|rfc3339>
//	POST /v1/profile?entity=pod:<uid>&seconds=30&hz=99
//	GET  /metrics
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	api := a.requireToken
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/v1/status", api(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"node":       a.cfg.Node,
			"version":    a.cfg.Version,
			"collectors": a.Status(),
			"oldest":     a.store.Oldest(),
			"interval":   a.cfg.Interval.String(),
		})
	}))
	mux.HandleFunc("/v1/snapshot", api(func(w http.ResponseWriter, r *http.Request) {
		from, to, err := parseRange(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, a.Snapshot(from, to, r.URL.Query().Get("lite") == "1"))
	}))
	mux.HandleFunc("/v1/profile", api(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		entity := q.Get("entity")
		if entity == "" {
			http.Error(w, "entity is required (e.g. pod:<uid>)", http.StatusBadRequest)
			return
		}
		secs, _ := strconv.Atoi(q.Get("seconds"))
		if secs <= 0 {
			secs = 10
		}
		if secs > 120 {
			secs = 120
		}
		hz, _ := strconv.Atoi(q.Get("hz"))
		prof, err := a.profiler.Profile(r.Context(), entity, time.Duration(secs)*time.Second, hz)
		if err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, ErrBusy) {
				code = http.StatusConflict
			}
			http.Error(w, err.Error(), code)
			return
		}
		writeJSON(w, prof)
	}))
	mux.HandleFunc("/v1/counters", api(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		secs, _ := strconv.Atoi(q.Get("seconds"))
		if secs <= 0 || secs > 60 {
			secs = 5
		}
		c, err := a.Counters(r.Context(), q.Get("entity"), time.Duration(secs)*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, c)
	}))
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Second))
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		a.metrics.write(w)
	})
	return mux
}

// TokenHeader carries the shared agent API token.
const TokenHeader = "X-Capybara-Token"

// requireToken rejects requests without the configured token. The header
// survives the Kubernetes API server pod proxy (which strips the caller's
// own Authorization header), so access is gated by who may read the token
// Secret and use pods/proxy.
func (a *Agent) requireToken(h http.HandlerFunc) http.HandlerFunc {
	if a.cfg.Token == "" {
		return h
	}
	want := []byte(a.cfg.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(TokenHeader)), want) != 1 {
			http.Error(w, "missing or invalid "+TokenHeader, http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Parse(time.RFC3339, s)
}

func parseRange(r *http.Request) (time.Time, time.Time, error) {
	q := r.URL.Query()
	now := time.Now()
	to, err := parseTime(q.Get("to"))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if to.IsZero() {
		to = now
	}
	from, err := parseTime(q.Get("from"))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if from.IsZero() {
		win := time.Minute
		if ws := q.Get("window"); ws != "" {
			d, err := time.ParseDuration(strings.TrimSpace(ws))
			if err != nil {
				return time.Time{}, time.Time{}, err
			}
			win = d
		}
		from = to.Add(-win)
	}
	return from, to, nil
}
