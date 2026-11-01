package agent

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/model"
)

const maxEndpointsPerEntity = 200

// httpCollector: plaintext HTTP/1.x RED metrics per route.
type httpCollector struct {
	a    *Agent
	objs bpf.HttpObjects
	l    linker
	rd   *ringbuf.Reader

	mu       sync.Mutex
	cur      *Window
	lastWarn map[string]time.Time
}

func (c *httpCollector) Name() string { return "http" }

func (c *httpCollector) Start(a *Agent) error {
	c.a = a
	c.cur = NewWindow(time.Time{}, time.Time{})
	c.lastWarn = map[string]time.Time{}
	if err := bpf.LoadHttpObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	p := c.objs.HttpPrograms
	if err := errors.Join(
		c.l.tracepoint("syscalls", "sys_enter_read", p.EnterReadTp),
		c.l.tracepoint("syscalls", "sys_exit_read", p.ExitReadTp),
		c.l.tracepoint("syscalls", "sys_enter_write", p.EnterWriteTp),
	); err != nil {
		return err
	}
	for _, err := range []error{
		c.l.tracepoint("syscalls", "sys_enter_recvfrom", p.EnterRecvfromTp),
		c.l.tracepoint("syscalls", "sys_exit_recvfrom", p.ExitRecvfromTp),
		c.l.tracepoint("syscalls", "sys_enter_sendto", p.EnterSendtoTp),
		c.l.tracepoint("syscalls", "sys_enter_writev", p.EnterWritevTp),
	} {
		if err != nil {
			a.log.Warn("http: optional hook unavailable", "err", err)
		}
	}
	rd, err := ringbuf.NewReader(c.objs.HttpEvents)
	if err != nil {
		return err
	}
	c.rd = rd
	go c.read()
	return nil
}

func (c *httpCollector) read() {
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		ev, ok := castSample[bpf.HttpHttpEvent](rec.RawSample)
		if !ok {
			continue
		}
		c.handle(ev)
	}
}

// ParseRequestLine extracts method and path from "GET /x?y HTTP/1.1\r\n...".
func ParseRequestLine(b []byte) (method, path string, ok bool) {
	line := string(b)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return "", "", false
	}
	method, path = parts[0], parts[1]
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		path = "/"
	}
	return method, path, true
}

// ParseStatus extracts the status code from "HTTP/1.1 200 OK".
func ParseStatus(b []byte) int {
	s := string(b)
	if len(s) < 12 || !strings.HasPrefix(s, "HTTP/") {
		return 0
	}
	i := strings.IndexByte(s, ' ')
	if i < 0 || len(s) < i+4 {
		return 0
	}
	code, err := strconv.Atoi(s[i+1 : i+4])
	if err != nil {
		return 0
	}
	return code
}

var (
	reUUID   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reNum    = regexp.MustCompile(`^[0-9]+$`)
	reHex    = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	reMixed  = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
	reHasNum = regexp.MustCompile(`[0-9]`)
)

// NormalizePath collapses IDs in URL paths so routes aggregate:
// /users/123/orders/4f1c... -> /users/:id/orders/:id
func NormalizePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		if reNum.MatchString(s) || reUUID.MatchString(s) || reHex.MatchString(s) ||
			(reMixed.MatchString(s) && reHasNum.MatchString(s)) {
			segs[i] = ":id"
		}
	}
	out := strings.Join(segs, "/")
	if len(out) > 80 {
		out = out[:80] + "…"
	}
	return out
}

func statusClass(code int) string {
	if code < 100 || code > 599 {
		return "other"
	}
	return fmt.Sprintf("%dxx", code/100)
}

func (c *httpCollector) handleDB(ev *bpf.HttpHttpEvent) {
	name, ok := protoNames[ev.Proto]
	if !ok {
		return
	}
	req := cbytes(ev.Req[:])
	if int(ev.Off) < len(req) {
		req = req[ev.Off:] // a coalesced frame later in the captured write
	}
	query := ParseDBRequest(ev.Proto, req)
	if query == "" {
		return // not a request after all (e.g. a Redis server's reply)
	}
	failed := DBError(ev.Proto, cbytes(ev.Resp[:]))
	entity := c.a.resolver.Entity(ev.Cgroup)
	latUs := ev.LatencyNs / 1000

	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.cur.Entity(entity)
	if e.DB == nil {
		e.DB = map[string]*model.DBQuery{}
	}
	k := dbKey(ev.Proto, query)
	q, ok := e.DB[k]
	if !ok {
		if len(e.DB) >= model.MaxDBQueries {
			k = dbKey(ev.Proto, "(other)")
			q = e.DB[k]
		}
		if q == nil {
			q = &model.DBQuery{Proto: name, Query: query}
			if len(e.DB) >= model.MaxDBQueries {
				q.Query = "(other)"
			}
			e.DB[k] = q
		}
	}
	q.Count++
	q.Lat.Observe(latUs)
	if failed {
		q.Errors++
		if kind := DBErrorKind(ev.Proto, cbytes(ev.Resp[:])); kind != "" {
			if q.ErrorKinds == nil {
				q.ErrorKinds = map[string]uint64{}
			}
			q.ErrorKinds[kind]++
		}
	}
}

func (c *httpCollector) handle(ev *bpf.HttpHttpEvent) {
	if ev.Proto != protoHTTP && ev.Proto != 0 {
		c.handleDB(ev)
		return
	}
	method, path, ok := ParseRequestLine(cbytes(ev.Req[:]))
	if !ok {
		return
	}
	code := ParseStatus(cbytes(ev.Resp[:]))
	path = NormalizePath(path)
	role := "server"
	if ev.Role == 1 {
		role = "client"
	}
	entity := c.a.resolver.Entity(ev.Cgroup)
	latUs := ev.LatencyNs / 1000

	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.cur.Entity(entity)
	if e.HTTP == nil {
		e.HTTP = map[string]*model.HTTPEndpoint{}
	}
	key := role + " " + method + " " + path
	ep, ok := e.HTTP[key]
	if !ok {
		if len(e.HTTP) >= maxEndpointsPerEntity {
			path = "(other)"
			key = role + " " + method + " " + path
			ep = e.HTTP[key]
		}
		if ep == nil {
			ep = &model.HTTPEndpoint{Role: role, Method: method, Path: path, Status: map[string]uint64{}}
			e.HTTP[key] = ep
		}
	}
	ep.Count++
	ep.Status[statusClass(code)]++
	ep.Lat.Observe(latUs)

	if code >= 500 {
		now := time.Now()
		if now.Sub(c.lastWarn[entity]) > 10*time.Second {
			c.lastWarn[entity] = now
			c.a.rec.Add(model.Event{
				Time: c.a.clock.wall(ev.Ts), Entity: entity, Type: model.EvHTTPError, Severity: model.SevWarn, PID: ev.Pid,
				Message: fmt.Sprintf("HTTP %d for %s %s (%s, %s)", code, method, path, role, (time.Duration(latUs) * time.Microsecond).Round(time.Microsecond)),
				Fields:  map[string]string{"status": fmt.Sprint(code), "path": path, "method": method, "role": role},
			})
		}
	}
}

func (c *httpCollector) Collect(w *Window) {
	c.mu.Lock()
	cur := c.cur
	c.cur = NewWindow(time.Time{}, time.Time{})
	c.mu.Unlock()
	for id, e := range cur.Entities {
		w.Entity(id).Merge(e)
	}
}

func (c *httpCollector) Close() error {
	if c.rd != nil {
		_ = c.rd.Close()
	}
	c.l.close()
	return c.objs.Close()
}
