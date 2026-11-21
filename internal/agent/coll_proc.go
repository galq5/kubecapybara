package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/cgroups"
	"github.com/galq5/kubecapybara/internal/model"
)

const (
	procEvExec   = 1
	procEvExit   = 2
	procEvSignal = 3
	procEvOOM    = 4
)

var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "ash": true, "zsh": true, "ksh": true, "fish": true, "busybox": true,
}

// container runtime processes that legitimately start processes in containers
// wrappers that commonly (and legitimately) start shells
var shellWrappers = map[string]bool{
	"timeout": true, "env": true, "nice": true, "nohup": true, "tini": true, "dumb-init": true,
	"catatonit": true, "xargs": true, "make": true, "watch": true, "cron": true, "crond": true,
	"su": true, "sudo": true, "s6-supervise": true, "supervisord": true, "entrypoint.sh": true,
}

// (comm is truncated to 15 chars, e.g. "containerd-shim", "runc:[2:INIT]").
var runtimeParents = []string{"runc", "crun", "conmon", "containerd-shim", "youki", "crio"}

func isRuntime(comm string) bool {
	for _, r := range runtimeParents {
		if strings.HasPrefix(comm, r) {
			return true
		}
	}
	return false
}

// procCollector: exec/exit/signal/OOM events.
type procCollector struct {
	a    *Agent
	objs bpf.ProcObjects
	l    linker
	rd   *ringbuf.Reader

	// termKey(entity, pid) of a container's PID 1 -> when its termination
	// was requested: a SIGTERM, or any signal from the container runtime
	// (pod deletion, rollout, eviction, liveness restart, and the SIGKILL
	// after the grace period). The exit that follows is not a crash. Keyed
	// by process, not pod: the containers of a pod stop one by one, and the
	// pod sandbox (pause) only ever gets the runtime's SIGKILL.
	terminating map[string]time.Time
}

func termKey(entity string, pid uint32) string {
	return entity + "|" + strconv.FormatUint(uint64(pid), 10)
}

// terminationGrace is how long after a SIGTERM to PID 1 an exit (or the
// final SIGKILL) is considered part of a requested termination.
const terminationGrace = 15 * time.Minute

var secretArg = regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credentials?|auth)[a-z0-9_-]*\s*[=:]\s*|--?(?:password|passwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credentials?)[a-z0-9_-]*\s+)("[^"]*"|'[^']*'|\S+)`)

// RedactArgs masks values of secret-looking arguments (--password=x,
// TOKEN=y, --api-key z) so command lines can be shown safely.
func RedactArgs(args string) string {
	return secretArg.ReplaceAllString(args, "${1}***")
}

// isTermination reports whether an exit/kill of a container's PID 1
// (termKey) is a requested termination rather than a crash.
func (c *procCollector) isTermination(key string, sig, status int32, t time.Time) bool {
	if sig == 15 || status == 143 {
		return true
	}
	if at, ok := c.terminating[key]; ok && t.Sub(at) < terminationGrace {
		return true
	}
	return false
}

func (c *procCollector) markTerminating(key string, t time.Time) {
	c.terminating[key] = t
	if len(c.terminating) > 4096 {
		for k, at := range c.terminating {
			if t.Sub(at) > terminationGrace {
				delete(c.terminating, k)
			}
		}
	}
}

func (c *procCollector) Name() string { return "proc" }

func (c *procCollector) Start(a *Agent) error {
	c.a = a
	c.terminating = map[string]time.Time{}
	if err := bpf.LoadProcObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	p := c.objs.ProcPrograms
	if err := errors.Join(
		c.l.tracing(p.OnExec, "tp_btf/sched_process_exec"),
		c.l.tracing(p.OnExit, "tp_btf/sched_process_exit"),
		c.l.tracing(p.OnSignal, "tp_btf/signal_generate"),
	); err != nil {
		return err
	}
	if err := c.l.tracepoint("oom", "mark_victim", p.OnOom); err != nil {
		a.log.Warn("proc: oom tracing unavailable", "err", err)
	}
	rd, err := ringbuf.NewReader(c.objs.CapyProcEvents)
	if err != nil {
		return err
	}
	c.rd = rd
	go c.read()
	return nil
}

func (c *procCollector) read() {
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		ev, ok := castSample[bpf.ProcCapyProcEvent](rec.RawSample)
		if !ok {
			continue
		}
		c.handle(ev)
	}
}

func (c *procCollector) handle(ev *bpf.ProcCapyProcEvent) {
	a := c.a
	t := a.clock.wall(ev.Ts)
	comm := cstr(ev.Comm[:])

	switch ev.Type {
	case procEvExec:
		info := a.noteCgroup(ev.Cgroup, t)
		if info.PodUID == "" {
			return // host processes are too noisy for the event log
		}
		pcomm := cstr(ev.Pcomm[:])
		file := cstr(ev.Filename[:])
		args := RedactArgs(argsString(ev.Args[:]))
		fields := map[string]string{
			"file": file, "args": args, "ppid": fmt.Sprint(ev.Ppid), "parent": pcomm,
			"nsPid": fmt.Sprint(ev.NsPid), "uid": fmt.Sprint(ev.Uid),
		}
		evt := model.Event{
			Time: t, Entity: info.Entity, Type: model.EvExec, PID: ev.Pid, Comm: comm,
			Message: fmt.Sprintf("exec %s", strings.TrimSpace(args)),
			Fields:  fields,
		}
		base := filepath.Base(file)
		switch {
		case ev.Tty == 1 && ev.NsPid != 1 && isRuntime(pcomm):
			evt.Type = model.EvExecSession
			evt.Severity = model.SevWarn
			evt.Message = fmt.Sprintf("interactive exec session: %s (uid %d)", strings.TrimSpace(args), ev.Uid)
		case shells[base] && !shells[pcomm] && !shellWrappers[pcomm] && !isRuntime(pcomm) && ev.NsPid != 1:
			evt.Type = model.EvShell
			evt.Severity = model.SevWarn
			evt.Message = fmt.Sprintf("shell %s spawned by %s (pid %d): %s", base, pcomm, ev.Ppid, strings.TrimSpace(args))
		}
		if ev.Uid == 0 {
			fields["root"] = "true"
		}
		a.rec.Add(evt)

	case procEvExit:
		info := a.resolver.Lookup(ev.Cgroup)
		if info.PodUID == "" {
			return
		}
		status := (ev.Code >> 8) & 0xff
		sig := ev.Code & 0x7f
		msg := fmt.Sprintf("%s (pid %d) exited with status %d", comm, ev.Pid, status)
		if sig != 0 {
			msg = fmt.Sprintf("%s (pid %d) killed by %s", comm, ev.Pid, signalName(sig))
			if ev.Code&0x80 != 0 {
				msg += " (core dumped)"
			}
		}
		sev := model.SevInfo
		crashed := false
		if ev.NsPid == 1 {
			key := termKey(info.Entity, ev.Pid)
			msg = "container main process: " + msg
			if c.isTermination(key, sig, status, t) {
				msg += " (termination requested)"
			} else {
				sev = model.SevCrit
				crashed = true
			}
			delete(c.terminating, key)
		}
		a.rec.Add(model.Event{
			Time: t, Entity: info.Entity, Type: model.EvExit, Severity: sev, PID: ev.Pid, Comm: comm, Message: msg,
			Fields: map[string]string{"status": fmt.Sprint(status), "signal": fmt.Sprint(sig), "nsPid": fmt.Sprint(ev.NsPid)},
		})
		if crashed {
			a.rec.Crash(info.Entity, msg, t)
		}

	case procEvSignal:
		target := a.resolver.Lookup(ev.TargetCgroup)
		if target.PodUID == "" {
			return
		}
		sender := a.resolver.Lookup(ev.Cgroup)
		tcomm := cstr(ev.Tcomm[:])
		sname := signalName(ev.Code)
		from := fmt.Sprintf("%s (pid %d)", comm, ev.Pid)
		if ev.Pid == ev.TargetPid {
			from = "the kernel (fault in the process itself)"
		} else if sender.Entity != target.Entity {
			from += " in " + sender.Entity
		}
		sev := model.SevWarn
		if ev.Code == 15 {
			sev = model.SevInfo
		}
		msg := fmt.Sprintf("%s delivered to %s (pid %d) by %s", sname, tcomm, ev.TargetPid, from)
		a.rec.Add(model.Event{
			Time: t, Entity: target.Entity, Type: model.EvSignal, Severity: sev, PID: ev.TargetPid, Comm: tcomm, Message: msg,
			Fields: map[string]string{"signal": sname, "sender": comm, "senderPid": fmt.Sprint(ev.Pid), "senderEntity": sender.Entity, "nsPid": fmt.Sprint(ev.TargetNsPid)},
		})
		if ev.TargetNsPid == 1 {
			key := termKey(target.Entity, ev.TargetPid)
			// The runtime (runc kill, outside the pod) stops containers: its
			// SIGKILL ends the grace period, kills a PID 1 that ignores
			// SIGTERM (no handler: the kernel drops it unseen) and tears
			// down the pod sandbox.
			fromRuntime := ev.Pid != ev.TargetPid && sender.Entity != target.Entity && isRuntime(comm)
			switch {
			case ev.Code == 15 || fromRuntime:
				c.markTerminating(key, t)
			case ev.Code == 9 && c.isTermination(key, 0, 0, t):
			default:
				a.rec.Crash(target.Entity, msg, t)
			}
		}

	case procEvOOM:
		info := c.oomVictim(ev.Cgroup, ev.TargetPid)
		msg := fmt.Sprintf("OOM killer selected pid %d (anon-rss %s, file-rss %s, total-vm %s)",
			ev.TargetPid, kb(ev.Extra[1]), kb(ev.Extra[2]), kb(ev.Extra[0]))
		a.rec.Add(model.Event{
			Time: t, Entity: info.Entity, Type: model.EvOOM, Severity: model.SevCrit, PID: ev.TargetPid, Message: msg,
			Fields: map[string]string{"anonRssKB": fmt.Sprint(ev.Extra[1]), "totalVmKB": fmt.Sprint(ev.Extra[0])},
		})
		if info.PodUID != "" {
			a.rec.Crash(info.Entity, "OOM killed", t)
		}
	}
}

// oomVictim returns the cgroup of the process the OOM killer selected. The
// tracepoint runs in the task whose allocation triggered the killer: with a
// container at its own limit that is a neighbour of the victim, but when the
// node itself runs out of memory it can be any process, which must not get
// the crash report. The victim is still in /proc when it is marked; if it is
// gone already, fall back to the triggering task's cgroup.
func (c *procCollector) oomVictim(trigger uint64, victimPid uint32) *cgroups.Info {
	a := c.a
	if cg, err := a.resolver.ProcCgroupID(a.cfg.ProcRoot, victimPid); err == nil {
		return a.resolver.Lookup(cg)
	}
	return a.resolver.Lookup(trigger)
}

func kb(v uint64) string {
	switch {
	case v >= 1<<20:
		return fmt.Sprintf("%.1fGiB", float64(v)/(1<<20))
	case v >= 1<<10:
		return fmt.Sprintf("%.1fMiB", float64(v)/(1<<10))
	}
	return fmt.Sprintf("%dKiB", v)
}

func (c *procCollector) Collect(w *Window) {}

func (c *procCollector) Close() error {
	if c.rd != nil {
		_ = c.rd.Close()
	}
	c.l.close()
	return c.objs.Close()
}
