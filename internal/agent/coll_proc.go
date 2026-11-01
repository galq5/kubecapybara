package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/galq5/kubecapybara/internal/bpf"
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
var runtimeParents = []string{"runc", "crun", "conmon", "containerd-shim", "youki"}

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
}

func (c *procCollector) Name() string { return "proc" }

func (c *procCollector) Start(a *Agent) error {
	c.a = a
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
		args := argsString(ev.Args[:])
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
		if ev.NsPid == 1 {
			sev = model.SevCrit
			msg = "container main process: " + msg
		}
		a.rec.Add(model.Event{
			Time: t, Entity: info.Entity, Type: model.EvExit, Severity: sev, PID: ev.Pid, Comm: comm, Message: msg,
			Fields: map[string]string{"status": fmt.Sprint(status), "signal": fmt.Sprint(sig), "nsPid": fmt.Sprint(ev.NsPid)},
		})
		if ev.NsPid == 1 && (sig != 0 || status != 0) {
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
		if ev.TargetNsPid == 1 && ev.Code != 15 {
			a.rec.Crash(target.Entity, msg, t)
		}

	case procEvOOM:
		info := a.resolver.Lookup(ev.Cgroup)
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
