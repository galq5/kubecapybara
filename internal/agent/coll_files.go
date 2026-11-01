package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/model"
)

const (
	fileOpRead  = 1
	fileOpWrite = 2
	fileOpFsync = 3
)

// filesCollector reports slow operations on regular files per entity.
type filesCollector struct {
	a    *Agent
	objs bpf.FilesObjects
	l    linker
	rd   *ringbuf.Reader

	mu    sync.Mutex
	cur   *Window
	paths map[string]string // "parent/name" -> full path seen via /proc
}

// pseudo filesystems whose "files" are kernel interfaces, not storage
var pseudoFS = map[string]bool{
	"cgroup": true, "cgroup2": true, "proc": true, "sysfs": true, "debugfs": true, "tracefs": true,
	"bpf": true, "securityfs": true, "configfs": true, "pstore": true, "devpts": true,
}

func (c *filesCollector) Name() string { return "files" }

func (c *filesCollector) Start(a *Agent) error {
	c.a = a
	c.cur = NewWindow(time.Time{}, time.Time{})
	c.paths = map[string]string{}
	if err := bpf.LoadFilesObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	th := a.cfg.FileThreshold
	if th <= 0 {
		th = 10 * time.Millisecond
	}
	if err := c.objs.ThresholdNs.Set(uint64(th)); err != nil {
		return fmt.Errorf("set threshold: %w", err)
	}
	p := c.objs.FilesPrograms
	for _, x := range []struct {
		sc           string
		enter, leave func() error
	}{
		{"read", func() error { return c.l.tracepoint("syscalls", "sys_enter_read", p.EnterRead) }, func() error { return c.l.tracepoint("syscalls", "sys_exit_read", p.ExitRead) }},
		{"pread64", func() error { return c.l.tracepoint("syscalls", "sys_enter_pread64", p.EnterPread64) }, func() error { return c.l.tracepoint("syscalls", "sys_exit_pread64", p.ExitPread64) }},
		{"readv", func() error { return c.l.tracepoint("syscalls", "sys_enter_readv", p.EnterReadv) }, func() error { return c.l.tracepoint("syscalls", "sys_exit_readv", p.ExitReadv) }},
		{"write", func() error { return c.l.tracepoint("syscalls", "sys_enter_write", p.EnterWrite) }, func() error { return c.l.tracepoint("syscalls", "sys_exit_write", p.ExitWrite) }},
		{"pwrite64", func() error { return c.l.tracepoint("syscalls", "sys_enter_pwrite64", p.EnterPwrite64) }, func() error { return c.l.tracepoint("syscalls", "sys_exit_pwrite64", p.ExitPwrite64) }},
		{"writev", func() error { return c.l.tracepoint("syscalls", "sys_enter_writev", p.EnterWritev) }, func() error { return c.l.tracepoint("syscalls", "sys_exit_writev", p.ExitWritev) }},
		{"fsync", func() error { return c.l.tracepoint("syscalls", "sys_enter_fsync", p.EnterFsync) }, func() error { return c.l.tracepoint("syscalls", "sys_exit_fsync", p.ExitFsync) }},
		{"fdatasync", func() error { return c.l.tracepoint("syscalls", "sys_enter_fdatasync", p.EnterFdatasync) }, func() error { return c.l.tracepoint("syscalls", "sys_exit_fdatasync", p.ExitFdatasync) }},
	} {
		// attach the exit first and the entry only if the exit worked, so no
		// start record is left without its exit
		err := x.leave()
		if err == nil {
			err = x.enter()
		}
		if err != nil {
			if x.sc == "read" || x.sc == "write" {
				return err
			}
			a.log.Warn("files: hook unavailable", "syscall", x.sc, "err", err)
		}
	}
	rd, err := ringbuf.NewReader(c.objs.FileEvents)
	if err != nil {
		return err
	}
	c.rd = rd
	go c.read()
	return nil
}

func (c *filesCollector) read() {
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		ev, ok := castSample[bpf.FilesFileEvent](rec.RawSample)
		if !ok {
			continue
		}
		c.handle(ev)
	}
}

// filePath prefers the full path from /proc/<pid>/fd and falls back to
// "parent/name" captured in the kernel (the file may be closed already).
// Resolved paths are remembered so later events of a closed file keep the
// same name. Called with c.mu held.
func (c *filesCollector) filePath(ev *bpf.FilesFileEvent) string {
	parent := cstr(ev.Parent[:])
	name := cstr(ev.Name[:])
	short := parent + "/" + name
	link := filepath.Join(c.a.cfg.ProcRoot, strconv.Itoa(int(ev.Pid)), "fd", strconv.Itoa(int(ev.Fd)))
	if p, err := os.Readlink(link); err == nil && filepath.Base(p) == name {
		if len(c.paths) > 10000 {
			c.paths = map[string]string{}
		}
		c.paths[short] = p
		return p
	}
	if p, ok := c.paths[short]; ok {
		return p
	}
	if parent == "" || parent == "/" {
		return "/" + name
	}
	return "…/" + short
}

func (c *filesCollector) handle(ev *bpf.FilesFileEvent) {
	if pseudoFS[cstr(ev.Fstype[:])] {
		return
	}
	entity := c.a.resolver.Entity(ev.Cgroup)
	c.mu.Lock()
	defer c.mu.Unlock()
	path := c.filePath(ev)
	e := c.cur.Entity(entity)
	if e.Files == nil {
		e.Files = map[string]*model.FileStats{}
	}
	f, ok := e.Files[path]
	if !ok {
		if len(e.Files) >= model.MaxFiles {
			path = "(other files)"
			f = e.Files[path]
		}
		if f == nil {
			f = &model.FileStats{Path: path, FSType: cstr(ev.Fstype[:])}
			e.Files[path] = f
		}
	}
	switch ev.Op {
	case fileOpRead:
		f.Reads++
	case fileOpWrite:
		f.Writes++
	case fileOpFsync:
		f.Fsyncs++
	}
	f.WaitNs += ev.DurNs
	if ev.DurNs > f.MaxNs {
		f.MaxNs = ev.DurNs
	}
	if ev.Ret > 0 {
		f.Bytes += uint64(ev.Ret)
	}
}

func (c *filesCollector) Collect(w *Window) {
	c.mu.Lock()
	cur := c.cur
	c.cur = NewWindow(time.Time{}, time.Time{})
	c.mu.Unlock()
	for id, e := range cur.Entities {
		w.Entity(id).Merge(e)
	}
}

func (c *filesCollector) Close() error {
	if c.rd != nil {
		_ = c.rd.Close()
	}
	c.l.close()
	return c.objs.Close()
}
