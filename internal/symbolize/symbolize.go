// Package symbolize resolves kernel and user space instruction addresses to
// function names using /proc/kallsyms, /proc/<pid>/maps and ELF symbol
// tables (with a Go pclntab fallback for stripped Go binaries).
package symbolize

import (
	"bufio"
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Symbolizer caches symbol tables. Safe for concurrent use.
type Symbolizer struct {
	procRoot string

	kOnce sync.Once
	ksyms []sym

	mu       sync.Mutex
	elfs     map[string]*elfInfo
	maps     map[uint32][]mapping
	perfMaps map[uint32][]sym // JIT symbols (JVM perf maps, node --perf-basic-prof)
}

type sym struct {
	addr uint64
	name string
}

type mapping struct {
	start, end, offset uint64
	path               string
}

type elfInfo struct {
	err   error
	typ   elf.Type
	loads []elf.ProgHeader
	syms  []sym
	gotab *gosym.Table
}

// New creates a symbolizer reading from procRoot (usually /proc).
func New(procRoot string) *Symbolizer {
	return &Symbolizer{procRoot: procRoot, elfs: map[string]*elfInfo{}, maps: map[uint32][]mapping{}, perfMaps: map[uint32][]sym{}}
}

// Kernel resolves a kernel address.
func (s *Symbolizer) Kernel(addr uint64) string {
	s.kOnce.Do(s.loadKallsyms)
	i := sort.Search(len(s.ksyms), func(i int) bool { return s.ksyms[i].addr > addr }) - 1
	if i < 0 {
		return fmt.Sprintf("[kernel] %#x", addr)
	}
	return s.ksyms[i].name
}

func (s *Symbolizer) loadKallsyms() {
	f, err := os.Open(filepath.Join(s.procRoot, "kallsyms"))
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		switch fields[1] {
		case "t", "T", "w", "W":
		default:
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		s.ksyms = append(s.ksyms, sym{addr, fields[2]})
	}
	sort.Slice(s.ksyms, func(i, j int) bool { return s.ksyms[i].addr < s.ksyms[j].addr })
}

// Forget drops cached /proc/<pid>/maps (call after a profile).
func (s *Symbolizer) Forget() {
	s.mu.Lock()
	s.maps = map[uint32][]mapping{}
	s.perfMaps = map[uint32][]sym{}
	s.mu.Unlock()
}

// nsPid returns the pid of a process inside its own pid namespace.
func (s *Symbolizer) nsPid(pid uint32) string {
	b, err := os.ReadFile(filepath.Join(s.procRoot, strconv.Itoa(int(pid)), "status"))
	if err != nil {
		return strconv.Itoa(int(pid))
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "NSpid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				return f[len(f)-1]
			}
		}
	}
	return strconv.Itoa(int(pid))
}

// perfMap loads /tmp/perf-<pid>.map as seen inside the process' mount
// namespace: "START SIZE name" lines written by JIT runtimes (JVM with
// -XX:+UnlockDiagnosticVMOptions -XX:+DumpPerfMapAtExit or perf-map-agent,
// node --perf-basic-prof, .NET DOTNET_PerfMapEnabled=1).
func (s *Symbolizer) perfMap(pid uint32) []sym {
	s.mu.Lock()
	m, ok := s.perfMaps[pid]
	s.mu.Unlock()
	if ok {
		return m
	}
	path := filepath.Join(s.procRoot, strconv.Itoa(int(pid)), "root", "tmp", "perf-"+s.nsPid(pid)+".map")
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			parts := strings.SplitN(sc.Text(), " ", 3)
			if len(parts) != 3 {
				continue
			}
			start, err1 := strconv.ParseUint(parts[0], 16, 64)
			size, err2 := strconv.ParseUint(parts[1], 16, 64)
			if err1 != nil || err2 != nil {
				continue
			}
			m = append(m, sym{start, parts[2]}, sym{start + size, ""})
		}
		f.Close()
		// by address; at equal addresses end markers sort first so that they
		// never hide a symbol starting where another one ends, and symbols
		// keep file order (a later entry for recompiled code wins)
		sort.SliceStable(m, func(i, j int) bool {
			if m[i].addr != m[j].addr {
				return m[i].addr < m[j].addr
			}
			return m[i].name == "" && m[j].name != ""
		})
	}
	s.mu.Lock()
	s.perfMaps[pid] = m
	s.mu.Unlock()
	return m
}

// jit resolves an address in JIT compiled code ("" if unknown).
func (s *Symbolizer) jit(pid uint32, addr uint64) string {
	m := s.perfMap(pid)
	i := sort.Search(len(m), func(i int) bool { return m[i].addr > addr }) - 1
	if i >= 0 && m[i].name != "" {
		return m[i].name
	}
	return ""
}

func (s *Symbolizer) procMaps(pid uint32) []mapping {
	s.mu.Lock()
	m, ok := s.maps[pid]
	s.mu.Unlock()
	if ok {
		return m
	}
	f, err := os.Open(filepath.Join(s.procRoot, strconv.Itoa(int(pid)), "maps"))
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 6 || !strings.Contains(fields[1], "x") {
				continue
			}
			r := strings.SplitN(fields[0], "-", 2)
			start, _ := strconv.ParseUint(r[0], 16, 64)
			end, _ := strconv.ParseUint(r[1], 16, 64)
			off, _ := strconv.ParseUint(fields[2], 16, 64)
			m = append(m, mapping{start, end, off, fields[5]})
		}
		f.Close()
	}
	s.mu.Lock()
	s.maps[pid] = m
	s.mu.Unlock()
	return m
}

// User resolves a user space address of pid.
func (s *Symbolizer) User(pid uint32, addr uint64) string {
	for _, m := range s.procMaps(pid) {
		if addr < m.start || addr >= m.end {
			continue
		}
		base := filepath.Base(m.path)
		if strings.HasPrefix(m.path, "[") {
			if name := s.jit(pid, addr); name != "" {
				return name
			}
			return m.path
		}
		// open through the process root so container files resolve
		path := filepath.Join(s.procRoot, strconv.Itoa(int(pid)), "root", m.path)
		ei := s.elf(path)
		if ei.err != nil {
			return fmt.Sprintf("%s+%#x", base, addr-m.start+m.offset)
		}
		fileOff := addr - m.start + m.offset
		vaddr := fileOff
		if ei.typ == elf.ET_EXEC {
			vaddr = addr
		} else {
			for _, p := range ei.loads {
				if fileOff >= p.Off && fileOff < p.Off+p.Filesz {
					vaddr = fileOff - p.Off + p.Vaddr
					break
				}
			}
		}
		if name := ei.lookup(vaddr); name != "" {
			return name
		}
		return fmt.Sprintf("%s+%#x", base, fileOff)
	}
	// anonymous executable memory: JIT compiled code
	if name := s.jit(pid, addr); name != "" {
		return name
	}
	return fmt.Sprintf("[unknown] %#x", addr)
}

func (s *Symbolizer) elf(path string) *elfInfo {
	key := path
	if fi, err := os.Stat(path); err == nil {
		key = fmt.Sprintf("%s:%d:%d", path, fi.Size(), fi.ModTime().UnixNano())
	}
	s.mu.Lock()
	ei, ok := s.elfs[key]
	s.mu.Unlock()
	if ok {
		return ei
	}
	ei = loadELF(path)
	s.mu.Lock()
	if len(s.elfs) > 512 {
		s.elfs = map[string]*elfInfo{}
	}
	s.elfs[key] = ei
	s.mu.Unlock()
	return ei
}

func loadELF(path string) *elfInfo {
	f, err := elf.Open(path)
	if err != nil {
		return &elfInfo{err: err}
	}
	defer f.Close()
	ei := &elfInfo{typ: f.Type}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			ei.loads = append(ei.loads, p.ProgHeader)
		}
	}
	add := func(ss []elf.Symbol) {
		for _, s := range ss {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Value != 0 {
				ei.syms = append(ei.syms, sym{s.Value, s.Name})
			}
		}
	}
	if ss, err := f.Symbols(); err == nil {
		add(ss)
	}
	if ss, err := f.DynamicSymbols(); err == nil {
		add(ss)
	}
	sort.Slice(ei.syms, func(i, j int) bool { return ei.syms[i].addr < ei.syms[j].addr })

	if len(ei.syms) == 0 {
		// stripped Go binary: use pclntab
		if pcln, text := f.Section(".gopclntab"), f.Section(".text"); pcln != nil && text != nil {
			if data, err := pcln.Data(); err == nil {
				if tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr)); err == nil {
					ei.gotab = tab
				}
			}
		}
	}
	return ei
}

func (ei *elfInfo) lookup(vaddr uint64) string {
	if len(ei.syms) > 0 {
		i := sort.Search(len(ei.syms), func(i int) bool { return ei.syms[i].addr > vaddr }) - 1
		if i >= 0 {
			return ei.syms[i].name
		}
	}
	if ei.gotab != nil {
		if fn := ei.gotab.PCToFunc(vaddr); fn != nil {
			return fn.Name
		}
	}
	return ""
}
