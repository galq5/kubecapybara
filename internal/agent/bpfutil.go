package agent

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// linker keeps track of attached links.
type linker struct {
	links []link.Link
}

func (l *linker) add(lk link.Link, err error, what string) error {
	if err != nil {
		return fmt.Errorf("attach %s: %w", what, err)
	}
	l.links = append(l.links, lk)
	return nil
}

func (l *linker) tracing(p *ebpf.Program, what string) error {
	lk, err := link.AttachTracing(link.TracingOptions{Program: p})
	return l.add(lk, err, what)
}

func (l *linker) kprobe(sym string, p *ebpf.Program) error {
	lk, err := link.Kprobe(sym, p, nil)
	return l.add(lk, err, "kprobe/"+sym)
}

func (l *linker) kretprobe(sym string, p *ebpf.Program) error {
	lk, err := link.Kretprobe(sym, p, nil)
	return l.add(lk, err, "kretprobe/"+sym)
}

func (l *linker) tracepoint(group, name string, p *ebpf.Program) error {
	lk, err := link.Tracepoint(group, name, p, nil)
	return l.add(lk, err, "tracepoint/"+group+"/"+name)
}

func (l *linker) close() {
	for _, lk := range l.links {
		_ = lk.Close()
	}
	l.links = nil
}

// drainMap reads and deletes every entry of a hash map.
func drainMap[K comparable, V any](m *ebpf.Map, fn func(K, *V)) {
	if m == nil {
		return
	}
	var (
		k    K
		v    V
		keys []K
	)
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, key := range keys {
		var val V
		if err := m.LookupAndDelete(&key, &val); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			if err := m.Lookup(&key, &val); err != nil {
				continue
			}
			_ = m.Delete(&key)
		}
		fn(key, &val)
	}
}

// castSample interprets a ring buffer sample as T without copying.
func castSample[T any](b []byte) (*T, bool) {
	var zero T
	if len(b) < int(unsafe.Sizeof(zero)) {
		return nil, false
	}
	return (*T)(unsafe.Pointer(&b[0])), true
}

