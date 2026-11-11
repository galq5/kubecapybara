package agent

import (
	"bytes"
	"net/netip"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// ip16 converts a 16 byte (possibly v4-mapped) address to a string.
func ip16(b [16]uint8) string {
	a := netip.AddrFrom16(b).Unmap()
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// cutRunes returns the first n bytes of s, shortened so that no UTF-8
// sequence is cut in half.
func cutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// truncate shortens s to at most n bytes plus an ellipsis.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return cutRunes(s, n) + "…"
}

// cstr converts a NUL terminated C char array into a Go string.
func cstr[T int8 | uint8](b []T) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

// cbytes converts a C char array into bytes (not stopping at NUL).
func cbytes[T int8 | uint8](b []T) []byte {
	buf := make([]byte, len(b))
	for i, c := range b {
		buf[i] = byte(c)
	}
	return buf
}

// argsString converts a NUL separated argv buffer into a space separated string.
func argsString[T int8 | uint8](b []T) string {
	raw := cbytes(b)
	raw = bytes.TrimRight(raw, "\x00")
	return string(bytes.ReplaceAll(raw, []byte{0}, []byte{' '}))
}

// clock converts kernel monotonic timestamps (bpf_ktime_get_ns) to wall time.
type clock struct {
	offset time.Duration // wall - mono
}

func newClock() clock {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	mono := time.Duration(ts.Nano())
	return clock{offset: time.Duration(time.Now().UnixNano()) - mono}
}

func (c clock) wall(ktimeNs uint64) time.Time {
	return time.Unix(0, int64(time.Duration(ktimeNs)+c.offset))
}

func monoNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

var errnoNames = map[int32]string{}

func errnoName(e int32) string {
	if n, ok := errnoNames[e]; ok {
		return n
	}
	n := unix.ErrnoName(syscall.Errno(-e))
	if n == "" {
		n = syscall.Errno(-e).Error()
	}
	return n
}

var signalNames = map[int32]string{
	4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 15: "SIGTERM",
}

func signalName(s int32) string {
	if n, ok := signalNames[s]; ok {
		return n
	}
	n := unix.SignalName(syscall.Signal(s))
	if n == "" {
		return "SIG?"
	}
	return n
}
