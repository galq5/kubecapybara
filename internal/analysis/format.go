package analysis

import (
	"fmt"
	"math"
	"time"
)

// Dur formats microseconds as a short human duration.
func Dur(us float64) string {
	switch {
	case us <= 0:
		return "-"
	case us < 1000:
		return fmt.Sprintf("%.0fµs", us)
	case us < 1e6:
		return fmt.Sprintf("%.1fms", us/1e3)
	case us < 60e6:
		return fmt.Sprintf("%.2fs", us/1e6)
	}
	return (time.Duration(us) * time.Microsecond).Round(time.Second).String()
}

// Bytes formats a byte count.
func Bytes(b float64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%.0fB", b)
	}
	exp := int(math.Log(b) / math.Log(unit))
	if exp > 6 {
		exp = 6
	}
	return fmt.Sprintf("%.1f%ciB", b/math.Pow(unit, float64(exp)), "KMGTPE"[exp-1])
}

// Rate formats a per-second value.
func Rate(v float64) string {
	switch {
	case v == 0:
		return "0"
	case v < 0.01:
		return "<0.01"
	case v < 10:
		return fmt.Sprintf("%.2f", v)
	case v < 1000:
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1fk", v/1000)
}

// Pct formats a ratio (0..1) as a percentage.
func Pct(r float64) string {
	switch {
	case r <= 0:
		return "0%"
	case r < 0.001:
		return "<0.1%"
	case r < 0.1:
		return fmt.Sprintf("%.1f%%", r*100)
	}
	return fmt.Sprintf("%.0f%%", r*100)
}

// Money formats US dollars.
func Money(v float64) string {
	switch {
	case v < 0.01:
		return "<$0.01"
	case v < 100:
		return fmt.Sprintf("$%.2f", v)
	}
	return fmt.Sprintf("$%.0f", v)
}

func ratio(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// Ago formats a time relative to now.
func Ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	switch {
	case d < 0:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
