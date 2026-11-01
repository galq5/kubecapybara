// Package render produces human readable text reports from analysis views.
// The same functions back the CLI subcommands and the TUI panes.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

// Style controls colors.
type Style struct {
	Color bool
	Width int // 0 = unlimited
}

var (
	critStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	headStyle   = lipgloss.NewStyle().Bold(true).Underline(true)
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	accentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))
)

func (s Style) paint(st lipgloss.Style, text string) string {
	if !s.Color {
		return text
	}
	return st.Render(text)
}

// Crit, Warn, Info, OK, Dim, Title and Accent colour text when enabled.
func (s Style) Crit(t string) string   { return s.paint(critStyle, t) }
func (s Style) Warn(t string) string   { return s.paint(warnStyle, t) }
func (s Style) Info(t string) string   { return s.paint(infoStyle, t) }
func (s Style) OK(t string) string     { return s.paint(okStyle, t) }
func (s Style) Dim(t string) string    { return s.paint(dimStyle, t) }
func (s Style) Title(t string) string  { return s.paint(titleStyle, t) }
func (s Style) Accent(t string) string { return s.paint(accentStyle, t) }

// Table renders aligned columns. Cells may contain ANSI color codes.
type Table struct {
	Headers []string
	Rows    [][]string
	Right   map[int]bool // right-align columns
	MaxCol  int          // truncate cells wider than this (0 = 60)
}

// AddRow appends a row.
func (t *Table) AddRow(cells ...string) { t.Rows = append(t.Rows, cells) }

func visibleWidth(s string) int { return runewidth.StringWidth(stripANSI(s)) }

func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'):
			inEsc = false
		case !inEsc:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func truncate(s string, w int) string {
	if visibleWidth(s) <= w {
		return s
	}
	plain := stripANSI(s)
	return runewidth.Truncate(plain, w, "…")
}

// Render writes the table.
func (t *Table) Render(w io.Writer, st Style) {
	maxCol := t.MaxCol
	if maxCol == 0 {
		maxCol = 60
	}
	n := len(t.Headers)
	widths := make([]int, n)
	for i, h := range t.Headers {
		widths[i] = visibleWidth(h)
	}
	rows := make([][]string, len(t.Rows))
	for r, row := range t.Rows {
		rows[r] = make([]string, n)
		for i := 0; i < n && i < len(row); i++ {
			c := truncate(row[i], maxCol)
			rows[r][i] = c
			if vw := visibleWidth(c); vw > widths[i] {
				widths[i] = vw
			}
		}
	}
	pad := func(s string, i int) string {
		gap := widths[i] - visibleWidth(s)
		if gap <= 0 {
			return s
		}
		if t.Right[i] {
			return strings.Repeat(" ", gap) + s
		}
		return s + strings.Repeat(" ", gap)
	}
	var hdr []string
	for i, h := range t.Headers {
		hdr = append(hdr, pad(h, i))
	}
	line := strings.Join(hdr, "  ")
	if st.Color {
		fmt.Fprintln(w, headStyle.Render(strings.TrimRight(line, " ")))
	} else {
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	for _, row := range rows {
		var cells []string
		for i := range t.Headers {
			cells = append(cells, pad(row[i], i))
		}
		fmt.Fprintln(w, strings.TrimRight(strings.Join(cells, "  "), " "))
	}
}

// Bar renders a horizontal bar for a 0..1 share.
func Bar(share float64, width int) string {
	if share < 0 {
		share = 0
	}
	if share > 1 {
		share = 1
	}
	full := int(share*float64(width) + 0.5)
	return strings.Repeat("█", full) + strings.Repeat("░", width-full)
}

// Section prints a section header.
func Section(w io.Writer, st Style, title string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.Title(title))
}
