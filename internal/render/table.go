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

// Style controls colors and, for screens of a known size (the dashboard),
// the width reports are laid out for.
type Style struct {
	Color bool
	// Width is the number of columns available (0 = unlimited): tables
	// shrink their widest columns to fit and prose is wrapped.
	Width int
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

// dropColumn removes column i.
func (t *Table) dropColumn(i int) {
	cut := func(s []string) []string {
		if i >= len(s) {
			return s
		}
		return append(append([]string{}, s[:i]...), s[i+1:]...)
	}
	t.Headers = cut(t.Headers)
	for r := range t.Rows {
		t.Rows[r] = cut(t.Rows[r])
	}
	right := map[int]bool{}
	for c, v := range t.Right {
		switch {
		case c < i:
			right[c] = v
		case c > i:
			right[c-1] = v
		}
	}
	t.Right = right
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

// truncate shortens s to w cells by cutting out the middle: what tells two
// rows apart is usually at the end (the pod suffix of a replica, the last
// element of a path), what says which thing it is at the start.
func truncate(s string, w int) string {
	if visibleWidth(s) <= w {
		return s
	}
	if w <= 1 {
		return "…"
	}
	r := []rune(stripANSI(s))
	tail := min((w-1)/3, 12)
	head := w - 1 - tail
	i, used := 0, 0
	for i < len(r) && used+runewidth.RuneWidth(r[i]) <= head {
		used += runewidth.RuneWidth(r[i])
		i++
	}
	j, used := len(r), 0
	for j > i && used+runewidth.RuneWidth(r[j-1]) <= tail {
		used += runewidth.RuneWidth(r[j-1])
		j--
	}
	return string(r[:i]) + "…" + string(r[j:])
}

// Truncate shortens s to w cells, keeping its start and its end.
func Truncate(s string, w int) string { return truncate(s, w) }

// minShrink is the narrowest a column is made to fit a table on the screen.
const minShrink = 16

// fit narrows the widest columns until the table fits in total cells.
func fit(widths []int, headers []string, total int) {
	sum := 2 * (len(widths) - 1)
	for _, w := range widths {
		sum += w
	}
	for sum > total {
		widest := -1
		for i, w := range widths {
			if w > max(minShrink, visibleWidth(headers[i])) && (widest < 0 || w > widths[widest]) {
				widest = i
			}
		}
		if widest < 0 {
			return // nothing left to shrink: the rest is cut by the screen
		}
		widths[widest]--
		sum--
	}
}

// Wrap breaks text into lines of at most st.Width cells at word
// boundaries; continuation lines are indented by hang cells. The leading
// spaces of text are kept. Without a width the text is returned as is.
func Wrap(st Style, text string, hang int) string {
	if st.Width <= 0 || visibleWidth(text) <= st.Width {
		return text
	}
	return strings.Join(wrapWords(text, st.Width, hang), "\n")
}

// WrapPrefix prints prefix (aligned columns: its spacing is kept) followed
// by text, wrapped under itself to the right of the prefix.
func WrapPrefix(st Style, prefix, text string) string {
	pw := visibleWidth(prefix)
	if st.Width <= 0 || pw+visibleWidth(text) <= st.Width || st.Width-pw < 20 {
		return prefix + text
	}
	lines := wrapWords(text, st.Width-pw, 0)
	pad := strings.Repeat(" ", pw)
	for i := range lines {
		if i == 0 {
			lines[i] = prefix + lines[i]
		} else {
			lines[i] = pad + lines[i]
		}
	}
	return strings.Join(lines, "\n")
}

// wrapWords fills lines of width cells with the words of text; lines after
// the first are indented by hang. Colour codes travel with their word and
// count for nothing.
func wrapWords(text string, width, hang int) []string {
	if width-hang < 16 {
		hang = 0
	}
	lead := len(text) - len(strings.TrimLeft(text, " "))
	words := strings.Fields(text)
	var lines []string
	cur, curW := strings.Repeat(" ", lead), lead
	empty := true
	flush := func() {
		lines = append(lines, cur)
		cur, curW, empty = strings.Repeat(" ", hang), hang, true
	}
	for _, w := range words {
		ww := visibleWidth(w)
		if !empty && curW+1+ww > width {
			flush()
		}
		if !empty {
			cur += " "
			curW++
		}
		cur += w
		curW += ww
		empty = false
	}
	if !empty {
		lines = append(lines, cur)
	}
	return lines
}

// Note prints a dimmed explanatory line (a legend or a hint), wrapped.
func Note(w io.Writer, st Style, text string) {
	lead := len(text) - len(strings.TrimLeft(text, " "))
	for _, l := range strings.Split(Wrap(Style{Width: st.Width}, text, lead), "\n") {
		fmt.Fprintln(w, st.Dim(l))
	}
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
	if st.Width > 0 {
		fit(widths, t.Headers, st.Width)
		for _, row := range rows {
			for i := range row {
				row[i] = truncate(row[i], widths[i])
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
	// a screen that lets the user jump between sections wants to know them
	if m, ok := w.(interface{ MarkSection(string) }); ok {
		m.MarkSection(title)
	}
	// no blank line before the first thing in a buffer
	if b, ok := w.(interface{ Len() int }); !ok || b.Len() > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, st.Title(title))
}
