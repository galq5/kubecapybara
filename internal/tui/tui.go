// Package tui implements the interactive `kubectl capybara top` dashboard.
package tui

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/render"
)

// Result is one refresh of data.
type Result struct {
	View     *analysis.View
	Base     *analysis.View
	Findings []analysis.Finding
	Warnings []string
}

// Loader fetches fresh data.
type Loader func(ctx context.Context) (*Result, error)

// Options configure the dashboard.
type Options struct {
	Source    string
	Namespace string
	Interval  time.Duration
	Window    time.Duration
}

var tabs = []string{"Overview", "Network", "Pods", "DNS", "HTTP", "Nodes", "Events", "Security", "Cost"}

var edgeSorts = []string{"traffic", "rtt", "connect", "errors", "retrans", "bytes", "conns"}

type loadedMsg struct {
	res *Result
	err error
}

type tickMsg time.Time

type model struct {
	load    Loader
	opts    Options
	st      render.Style
	res     *Result
	err     error
	loading bool
	updated time.Time

	tab       int
	vp        viewport.Model
	ready     bool
	width     int
	height    int
	filter    textinput.Model
	filtering bool
	sortIdx   int
	podCursor int
	podIDs    []string
	podDetail string
	showHelp  bool
}

// Run starts the dashboard and blocks until the user quits.
func Run(load Loader, opts Options) error {
	ti := textinput.New()
	ti.Placeholder = "filter (pod, namespace, port, name...)"
	ti.Prompt = "/ "
	m := &model{load: load, opts: opts, st: render.Style{Color: true}, filter: ti, loading: true}
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.fetch(), tick(m.opts.Interval))
}

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *model) fetch() tea.Cmd {
	load := m.load
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := load(ctx)
		return loadedMsg{res, err}
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		h := m.height - 4
		if h < 3 {
			h = 3
		}
		if !m.ready {
			m.vp = viewport.New(msg.Width, h)
			m.ready = true
		} else {
			m.vp.Width, m.vp.Height = msg.Width, h
		}
		m.refreshContent(false)
	case tickMsg:
		cmds = append(cmds, tick(m.opts.Interval))
		if !m.loading {
			m.loading = true
			cmds = append(cmds, m.fetch())
		}
	case loadedMsg:
		m.loading = false
		m.err = msg.err
		if msg.err == nil {
			m.res = msg.res
			m.updated = time.Now()
		}
		m.refreshContent(false)
	case tea.KeyMsg:
		if m.filtering {
			switch msg.String() {
			case "enter":
				m.filtering = false
				m.filter.Blur()
			case "esc":
				m.filtering = false
				m.filter.SetValue("")
				m.filter.Blur()
			default:
				var cmd tea.Cmd
				m.filter, cmd = m.filter.Update(msg)
				cmds = append(cmds, cmd)
			}
			m.refreshContent(true)
			return m, tea.Batch(cmds...)
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.showHelp = !m.showHelp
			m.refreshContent(true)
		case "tab", "right", "l":
			m.switchTab((m.tab + 1) % len(tabs))
		case "shift+tab", "left", "h":
			m.switchTab((m.tab + len(tabs) - 1) % len(tabs))
		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			m.switchTab(int(msg.String()[0] - '1'))
		case "/":
			m.filtering = true
			m.filter.Focus()
		case "esc":
			if m.podDetail != "" {
				m.podDetail = ""
			} else {
				m.filter.SetValue("")
			}
			m.refreshContent(true)
		case "s":
			m.sortIdx = (m.sortIdx + 1) % len(edgeSorts)
			m.refreshContent(true)
		case "r":
			if !m.loading {
				m.loading = true
				cmds = append(cmds, m.fetch())
			}
		case "j", "down":
			if tabs[m.tab] == "Pods" && m.podDetail == "" {
				if m.podCursor < len(m.podIDs)-1 {
					m.podCursor++
				}
				m.refreshContent(false)
				m.ensureCursorVisible()
			} else {
				m.vp.ScrollDown(1)
			}
		case "k", "up":
			if tabs[m.tab] == "Pods" && m.podDetail == "" {
				if m.podCursor > 0 {
					m.podCursor--
				}
				m.refreshContent(false)
				m.ensureCursorVisible()
			} else {
				m.vp.ScrollUp(1)
			}
		case "enter":
			if tabs[m.tab] == "Pods" && m.podDetail == "" && m.podCursor < len(m.podIDs) {
				m.podDetail = m.podIDs[m.podCursor]
				m.refreshContent(true)
			}
		default:
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(msg)
			cmds = append(cmds, cmd)
		}
	default:
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

func (m *model) switchTab(i int) {
	if i < 0 || i >= len(tabs) {
		return
	}
	m.tab = i
	m.podDetail = ""
	m.refreshContent(true)
}

func (m *model) ensureCursorVisible() {
	line := m.podCursor + 1
	if line < m.vp.YOffset {
		m.vp.SetYOffset(line)
	} else if line >= m.vp.YOffset+m.vp.Height {
		m.vp.SetYOffset(line - m.vp.Height + 1)
	}
}

func (m *model) refreshContent(resetScroll bool) {
	if !m.ready {
		return
	}
	var b bytes.Buffer
	if m.showHelp {
		b.WriteString(helpText)
	} else if m.res == nil {
		if m.err != nil {
			fmt.Fprintf(&b, "error: %v\n", m.err)
		} else {
			b.WriteString("loading data from agents…\n")
		}
	} else {
		m.renderTab(&b)
	}
	m.vp.SetContent(b.String())
	if resetScroll {
		m.vp.GotoTop()
	}
}

func (m *model) renderTab(b *bytes.Buffer) {
	v := m.res.View
	f := render.Filter{Text: m.filter.Value(), Namespace: m.opts.Namespace}
	st := m.st
	switch tabs[m.tab] {
	case "Overview":
		for _, w := range m.res.Warnings {
			fmt.Fprintln(b, st.Warn("! "+w))
		}
		render.Doctor(b, st, m.res.Findings, f)
		render.Section(b, st, "Slowest paths (RTT p99)")
		render.Edges(b, st, v, f, "rtt", 8)
	case "Network":
		fmt.Fprintf(b, "%s\n", st.Dim("sort: "+edgeSorts[m.sortIdx]+" (press s)   ⇄ = cross-zone   SEEN = which socket side was observed"))
		render.Edges(b, st, v, f, edgeSorts[m.sortIdx], 0)
	case "Pods":
		if m.podDetail != "" {
			render.Pod(b, st, v, m.podDetail)
			fmt.Fprintln(b, st.Dim("\nesc: back to list"))
			return
		}
		rows := render.PodRows(v, f)
		m.podIDs = m.podIDs[:0]
		for _, r := range rows {
			m.podIDs = append(m.podIDs, r.ID)
		}
		if m.podCursor >= len(m.podIDs) {
			m.podCursor = max(0, len(m.podIDs)-1)
		}
		var tb bytes.Buffer
		render.Pods(&tb, st, v, f)
		lines := strings.Split(strings.TrimRight(tb.String(), "\n"), "\n")
		sel := lipgloss.NewStyle().Reverse(true)
		for i, l := range lines {
			if i == m.podCursor+1 && len(m.podIDs) > 0 {
				fmt.Fprintln(b, sel.Render(stripForSelect(l)))
			} else {
				fmt.Fprintln(b, l)
			}
		}
		if len(m.podIDs) == 0 {
			fmt.Fprintln(b, st.Dim("no pod activity in this window"))
		} else {
			fmt.Fprintln(b, st.Dim("\n↑/↓ select, enter: details (time breakdown, dependencies, DNS, HTTP, events)"))
		}
	case "DNS":
		render.DNS(b, st, v, f)
	case "HTTP":
		render.HTTP(b, st, v, f)
	case "Nodes":
		render.Nodes(b, st, v, f)
	case "Events":
		render.Events(b, st, v, f, nil, 500)
	case "Security":
		render.Security(b, st, v, f)
	case "Cost":
		render.Cost(b, st, v)
	}
}

func stripForSelect(s string) string {
	var out strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			in = true
		case in && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'):
			in = false
		case !in:
			out.WriteRune(r)
		}
	}
	return out.String()
}

var (
	tabActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("14")).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Padding(0, 1)
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	critBadge   = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("9")).Padding(0, 1)
	warnBadge   = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("11")).Padding(0, 1)
)

func (m *model) View() string {
	if !m.ready {
		return "starting…"
	}
	var head strings.Builder
	head.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("13")).Render("🦫 kubecapybara "))
	if m.res != nil {
		var crit, warn int
		for _, f := range m.res.Findings {
			switch f.Severity {
			case analysis.SevCrit:
				crit++
			case analysis.SevWarn:
				warn++
			}
		}
		if crit > 0 {
			head.WriteString(critBadge.Render(fmt.Sprintf("%d crit", crit)) + " ")
		}
		if warn > 0 {
			head.WriteString(warnBadge.Render(fmt.Sprintf("%d warn", warn)) + " ")
		}
		v := m.res.View
		head.WriteString(statusStyle.Render(fmt.Sprintf(" window %s · %d nodes · %d flows · updated %s",
			m.opts.Window, len(v.Nodes), len(v.Edges), m.updated.Format("15:04:05"))))
	}
	if m.loading {
		head.WriteString(statusStyle.Render(" ⟳"))
	}
	if m.err != nil {
		head.WriteString(" " + critBadge.Render("error: "+truncate(m.err.Error(), 60)))
	}

	var tb []string
	for i, t := range tabs {
		label := fmt.Sprintf("%d %s", i+1, t)
		if i == m.tab {
			tb = append(tb, tabActive.Render(label))
		} else {
			tb = append(tb, tabInactive.Render(label))
		}
	}
	footer := statusStyle.Render(fmt.Sprintf("tab/1-9 switch · / filter · s sort · r refresh · ? help · q quit   %s", m.opts.Source))
	if m.filtering || m.filter.Value() != "" {
		footer = m.filter.View()
	}
	return head.String() + "\n" + strings.Join(tb, "") + "\n" + m.vp.View() + "\n" + footer
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

const helpText = `kubecapybara - keys

  tab / shift+tab / ← →   switch tabs (or press 1-9)
  ↑ ↓ / pgup pgdn / mouse scroll
  /                       filter rows (pod, namespace, port, DNS name...)
  esc                     clear filter / leave pod details
  enter                   (Pods) open pod details
  s                       (Network) cycle sort: traffic, rtt, connect, errors, retrans, bytes, conns
  r                       refresh now
  ?                       toggle this help
  q                       quit

Tabs

  Overview  doctor findings (what is wrong right now, with hints) + slowest paths
  Network   pod-to-pod TCP: RTT, connect latency, throughput, retransmits, refused, timeouts
  Pods      where each pod's threads spend time: CPU, waiting for CPU, disk, network, locks
  DNS       latency, failures, ndots waste per client; per-replica DNS server latency
  HTTP      HTTP/1.x rate, errors, latency per route (agent flag --l7)
  Nodes     noisy neighbours: who uses / steals CPU, disk and network; conntrack; drops
  Events    flight recorder: execs, exits, signals, OOMs, DNS failures, connect failures
  Security  interactive exec sessions, shells spawned by apps, undeclared ports, internet egress
  Cost      cross-zone traffic and estimated monthly transfer cost
`

// Frame renders a single dashboard frame without a terminal (used for
// screenshots and tests). tab is the tab index; podDetail optionally opens
// the details of a pod entity on the Pods tab.
func Frame(res *Result, opts Options, width, height, tab int, podDetail string) string {
	ti := textinput.New()
	m := &model{opts: opts, st: render.Style{Color: true}, filter: ti, res: res, updated: time.Now()}
	m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m.tab = tab
	m.podDetail = podDetail
	m.refreshContent(true)
	return m.View()
}
