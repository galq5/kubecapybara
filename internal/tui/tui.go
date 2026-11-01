// Package tui implements the interactive `kubectl capybara top` dashboard
// (Bubble Tea + Bubbles: table, viewport, textinput, help, key).
package tui

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/galq5/kubecapybara/internal/analysis"
	cmodel "github.com/galq5/kubecapybara/internal/model"
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

var tabs = []string{"Overview", "Network", "Pods", "Services", "DNS", "HTTP", "Nodes", "Events", "Security", "Cost"}

// TabIndex returns the index of a tab by name (-1 if unknown).
func TabIndex(name string) int {
	for i, t := range tabs {
		if strings.EqualFold(t, name) {
			return i
		}
	}
	return -1
}

// sort orders of the interactive tables
var (
	edgeSorts = []string{"traffic", "rtt", "connect", "errors", "retrans", "bytes", "conns"}
	podSorts  = []string{"cpu", "runq", "memory", "dns", "http", "name"}
)

// ---------------------------------------------------------------- keys

type keyMap struct {
	Next, Prev, Jump, Up, Down, Enter, Back, Filter, Sort, Refresh, Help, Quit key.Binding
}

func newKeys() keyMap {
	return keyMap{
		Next:    key.NewBinding(key.WithKeys("tab", "right", "l"), key.WithHelp("tab/→", "next tab")),
		Prev:    key.NewBinding(key.WithKeys("shift+tab", "left", "h"), key.WithHelp("⇧tab/←", "prev tab")),
		Jump:    key.NewBinding(key.WithKeys("1", "2", "3", "4", "5", "6", "7", "8", "9", "0"), key.WithHelp("1-0", "jump to tab")),
		Up:      key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:    key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Enter:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "details")),
		Back:    key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back / clear filter")),
		Filter:  key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Sort:    key.NewBinding(key.WithKeys("s", "S"), key.WithHelp("s/S", "sort")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		Help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Next, k.Jump, k.Enter, k.Filter, k.Sort, k.Refresh, k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Next, k.Prev, k.Jump}, {k.Up, k.Down, k.Enter, k.Back}, {k.Filter, k.Sort, k.Refresh}, {k.Help, k.Quit}}
}

// ---------------------------------------------------------------- model

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

	keys keyMap
	help help.Model

	tab       int
	vp        viewport.Model
	tbl       table.Model
	rowIDs    []string // item id per table row
	edges     map[string]*analysis.Edge
	ready     bool
	width     int
	height    int
	filter    textinput.Model
	filtering bool
	sortIdx   map[int]int // tab -> sort index
	detail    string      // pod entity id or edge key being inspected
	selected  map[int]string
}

func newModel(load Loader, opts Options) *model {
	ti := textinput.New()
	ti.Placeholder = "filter (pod, namespace, port, name...)"
	ti.Prompt = "/ "
	t := table.New(table.WithFocused(true))
	s := table.DefaultStyles()
	s.Header = s.Header.Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).BorderForeground(lipgloss.Color("8"))
	s.Selected = s.Selected.Foreground(lipgloss.Color("0")).Background(lipgloss.Color("14")).Bold(false)
	t.SetStyles(s)
	h := help.New()
	return &model{
		load: load, opts: opts, st: render.Style{Color: true}, filter: ti, loading: true,
		keys: newKeys(), help: h, tbl: t, sortIdx: map[int]int{}, selected: map[int]string{},
	}
}

// Run starts the dashboard and blocks until the user quits.
func Run(load Loader, opts Options) error {
	p := tea.NewProgram(newModel(load, opts), tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}

func (m *model) Init() tea.Cmd { return tea.Batch(m.fetch(), tick(m.opts.Interval)) }

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

func (m *model) tableTab() bool {
	return m.detail == "" && (tabs[m.tab] == "Network" || tabs[m.tab] == "Pods")
}

func (m *model) contentHeight() int {
	h := m.height - 3 // header, tabs, footer
	if m.help.ShowAll {
		h -= 4
	}
	if h < 3 {
		h = 3
	}
	return h
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.Width = msg.Width
		if !m.ready {
			m.vp = viewport.New(msg.Width, m.contentHeight())
			m.ready = true
		}
		m.resize()
		m.refresh(false)
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
		m.refresh(false)
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
			m.refresh(true)
			return m, tea.Batch(cmds...)
		}
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help):
			m.help.ShowAll = !m.help.ShowAll
			m.resize()
			m.refresh(false)
		case key.Matches(msg, m.keys.Next):
			m.switchTab((m.tab + 1) % len(tabs))
		case key.Matches(msg, m.keys.Prev):
			m.switchTab((m.tab + len(tabs) - 1) % len(tabs))
		case key.Matches(msg, m.keys.Jump):
			i := int(msg.String()[0] - '1')
			if msg.String() == "0" {
				i = 9
			}
			m.switchTab(i)
		case key.Matches(msg, m.keys.Filter):
			m.filtering = true
			m.filter.Focus()
		case key.Matches(msg, m.keys.Back):
			if m.detail != "" {
				m.detail = ""
			} else {
				m.filter.SetValue("")
			}
			m.refresh(true)
		case key.Matches(msg, m.keys.Sort):
			n := len(edgeSorts)
			if tabs[m.tab] == "Pods" {
				n = len(podSorts)
			}
			step := 1
			if msg.String() == "S" {
				step = n - 1
			}
			m.sortIdx[m.tab] = (m.sortIdx[m.tab] + step) % n
			m.refresh(false)
		case key.Matches(msg, m.keys.Refresh):
			if !m.loading {
				m.loading = true
				cmds = append(cmds, m.fetch())
			}
		case key.Matches(msg, m.keys.Enter) && m.tableTab():
			if c := m.tbl.Cursor(); c >= 0 && c < len(m.rowIDs) {
				m.detail = m.rowIDs[c]
				m.refresh(true)
			}
		default:
			if m.tableTab() {
				var cmd tea.Cmd
				m.tbl, cmd = m.tbl.Update(msg)
				if c := m.tbl.Cursor(); c >= 0 && c < len(m.rowIDs) {
					m.selected[m.tab] = m.rowIDs[c]
				}
				cmds = append(cmds, cmd)
			} else {
				var cmd tea.Cmd
				m.vp, cmd = m.vp.Update(msg)
				cmds = append(cmds, cmd)
			}
		}
	case tea.MouseMsg:
		if m.tableTab() {
			switch msg.Button {
			case tea.MouseButtonWheelUp:
				m.tbl.MoveUp(3)
			case tea.MouseButtonWheelDown:
				m.tbl.MoveDown(3)
			}
		} else {
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(msg)
			cmds = append(cmds, cmd)
		}
	}
	return m, tea.Batch(cmds...)
}

func (m *model) resize() {
	h := m.contentHeight()
	m.vp.Width, m.vp.Height = m.width, h
	m.tbl.SetWidth(m.width)
	m.tbl.SetHeight(h - 1) // one line for the sort hint
}

func (m *model) switchTab(i int) {
	if i < 0 || i >= len(tabs) {
		return
	}
	m.tab = i
	m.detail = ""
	m.refresh(true)
}

// refresh rebuilds the content of the current tab.
func (m *model) refresh(resetScroll bool) {
	if !m.ready {
		return
	}
	if m.res != nil && m.tableTab() {
		m.buildTable()
		return
	}
	var b bytes.Buffer
	switch {
	case m.res == nil && m.err != nil:
		fmt.Fprintf(&b, "error: %v\n", m.err)
	case m.res == nil:
		b.WriteString("loading data from agents…\n")
	default:
		m.renderText(&b)
	}
	m.vp.SetContent(b.String())
	if resetScroll {
		m.vp.GotoTop()
	}
}

func (m *model) filt() render.Filter {
	return render.Filter{Text: m.filter.Value(), Namespace: m.opts.Namespace}
}

// ---------------------------------------------------------------- tables

func edgeKey(e *analysis.Edge) string {
	return e.Client.ID + "|" + e.Server.ID + "|" + strconv.Itoa(int(e.Port))
}

func (m *model) buildTable() {
	v := m.res.View
	var cols []table.Column
	var rows []table.Row
	m.rowIDs = m.rowIDs[:0]
	switch tabs[m.tab] {
	case "Network":
		m.edges = map[string]*analysis.Edge{}
		edges := render.FilterEdges(v, m.filt())
		render.SortEdges(edges, edgeSorts[m.sortIdx[m.tab]])
		cols = fitColumns(m.width, []colSpec{
			{"CLIENT", 30, true}, {"SERVER", 30, true}, {"PORT", 5, false}, {"RTT p50", 8, false}, {"RTT p99", 8, false},
			{"CONN p99", 8, false}, {"CONN/s", 7, false}, {"TX/s", 9, false}, {"RX/s", 9, false}, {"RETR/s", 7, false},
			{"REFUSED", 7, false}, {"TIMEOUT", 7, false}, {"SEEN", 6, false},
		})
		for _, e := range edges {
			s := e.Stats
			server := e.Server.Display()
			if e.CrossZone {
				server += " ⇄"
			}
			k := edgeKey(e)
			m.edges[k] = e
			m.rowIDs = append(m.rowIDs, k)
			rows = append(rows, table.Row{
				e.Client.Display(), server, strconv.Itoa(int(e.Port)),
				analysis.Dur(s.RTT.P50()), analysis.Dur(s.RTT.P99()), analysis.Dur(s.Connect.P99()),
				analysis.Rate(v.PerSec(s.Connects)), analysis.Bytes(v.PerSec(s.BytesTx)), analysis.Bytes(v.PerSec(s.BytesRx)),
				analysis.Rate(v.PerSec(s.Retrans)), warnNum(s.Refused), warnNum(s.Timeouts), e.Side,
			})
		}
	case "Pods":
		pods := render.PodRows(v, m.filt())
		sortPods(v, pods, podSorts[m.sortIdx[m.tab]])
		oom := map[string]time.Duration{}
		for _, r := range analysis.OOMRisks(v) {
			oom[r.Endpoint.ID] = r.ETA
		}
		cols = fitColumns(m.width, []colSpec{
			{"POD", 40, true}, {"NODE", 14, true}, {"CPU", 6, false}, {"CPU TREND", 12, false}, {"RUNQ p99", 8, false},
			{"WAIT CPU", 8, false}, {"MEM", 9, false}, {"MEM%", 5, false}, {"OOM IN", 7, false}, {"THROTTLE", 8, false},
			{"DNS err", 7, false}, {"HTTP rps", 8, false}, {"5xx", 5, false},
		})
		for _, e := range pods {
			s := e.Stats
			cpu, runq, wait := "-", "-", "-"
			if sc := s.Sched; sc != nil {
				cpu = fmt.Sprintf("%.3f", v.CoresUsed(sc))
				runq = analysis.Dur(sc.RunQ.P99())
				q := float64(sc.OffNs[cmodel.StateRunQ])
				if q+float64(sc.OnCPUNs) > 0 {
					wait = analysis.Pct(q / (q + float64(sc.OnCPUNs)))
				}
			}
			trend, _ := render.SeriesSparks(v, e.ID, 12)
			mem, memPct, thr := "-", "-", "-"
			if r := s.Res; r != nil {
				if r.MemCurrent > 0 {
					mem = analysis.Bytes(float64(r.MemCurrent))
				}
				if r.MemMax > 0 {
					memPct = analysis.Pct(float64(r.MemCurrent) / float64(r.MemMax))
				}
				if r.Periods > 0 {
					thr = analysis.Pct(float64(r.Throttled) / float64(r.Periods))
				}
			}
			oomIn := "-"
			if eta, ok := oom[e.ID]; ok {
				oomIn = eta.Round(time.Minute).String()
			}
			dnsErr := "-"
			if d := s.DNS; d != nil {
				dnsErr = warnNum(d.RCodes["SERVFAIL"] + d.RCodes["REFUSED"] + d.Timeouts)
			}
			rps, e5 := "-", "-"
			var req, errs uint64
			for _, ep := range s.HTTP {
				if ep.Role == "server" {
					req += ep.Count
					errs += ep.Errors()
				}
			}
			if req > 0 {
				rps, e5 = analysis.Rate(v.PerSec(req)), analysis.Pct(float64(errs)/float64(req))
			}
			m.rowIDs = append(m.rowIDs, e.ID)
			rows = append(rows, table.Row{e.Endpoint.Display(), e.Endpoint.Node, cpu, trend, runq, wait, mem, memPct, oomIn, thr, dnsErr, rps, e5})
		}
	}
	m.tbl.SetRows(nil) // columns and rows must stay consistent
	m.tbl.SetColumns(cols)
	m.tbl.SetRows(rows)
	// keep the selection on the same item across refreshes
	cur := 0
	if id, ok := m.selected[m.tab]; ok {
		for i, rid := range m.rowIDs {
			if rid == id {
				cur = i
				break
			}
		}
	}
	m.tbl.SetCursor(cur)
}

func warnNum(n uint64) string {
	if n == 0 {
		return "0"
	}
	return strconv.FormatUint(n, 10) + " !"
}

type colSpec struct {
	title string
	width int
	flex  bool // grows/shrinks with the terminal
}

// fitColumns gives fixed columns their width and spreads the rest over the
// flexible ones.
func fitColumns(total int, specs []colSpec) []table.Column {
	fixed, flexW, flexN := 0, 0, 0
	for _, s := range specs {
		w := max(s.width, len([]rune(s.title)))
		if s.flex {
			flexW += w
			flexN++
		} else {
			fixed += w
		}
	}
	avail := total - fixed - 2*len(specs) // cell padding
	cols := make([]table.Column, len(specs))
	for i, s := range specs {
		w := max(s.width, len([]rune(s.title)))
		if s.flex && flexW > 0 {
			w = max(12, avail*w/flexW)
		}
		cols[i] = table.Column{Title: s.title, Width: w}
	}
	return cols
}

func sortPods(v *analysis.View, pods []*analysis.EntityView, by string) {
	key := func(e *analysis.EntityView) float64 {
		s := e.Stats
		switch by {
		case "runq":
			if s.Sched != nil {
				return s.Sched.RunQ.P99()
			}
		case "memory":
			if s.Res != nil {
				return float64(s.Res.MemCurrent)
			}
		case "dns":
			if s.DNS != nil {
				return float64(s.DNS.Queries)
			}
		case "http":
			var n uint64
			for _, ep := range s.HTTP {
				n += ep.Count
			}
			return float64(n)
		case "name":
			return 0
		default:
			if s.Sched != nil {
				return float64(s.Sched.OnCPUNs)
			}
		}
		return 0
	}
	sort.SliceStable(pods, func(i, j int) bool {
		if by == "name" {
			return pods[i].Endpoint.Display() < pods[j].Endpoint.Display()
		}
		return key(pods[i]) > key(pods[j])
	})
}

// ---------------------------------------------------------------- text tabs

func (m *model) renderText(b *bytes.Buffer) {
	v := m.res.View
	f := m.filt()
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
		if e := m.edges[m.detail]; e != nil {
			render.EdgeDetail(b, st, v, e)
		}
		fmt.Fprintln(b, st.Dim("\nesc: back to the list"))
	case "Pods":
		render.Pod(b, st, v, m.detail)
		fmt.Fprintln(b, st.Dim("\nesc: back to the list"))
	case "Services":
		render.Services(b, st, v, f)
	case "DNS":
		render.DNS(b, st, v, f)
	case "HTTP":
		render.HTTP(b, st, v, f)
	case "Nodes":
		render.Nodes(b, st, v, f)
		render.Section(b, st, "Memory trending to OOM")
		render.OOMRisks(b, st, v)
	case "Events":
		render.Events(b, st, v, f, nil, 500)
	case "Security":
		render.Security(b, st, v, f)
	case "Cost":
		render.Cost(b, st, v)
	}
}

// ---------------------------------------------------------------- view

var (
	tabActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("14")).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Padding(0, 1)
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	critBadge   = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("9")).Padding(0, 1)
	warnBadge   = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("11")).Padding(0, 1)
	hintStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
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
		head.WriteString(statusStyle.Render(fmt.Sprintf(" window %s · %d nodes · %d flows · updated %s · %s",
			m.opts.Window, len(v.Nodes), len(v.Edges), m.updated.Format("15:04:05"), m.opts.Source)))
	}
	if m.loading {
		head.WriteString(statusStyle.Render(" ⟳"))
	}
	if m.err != nil {
		head.WriteString(" " + critBadge.Render("error: "+truncate(m.err.Error(), 60)))
	}

	var tb []string
	for i, t := range tabs {
		label := fmt.Sprintf("%d %s", (i+1)%10, t)
		if i == m.tab {
			tb = append(tb, tabActive.Render(label))
		} else {
			tb = append(tb, tabInactive.Render(label))
		}
	}

	var body string
	if m.res != nil && m.tableTab() {
		sorts := edgeSorts
		if tabs[m.tab] == "Pods" {
			sorts = podSorts
		}
		hint := hintStyle.Render(fmt.Sprintf("sort: %s (s/S) · %d rows · enter: details · ⇄ = cross-zone · ! = errors", sorts[m.sortIdx[m.tab]], len(m.rowIDs)))
		body = hint + "\n" + m.tbl.View()
	} else {
		body = m.vp.View()
	}

	footer := m.help.View(m.keys)
	if m.filtering || m.filter.Value() != "" {
		footer = m.filter.View()
	}
	return head.String() + "\n" + strings.Join(tb, "") + "\n" + body + "\n" + footer
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Frame renders a single dashboard frame without a terminal (used for
// screenshots and tests). detail optionally opens a pod entity (Pods tab)
// or an edge key (Network tab).
func Frame(res *Result, opts Options, width, height, tab int, detail string) string {
	m := newModel(nil, opts)
	m.res, m.updated, m.loading = res, time.Now(), false
	m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m.tab = tab
	m.detail = detail
	if detail != "" && tabs[tab] == "Network" {
		m.buildTableFor("Network")
	}
	m.refresh(true)
	return m.View()
}

// buildTableFor populates edge lookups for a tab without showing it.
func (m *model) buildTableFor(tab string) {
	saved, savedDetail := m.tab, m.detail
	m.tab, m.detail = TabIndex(tab), ""
	m.buildTable()
	m.tab, m.detail = saved, savedDetail
}

// EdgeKey exposes the detail key of an edge (for screenshots).
func EdgeKey(e *analysis.Edge) string { return edgeKey(e) }
