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
	// Problems are the findings grouped by what they are about (see
	// analysis.Triage).
	Problems []analysis.Problem
	Warnings []string
	SLOs     []analysis.SLOStatus
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

// Tab names. The first ten are always shown and reached with 1-9 and 0;
// VoIP only appears when SIP or RTP traffic was observed (key v).
const (
	tabOverview = "Overview"
	tabNetwork  = "Network"
	tabPods     = "Pods"
	tabServices = "Services"
	tabDNS      = "DNS"
	tabApps     = "Apps"
	tabNodes    = "Nodes"
	tabEvents   = "Events"
	tabSecurity = "Security"
	tabCost     = "Cost"
	tabVoIP     = "VoIP"
)

var tabs = []string{tabOverview, tabNetwork, tabPods, tabServices, tabDNS, tabApps, tabNodes, tabEvents, tabSecurity, tabCost, tabVoIP}

// shorter labels for terminals too narrow for the full tab bar
var shortTabs = map[string]string{
	tabOverview: "Over", tabNetwork: "Net", tabPods: "Pods", tabServices: "Svc", tabDNS: "DNS", tabApps: "Apps",
	tabNodes: "Node", tabEvents: "Evts", tabSecurity: "Sec", tabCost: "Cost", tabVoIP: "VoIP",
}

// TabIndex returns the index of a tab by name (-1 if unknown). "HTTP" is
// accepted for the Apps tab, which holds HTTP routes, database statements
// and slow files.
func TabIndex(name string) int {
	if strings.EqualFold(name, "HTTP") {
		name = tabApps
	}
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
	podSorts  = []string{"cpu", "runq", "memory", "oom", "dns", "http", "name"}
)

// nodeDetails is how many nodes get a workload table on the Nodes tab
// without a filter.
const nodeDetails = 3

// ---------------------------------------------------------------- keys

type keyMap struct {
	Next, Prev, Jump, VoIP, Up, Down, Enter, Back, Filter, Sort, Hosts, Left, Right, PrevSect, NextSect, Refresh, Help, Quit key.Binding
}

func newKeys() keyMap {
	return keyMap{
		Next:   key.NewBinding(key.WithKeys("tab", "right", "l"), key.WithHelp("tab/→", "next tab")),
		Prev:   key.NewBinding(key.WithKeys("shift+tab", "left", "h"), key.WithHelp("⇧tab/←", "prev tab")),
		Jump:   key.NewBinding(key.WithKeys("1", "2", "3", "4", "5", "6", "7", "8", "9", "0"), key.WithHelp("1-0", "jump to tab")),
		VoIP:   key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "VoIP tab")),
		Up:     key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:   key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Enter:  key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "details")),
		Back:   key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back / clear filter")),
		Filter: key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Sort:   key.NewBinding(key.WithKeys("s", "S"), key.WithHelp("s/S", "sort")),
		Hosts:  key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "host processes")),
		Left:   key.NewBinding(key.WithKeys("<", ","), key.WithHelp("</>", "scroll sideways")),
		Right:  key.NewBinding(key.WithKeys(">", ".")),
		// sections of a long tab (Services: balance, outliers, pools...)
		PrevSect: key.NewBinding(key.WithKeys("["), key.WithHelp("[/]", "prev/next section")),
		NextSect: key.NewBinding(key.WithKeys("]")),
		Refresh:  key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

// ShortHelp lists the keys that do something on the current tab (bindings
// that do not apply are disabled and left out by the help bubble).
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Next, k.Jump, k.Enter, k.Filter, k.Sort, k.Hosts, k.PrevSect, k.Left, k.Refresh, k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Next, k.Prev, k.Jump, k.VoIP}, {k.Up, k.Down, k.Enter, k.Back}, {k.Filter, k.Sort, k.Hosts, k.PrevSect, k.Left}, {k.Refresh, k.Help, k.Quit}}
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

	tab       string
	vp        viewport.Model
	tbl       table.Model
	rowIDs    []string // item id per table row
	ready     bool
	width     int
	height    int
	filter    textinput.Model
	filtering bool
	sortIdx   map[string]int // tab -> sort index
	detail    string         // pod entity id or edge key being inspected
	back      string         // tab to return to when the detail is closed
	selected  map[string]string
	showHosts bool // Pods tab: include processes outside pods
	voip      bool // the data has SIP or RTP traffic

	backDetail string // detail to restore with it

	// Overview: the problems shown, the selected one and where each starts
	problems   []analysis.Problem
	probCursor int
	probKey    string
	probLines  [][2]int // first line and line count of each problem

	sections []section // of the text on screen, for [ and ]
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
		load: load, opts: opts, st: render.Style{Color: true}, filter: ti, loading: true, tab: tabOverview,
		keys: newKeys(), help: h, tbl: t, sortIdx: map[string]int{}, selected: map[string]string{},
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

// setResult installs fresh data.
func (m *model) setResult(res *Result) {
	m.res, m.updated = res, time.Now()
	if res.Problems == nil && len(res.Findings) > 0 {
		res.Problems = analysis.Triage(res.View, res.Findings, res.Base, nil)
	}
	m.voip = false
	for _, e := range res.View.Entities {
		if e.Stats.SIP != nil || (e.Stats.RTP != nil && e.Stats.RTP.PacketsIn+e.Stats.RTP.PacketsOut > 0) {
			m.voip = true
			break
		}
	}
	if m.tab == tabVoIP && !m.voip {
		m.tab = tabOverview
	}
}

// hasVoIP reports whether any entity has SIP or RTP traffic.
func (m *model) hasVoIP() bool { return m.res != nil && m.voip }

// visible returns the tabs currently shown.
func (m *model) visible() []string {
	if m.hasVoIP() || m.tab == tabVoIP {
		return tabs
	}
	return tabs[:len(tabs)-1]
}

func (m *model) tableTab() bool {
	return m.detail == "" && (m.tab == tabNetwork || m.tab == tabPods)
}

// problemList reports whether the selectable list of problems is shown.
func (m *model) problemList() bool {
	return m.detail == "" && m.tab == tabOverview && m.res != nil
}

// problemDetail returns the problem opened on the Overview tab, if any.
func (m *model) problemDetail() *analysis.Problem {
	key, ok := strings.CutPrefix(m.detail, problemPrefix)
	if !ok || m.tab != tabOverview || m.res == nil {
		return nil
	}
	for i := range m.res.Problems {
		if m.res.Problems[i].Key == key {
			return &m.res.Problems[i]
		}
	}
	return nil
}

// problemPod returns the pod to open from a problem: the one its evidence
// names most.
func problemPod(p *analysis.Problem) string {
	if p == nil || len(p.Pods) == 0 {
		return ""
	}
	return p.Pods[0]
}

const problemPrefix = "problem:"

// syncKeys enables the bindings that apply to what is on screen, so the
// footer only advertises keys that do something.
func (m *model) syncKeys() {
	m.keys.Sort.SetEnabled(m.tableTab())
	m.keys.Hosts.SetEnabled(m.tableTab() && m.tab == tabPods)
	m.keys.Enter.SetEnabled(m.tableTab() || (m.problemList() && len(m.problems) > 0) || problemPod(m.problemDetail()) != "")
	m.keys.Left.SetEnabled(!m.tableTab())
	m.keys.Right.SetEnabled(!m.tableTab())
	m.keys.PrevSect.SetEnabled(!m.tableTab() && len(m.sections) > 1)
	m.keys.NextSect.SetEnabled(!m.tableTab() && len(m.sections) > 1)
	m.keys.VoIP.SetEnabled(m.hasVoIP())
}

func (m *model) contentHeight() int {
	h := m.height - 3 // header, tabs, footer
	if m.help.ShowAll {
		// the full help is as tall as its longest column of enabled keys
		h -= lipgloss.Height(m.help.View(m.keys)) - 1 + len(m.glossary())
	}
	if h < 3 {
		h = 3
	}
	return h
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	m.syncKeys()
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.Width = msg.Width
		if !m.ready {
			m.vp = viewport.New(msg.Width, m.contentHeight())
			m.vp.SetHorizontalStep(0) // sideways scrolling is on < and >: ←/→ switch tabs
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
		if msg.err == nil && msg.res != nil {
			m.setResult(msg.res)
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
			m.step(1)
		case key.Matches(msg, m.keys.Prev):
			m.step(-1)
		case key.Matches(msg, m.keys.Jump):
			i := int(msg.String()[0] - '1')
			if msg.String() == "0" {
				i = 9
			}
			if vis := m.visible(); i >= 0 && i < len(vis) {
				m.switchTab(vis[i])
			}
		case key.Matches(msg, m.keys.VoIP):
			m.switchTab(tabVoIP)
		case key.Matches(msg, m.keys.Filter):
			m.filtering = true
			m.filter.Focus()
		case key.Matches(msg, m.keys.Back):
			switch {
			case m.detail != "":
				m.detail = ""
				if m.back != "" {
					m.tab, m.detail = m.back, m.backDetail
					m.back, m.backDetail = "", ""
				}
			default:
				m.filter.SetValue("")
			}
			m.refresh(true)
			m.showProblem()
		case key.Matches(msg, m.keys.Sort):
			n := len(edgeSorts)
			if m.tab == tabPods {
				n = len(podSorts)
			}
			step := 1
			if msg.String() == "S" {
				step = n - 1
			}
			m.sortIdx[m.tab] = (m.sortIdx[m.tab] + step) % n
			m.refresh(false)
		case key.Matches(msg, m.keys.Hosts):
			m.showHosts = !m.showHosts
			m.refresh(false)
		case key.Matches(msg, m.keys.Left):
			m.vp.ScrollLeft(8)
		case key.Matches(msg, m.keys.Right):
			m.vp.ScrollRight(8)
		case key.Matches(msg, m.keys.NextSect):
			for _, sec := range m.sections {
				if sec.line > m.vp.YOffset {
					m.vp.SetYOffset(sec.line)
					break
				}
			}
		case key.Matches(msg, m.keys.PrevSect):
			for i := len(m.sections) - 1; i >= 0; i-- {
				if m.sections[i].line < m.vp.YOffset {
					m.vp.SetYOffset(m.sections[i].line)
					break
				}
			}
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
		case key.Matches(msg, m.keys.Enter) && m.problemList():
			// a problem: everything found about it, with what to do
			if m.probCursor >= 0 && m.probCursor < len(m.problems) {
				m.detail = problemPrefix + m.problems[m.probCursor].Key
				m.refresh(true)
			}
		case key.Matches(msg, m.keys.Enter) && m.problemDetail() != nil:
			// the pod its evidence names most
			if id := problemPod(m.problemDetail()); id != "" && m.res.View.Entities[id] != nil {
				m.back, m.backDetail = tabOverview, m.detail
				m.tab, m.detail = tabPods, id
				m.refresh(true)
			}
		case m.problemList() && (key.Matches(msg, m.keys.Up) || key.Matches(msg, m.keys.Down)):
			if key.Matches(msg, m.keys.Up) {
				m.probCursor--
			} else {
				m.probCursor++
			}
			m.probKey = ""
			m.refresh(false)
			m.showProblem()
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
	m.syncKeys()
	return m, tea.Batch(cmds...)
}

func (m *model) resize() {
	h := m.contentHeight()
	m.st.Width = m.width
	m.vp.Width, m.vp.Height = m.width, h
	m.tbl.SetWidth(m.width)
	m.tbl.SetHeight(h - 1) // one line for the sort hint
}

// step moves to the next or previous visible tab.
func (m *model) step(d int) {
	vis := m.visible()
	for i, t := range vis {
		if t == m.tab {
			m.switchTab(vis[(i+d+len(vis))%len(vis)])
			return
		}
	}
	m.switchTab(vis[0])
}

func (m *model) switchTab(name string) {
	ok := false
	for _, t := range m.visible() {
		ok = ok || t == name
	}
	if !ok {
		return
	}
	m.tab = name
	m.detail, m.back, m.backDetail = "", "", ""
	m.refresh(true)
	m.showProblem()
}

// refresh rebuilds the content of the current tab.
func (m *model) refresh(resetScroll bool) {
	if !m.ready {
		return
	}
	m.syncKeys()
	m.resize() // what is on screen decides the height of the help
	if m.res != nil && m.tableTab() {
		m.buildTable()
		return
	}
	var b textBuf
	switch {
	case m.res == nil && m.err != nil:
		fmt.Fprintf(&b, "error: %v\n", m.err)
	case m.res == nil:
		b.WriteString("loading data from agents…\n")
	default:
		m.renderText(&b)
	}
	m.sections = b.sections
	content := b.String()
	// a tab longer than the screen starts with what it holds
	if len(m.sections) > 1 && strings.Count(content, "\n") > m.vp.Height && !m.problemList() {
		var names []string
		for _, sec := range m.sections {
			names = append(names, sec.title)
		}
		index := render.Wrap(render.Style{Width: m.st.Width}, "sections ([ and ] jump): "+strings.Join(names, " · "), 2)
		content = m.st.Dim(index) + "\n" + content
		for i := range m.sections {
			m.sections[i].line += strings.Count(index, "\n") + 1
		}
	}
	m.vp.SetContent(content)
	if resetScroll {
		m.vp.GotoTop()
		m.vp.SetXOffset(0)
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
	var specs []colSpec
	var rows []table.Row
	m.rowIDs = m.rowIDs[:0]
	switch m.tab {
	case tabNetwork:
		edges := render.FilterEdges(v, m.filt())
		render.SortEdges(edges, edgeSorts[m.sortIdx[m.tab]])
		// prio: what stays on a narrow terminal (errors before volumes)
		specs = []colSpec{
			{"CLIENT", 30, true, 99}, {"SERVER", 30, true, 99}, {"PORT", 5, false, 11}, {"RTT p50", 8, false, 2}, {"RTT p99", 8, false, 10},
			{"CONN p99", 8, false, 5}, {"CONN/s", 7, false, 6}, {"TX/s", 9, false, 3}, {"RX/s", 9, false, 4}, {"RETR/s", 7, false, 7},
			{"REFUSED", 7, false, 9}, {"TIMEOUT", 7, false, 8}, {"SEEN", 6, false, 1},
		}
		for _, e := range edges {
			s := e.Stats
			server := e.Server.Display()
			if e.CrossZone {
				server += " ⇄"
			}
			m.rowIDs = append(m.rowIDs, edgeKey(e))
			rows = append(rows, table.Row{
				e.Client.Display(), server, strconv.Itoa(int(e.Port)),
				analysis.Dur(s.RTT.P50()), analysis.Dur(s.RTT.P99()), analysis.Dur(s.Connect.P99()),
				analysis.Rate(v.PerSec(s.Connects)), analysis.Bytes(v.PerSec(s.BytesTx)), analysis.Bytes(v.PerSec(s.BytesRx)),
				analysis.Rate(v.PerSec(s.Retrans)), warnNum(s.Refused), warnNum(s.Timeouts), e.Side,
			})
		}
	case tabPods:
		pods := render.EntityRows(v, m.filt(), m.showHosts)
		oom := map[string]time.Duration{}
		for _, r := range analysis.OOMRisks(v) {
			oom[r.Endpoint.ID] = r.ETA
		}
		sortPods(pods, podSorts[m.sortIdx[m.tab]], oom)
		specs = []colSpec{
			{"POD", 40, true, 99}, {"NODE", 14, false, 4}, {"CPU", 6, false, 12}, {"CPU TREND", 12, false, 1}, {"RUNQ p99", 8, false, 5},
			{"WAIT CPU", 8, false, 10}, {"MEM", 9, false, 2}, {"MEM%", 5, false, 11}, {"OOM IN", 7, false, 7}, {"THROTTLE", 8, false, 8},
			{"DNS err", 7, false, 6}, {"HTTP rps", 8, false, 3}, {"5xx", 5, false, 9},
		}
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
	cols, kept := fitColumns(m.width, specs)
	for r, row := range rows {
		cells := make(table.Row, len(kept))
		for i, c := range kept {
			cell := row[c]
			if specs[c].flex {
				// names keep their end: replicas differ only in the suffix
				mark := ""
				if strings.HasSuffix(cell, " ⇄") {
					cell, mark = strings.TrimSuffix(cell, " ⇄"), " ⇄"
				}
				cell = render.Truncate(cell, cols[i].Width-lipgloss.Width(mark)) + mark
			}
			cells[i] = cell
		}
		rows[r] = cells
	}
	m.tbl.SetRows(nil) // columns and rows must stay consistent
	m.tbl.SetColumns(cols)
	m.tbl.SetRows(rows)
	// the header is only two lines high once it has columns
	m.tbl.SetHeight(m.contentHeight() - 1)
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
	flex  bool // takes the remaining width
	prio  int  // columns with the lowest priority are dropped first when the terminal is too narrow
}

// minFlex is the narrowest a name column gets before other columns are dropped.
const minFlex = 20

// fitColumns lays the columns out in total cells: fixed columns keep their
// width, flexible ones share the rest, and when even that does not fit the
// lowest priority columns are left out. It returns the columns and the
// index of the spec each one came from.
func fitColumns(total int, specs []colSpec) ([]table.Column, []int) {
	keep := make([]bool, len(specs))
	for i := range keep {
		keep[i] = true
	}
	width := func(s colSpec) int { return max(s.width, lipgloss.Width(s.title)) }
	need := func() (fixed, flexN, n int) {
		for i, s := range specs {
			if !keep[i] {
				continue
			}
			n++
			if s.flex {
				flexN++
			} else {
				fixed += width(s)
			}
		}
		return
	}
	for {
		fixed, flexN, n := need()
		if fixed+flexN*minFlex+2*n <= total {
			break
		}
		drop := -1
		for i, s := range specs {
			if keep[i] && !s.flex && (drop < 0 || s.prio < specs[drop].prio) {
				drop = i
			}
		}
		if drop < 0 {
			break
		}
		keep[drop] = false
	}
	fixed, flexN, n := need()
	avail := total - fixed - 2*n // cell padding
	var cols []table.Column
	var kept []int
	for i, s := range specs {
		if !keep[i] {
			continue
		}
		w := width(s)
		if s.flex {
			w = max(8, avail/max(flexN, 1))
		}
		cols = append(cols, table.Column{Title: s.title, Width: w})
		kept = append(kept, i)
	}
	return cols, kept
}

func sortPods(pods []*analysis.EntityView, by string, oom map[string]time.Duration) {
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
		case "oom":
			// soonest first; pods that are not trending to their limit by
			// how full they are
			if eta, ok := oom[e.ID]; ok {
				return 1e12 - eta.Seconds()
			}
			if s.Res != nil && s.Res.MemMax > 0 {
				return float64(s.Res.MemCurrent) / float64(s.Res.MemMax)
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

// ---------------------------------------------------------------- overview

// showProblem scrolls the Overview so the selected problem is on screen.
func (m *model) showProblem() {
	if !m.problemList() || m.probCursor < 0 || m.probCursor >= len(m.probLines) {
		return
	}
	first, n := m.probLines[m.probCursor][0], m.probLines[m.probCursor][1]
	switch {
	case m.probCursor == 0:
		m.vp.GotoTop()
	case first < m.vp.YOffset:
		m.vp.SetYOffset(first)
	case first+n > m.vp.YOffset+m.vp.Height:
		m.vp.SetYOffset(max(first+min(n, m.vp.Height)-m.vp.Height, 0))
	}
}

// renderOverview lists the problems: one or two lines each, and one line
// per finding for the selected one. Enter opens a problem.
func (m *model) renderOverview(b *textBuf) {
	st, f, v := m.st, m.filt(), m.res.View
	for _, w := range m.res.Warnings {
		fmt.Fprintln(b, render.Wrap(st, st.Warn("! "+w), 2))
	}
	if len(m.res.SLOs) > 0 {
		render.Section(b, st, "SLOs")
		render.SLOs(b, st, m.res.SLOs)
		fmt.Fprintln(b)
	}
	m.problems = m.problems[:0]
	var crit, warn int
	for i := range m.res.Problems {
		p := &m.res.Problems[i]
		if !render.MatchProblem(p, f) {
			continue
		}
		m.problems = append(m.problems, *p)
		switch {
		case p.Kind == "advice":
		case p.Severity == analysis.SevCrit:
			crit++
		default:
			warn++
		}
	}
	// stay on the same problem when the data refreshes
	if m.probKey != "" {
		for i := range m.problems {
			if m.problems[i].Key == m.probKey {
				m.probCursor = i
				break
			}
		}
	}
	m.probCursor = max(0, min(m.probCursor, len(m.problems)-1))
	m.probLines = m.probLines[:0]
	if len(m.problems) == 0 {
		if len(m.res.Problems) == 0 {
			fmt.Fprintln(b, st.OK("✔ no problems detected in this window"))
		} else {
			fmt.Fprintln(b, st.Dim("no finding matches the filter"))
		}
	} else {
		m.probKey = m.problems[m.probCursor].Key
		fmt.Fprintln(b, render.Wrap(st, fmt.Sprintf("%d problem(s): %s %d  %s %d  %s", crit+warn, st.Crit("crit"), crit, st.Warn("warn"), warn,
			st.Dim("· findings about one workload are one problem, likely causes first · ↑/↓ select · enter: evidence and what to do")), 2))
		fmt.Fprintln(b)
	}
	inner := st
	inner.Width = max(st.Width-2, 0)
	for i := range m.problems {
		p := &m.problems[i]
		var blk bytes.Buffer
		render.ProblemHeader(&blk, inner, p, m.res.Problems)
		if i == m.probCursor {
			render.ProblemLines(&blk, inner, p)
		}
		gutter := "  "
		if i == m.probCursor {
			gutter = st.Accent("▌") + " "
		}
		lines := strings.Split(strings.TrimRight(blk.String(), "\n"), "\n")
		m.probLines = append(m.probLines, [2]int{bytes.Count(b.Bytes(), []byte("\n")), len(lines)})
		for _, l := range lines {
			fmt.Fprintln(b, gutter+l)
		}
		fmt.Fprintln(b)
	}
	render.Section(b, st, "Slowest paths (RTT p99)")
	render.Edges(b, st, v, f, "rtt", 8)
}

// renderProblem shows one problem in full.
func (m *model) renderProblem(b *textBuf, p *analysis.Problem) {
	st := m.st
	render.ProblemHeader(b, st, p, m.res.Problems)
	nav := "esc: back to the problems"
	if id := problemPod(p); id != "" && m.res.View.Entities[id] != nil {
		nav = "enter: open " + m.res.View.Entities[id].Endpoint.Display() + " (where its time goes, dependencies, last crash) · " + nav
	}
	render.Note(b, st, "     "+nav)
	fmt.Fprintln(b)
	render.ProblemDetail(b, st, p, 6)
}

// textBuf collects the text of a tab and where its sections start.
type textBuf struct {
	bytes.Buffer
	sections []section
}

type section struct {
	title string
	line  int
}

// MarkSection is called by render.Section before it prints a title.
func (b *textBuf) MarkSection(title string) {
	line := bytes.Count(b.Bytes(), []byte("\n"))
	if b.Len() > 0 {
		line++ // a blank line comes first
	}
	b.sections = append(b.sections, section{title, line})
}

// ---------------------------------------------------------------- text tabs

func (m *model) renderText(b *textBuf) {
	v := m.res.View
	f := m.filt()
	st := m.st
	back := "\nesc: back to the list"
	if m.back != "" {
		back = "\nesc: back to " + m.back
	}
	switch m.tab {
	case tabOverview:
		if p := m.problemDetail(); p != nil {
			m.renderProblem(b, p)
		} else {
			m.detail = "" // the problem is gone
			m.renderOverview(b)
		}
	case tabNetwork:
		// look the edge up in the current data so the view refreshes
		var edge *analysis.Edge
		for _, e := range v.Edges {
			if edgeKey(e) == m.detail {
				edge = e
				break
			}
		}
		if edge != nil {
			render.EdgeDetail(b, st, v, edge)
		} else {
			fmt.Fprintln(b, st.Dim("this connection has no traffic in the current window"))
		}
		fmt.Fprintln(b, st.Dim(back))
	case tabPods:
		render.Pod(b, st, v, m.detail)
		fmt.Fprintln(b, st.Dim(back))
	case tabServices:
		render.Section(b, st, "Load balance per Service")
		render.Services(b, st, v, f)
		render.Section(b, st, "Replicas worse than their siblings")
		render.Outliers(b, st, v, f)
		render.Section(b, st, "Connection pools")
		render.Pools(b, st, v, m.res.Base, f)
	case tabDNS:
		render.DNS(b, st, v, f)
	case tabApps:
		render.Section(b, st, "HTTP routes")
		render.HTTP(b, st, v, f, false)
		render.Section(b, st, "Database statements")
		render.DB(b, st, v, f, false)
		render.Section(b, st, "Slow file operations")
		render.Files(b, st, v, f)
	case tabNodes:
		render.Nodes(b, st, v, f, nodeDetails)
		render.Section(b, st, "Control plane")
		render.ControlPlane(b, st, v, f)
	case tabEvents:
		render.Note(b, st, "newest first")
		render.EventsNewestFirst(b, st, v, f, nil, 500)
	case tabSecurity:
		render.Security(b, st, v, f)
	case tabCost:
		// costs are monthly extrapolations: use the longer baseline window
		// when there is one rather than the last minute
		cv := v
		if base := m.res.Base; base != nil && base.Seconds() > v.Seconds() {
			cv = base
			render.Note(b, st, fmt.Sprintf("computed over the baseline window (%s before the current one), which says more about cost than the last %s",
				time.Duration(base.Seconds()*float64(time.Second)).Round(time.Minute), m.opts.Window))
		}
		render.Section(b, st, "Cost per namespace")
		render.CostByGroup(b, st, analysis.CostByGroup(cv, "", analysis.DefaultPricing, 0.09), "namespace", f)
		render.Cost(b, st, cv, f)
	case tabVoIP:
		render.VoIP(b, st, v, f)
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
	brandStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("13"))
)

// clip cuts a line that is too wide for the screen.
func (m *model) clip(s string) string {
	return lipgloss.NewStyle().MaxWidth(m.width).Render(s)
}

// titleLine fits what matters most first: errors, then the number of
// findings, then context for as long as there is room.
func (m *model) titleLine() string {
	head := brandStyle.Render("🦫 kubecapybara ")
	if m.width < 60 {
		head = brandStyle.Render("🦫 ")
	}
	room := func(s string) bool { return lipgloss.Width(head)+lipgloss.Width(s) <= m.width }
	if m.err != nil {
		head += critBadge.Render("error: "+truncate(m.err.Error(), max(12, min(60, m.width-40)))) + " "
	}
	if m.res != nil {
		var crit, warn int
		for i := range m.res.Problems {
			switch p := &m.res.Problems[i]; {
			case p.Kind == "advice":
			case p.Severity == analysis.SevCrit:
				crit++
			default:
				warn++
			}
		}
		if crit > 0 {
			head += critBadge.Render(fmt.Sprintf("%d crit", crit)) + " "
		}
		if warn > 0 {
			head += warnBadge.Render(fmt.Sprintf("%d warn", warn)) + " "
		}
	}
	if m.loading {
		head += statusStyle.Render("⟳ ")
	}
	if m.res != nil {
		v := m.res.View
		sep := ""
		for _, part := range []string{
			fmt.Sprintf("window %s", m.opts.Window), fmt.Sprintf("%d nodes", len(v.Nodes)), fmt.Sprintf("%d flows", len(v.Edges)),
			"updated " + m.updated.Format("15:04:05"), m.opts.Source,
		} {
			if part == "" || !room(sep+part) {
				break
			}
			head += statusStyle.Render(sep + part)
			sep = " · "
		}
	}
	return m.clip(head)
}

// tabBar shows full names when they fit, short names on narrower
// terminals and, below that, only the keys next to the current tab.
func (m *model) tabBar() string {
	vis := m.visible()
	label := func(i int, name string) string {
		k := "v"
		if i < 10 {
			k = strconv.Itoa((i + 1) % 10)
		}
		if name == "" {
			return k
		}
		return k + " " + name
	}
	build := func(mode int) string {
		var tb []string
		for i, t := range vis {
			name := t
			// the current tab always keeps its full name
			switch {
			case t == m.tab:
			case mode == 1:
				name = shortTabs[t]
			case mode == 2:
				name = ""
			}
			if t == m.tab {
				tb = append(tb, tabActive.Render(label(i, name)))
			} else {
				tb = append(tb, tabInactive.Render(label(i, name)))
			}
		}
		return strings.Join(tb, "")
	}
	for mode := 0; mode < 3; mode++ {
		if bar := build(mode); lipgloss.Width(bar) <= m.width || mode == 2 {
			return m.clip(bar)
		}
	}
	return ""
}

func (m *model) View() string {
	if !m.ready {
		return "starting…"
	}
	m.syncKeys()
	var body string
	if m.res != nil && m.tableTab() {
		sorts := edgeSorts
		legend := "⇄ = cross-zone · ! = errors"
		if m.tab == tabPods {
			sorts = podSorts
			legend = "a: host processes off"
			if m.showHosts {
				legend = "a: host processes on"
			}
		}
		hint := hintStyle.Render(fmt.Sprintf("sort: %s (s/S) · %d rows · enter: details · ?: what the columns mean · %s", sorts[m.sortIdx[m.tab]], len(m.rowIDs), legend))
		body = m.clip(hint) + "\n" + m.tbl.View()
	} else {
		body = m.vp.View()
	}

	footer := m.help.View(m.keys)
	if m.help.ShowAll {
		for _, l := range m.glossary() {
			body += "\n" + hintStyle.Render(l)
		}
	}
	if m.filtering || m.filter.Value() != "" {
		footer = m.filter.View()
	}
	return m.titleLine() + "\n" + m.tabBar() + "\n" + body + "\n" + footer
}

// what the columns of the two tables mean, shown with the full help (?)
var glossaries = map[string]string{
	tabNetwork: "RTT = round trip time the kernel measures on the connection · CONN = time to establish a connection · CONN/s = new connections · " +
		"RETR/s = retransmitted segments (loss) · REFUSED = connects answered with a reset (nothing listens) · TIMEOUT = connects that got no answer · " +
		"SEEN = the end that was observed: client, server or both · ⇄ = the two ends are in different zones",
	tabPods: "CPU = cores used · CPU TREND = the last samples · RUNQ p99 = how long threads wait for a CPU at worst · WAIT CPU = share of the time " +
		"the pod wanted a CPU and did not get one · MEM% = memory used of the limit · OOM IN = when memory reaches the limit at the current growth · " +
		"THROTTLE = share of scheduler periods cut short by the CPU limit · DNS err = failed lookups · 5xx = share of failed HTTP responses",
}

// glossary returns the wrapped column legend of the table on screen.
func (m *model) glossary() []string {
	g, ok := glossaries[m.tab]
	if !ok || !m.tableTab() || m.width <= 0 {
		return nil
	}
	return strings.Split(render.Wrap(render.Style{Width: m.width}, g, 0), "\n")
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// Frame renders a single dashboard frame without a terminal (used for
// screenshots and tests). detail optionally opens a pod entity (Pods tab)
// or an edge key (Network tab).
func Frame(res *Result, opts Options, width, height, tab int, detail string) string {
	m := newModel(nil, opts)
	m.setResult(res)
	m.loading = false
	m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	if tab >= 0 && tab < len(tabs) {
		m.tab = tabs[tab]
	}
	m.detail = detail
	m.refresh(true)
	return m.View()
}

// ProblemKey exposes the detail key of a problem on the Overview tab (for
// screenshots).
func ProblemKey(p *analysis.Problem) string { return problemPrefix + p.Key }

// EdgeKey exposes the detail key of an edge (for screenshots).
func EdgeKey(e *analysis.Edge) string { return edgeKey(e) }
