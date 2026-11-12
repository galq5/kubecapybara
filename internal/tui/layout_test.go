package tui

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/demo"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func demoResult() *Result {
	c := demo.New(time.Now())
	v := analysis.Build(c.Snapshots, c.Meta, analysis.Options{})
	base := analysis.Build(c.Baseline, c.Meta, analysis.Options{})
	findings := analysis.Doctor(v, base)
	return &Result{View: v, Base: base, Findings: findings, Problems: analysis.Triage(v, findings, base, analysis.Doctor(base, nil)),
		Warnings: []string{"agent capybara-agent-zzz (node node-d): context deadline exceeded"}}
}

func demoModel(t *testing.T, width, height int) *model {
	t.Helper()
	m := newModel(nil, Options{Window: time.Minute, Source: "cluster agents in namespace capybara"})
	m.setResult(demoResult())
	m.loading = false
	m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	return m
}

func frameLines(m *model) []string {
	return strings.Split(ansiRe.ReplaceAllString(m.View(), ""), "\n")
}

func press(m *model, keys ...string) {
	for _, k := range keys {
		switch k {
		case "enter":
			m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		case "esc":
			m.Update(tea.KeyMsg{Type: tea.KeyEsc})
		case "down":
			m.Update(tea.KeyMsg{Type: tea.KeyDown})
		case "tab":
			m.Update(tea.KeyMsg{Type: tea.KeyTab})
		default:
			m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
		}
	}
}

// Every tab must fill the terminal exactly: a frame that is too tall loses
// its title line, a line that is too wide is cut by the terminal.
func TestFramesFitTheTerminal(t *testing.T) {
	for _, sz := range [][2]int{{80, 24}, {100, 30}, {132, 43}, {200, 60}} {
		m := demoModel(t, sz[0], sz[1])
		for _, tab := range m.visible() {
			m.switchTab(tab)
			check := func(what string) {
				lines := frameLines(m)
				if len(lines) != sz[1] {
					t.Errorf("%dx%d %s%s: %d lines", sz[0], sz[1], tab, what, len(lines))
				}
				for i, l := range lines {
					if w := runewidth.StringWidth(l); w > sz[0] {
						t.Errorf("%dx%d %s%s: line %d is %d cells wide: %q", sz[0], sz[1], tab, what, i+1, w, l)
						break
					}
				}
				if !strings.Contains(lines[0], "🦫") || !strings.Contains(lines[0], "crit") {
					t.Errorf("%dx%d %s%s: no title line with the findings: %q", sz[0], sz[1], tab, what, lines[0])
				}
				if !strings.Contains(lines[1], tab) {
					t.Errorf("%dx%d %s%s: the tab bar does not name the tab: %q", sz[0], sz[1], tab, what, lines[1])
				}
			}
			check("")
			if m.tableTab() || tab == tabOverview {
				press(m, "enter")
				check(" detail")
				press(m, "esc")
			}
			press(m, "?")
			check(" with help")
			press(m, "?")
		}
	}
}

func TestNarrowTablesKeepErrorsAndNameSuffixes(t *testing.T) {
	m := demoModel(t, 80, 24)
	m.switchTab(tabNetwork)
	out := strings.Join(frameLines(m), "\n")
	for _, want := range []string{"REFUSED", "TIMEOUT", "RTT p99", "-fghij", "-abcde"} {
		if !strings.Contains(out, want) {
			t.Errorf("Network at 80 columns lost %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "TX/s") {
		t.Error("volume columns should make room for the error columns on a narrow terminal")
	}
	m.switchTab(tabPods)
	out = strings.Join(frameLines(m), "\n")
	for _, want := range []string{"5xx", "THROTTLE", "OOM IN", "-fghij", "-m9wzt"} {
		if !strings.Contains(out, want) {
			t.Errorf("Pods at 80 columns lost %q:\n%s", want, out)
		}
	}
}

func TestErrorIsShownFirstInTheTitle(t *testing.T) {
	m := demoModel(t, 80, 24)
	m.err = context.DeadlineExceeded
	title := frameLines(m)[0]
	if !strings.Contains(title, "error: context deadline exceeded") {
		t.Fatalf("error not visible at 80 columns: %q", title)
	}
}

func TestVoIPTabOnlyWithVoIPTraffic(t *testing.T) {
	m := demoModel(t, 150, 44)
	if vis := m.visible(); vis[len(vis)-1] != tabVoIP {
		t.Fatalf("no VoIP tab although the demo has SIP and RTP: %v", vis)
	}
	press(m, "v")
	if out := strings.Join(frameLines(m), "\n"); m.tab != tabVoIP || !strings.Contains(out, "Calls (SIP)") || !strings.Contains(out, "Media (RTP)") {
		t.Fatalf("v did not open the VoIP tab:\n%s", out)
	}
	// without SIP/RTP the tab is gone and the dashboard leaves it
	res := demoResult()
	for _, e := range res.View.Entities {
		e.Stats.SIP, e.Stats.RTP = nil, nil
	}
	m.Update(loadedMsg{res: res})
	if m.tab == tabVoIP || len(m.visible()) != len(tabs)-1 || strings.Contains(frameLines(m)[1], "VoIP") {
		t.Fatalf("VoIP tab still shown without VoIP traffic (tab %s)", m.tab)
	}
	press(m, "v")
	if m.tab == tabVoIP {
		t.Fatal("v must do nothing without VoIP traffic")
	}
}

// The Overview lists problems, not findings: enter opens a problem with
// all its evidence, enter again the pod it is about, esc walks back.
func TestOverviewProblemsDrillDown(t *testing.T) {
	m := demoModel(t, 120, 40)
	if len(m.problems) < 3 || m.problems[0].Key != "shop/Deployment/payments" {
		t.Fatalf("the payments incident should come first: %d problems", len(m.problems))
	}
	out := strings.Join(frameLines(m), "\n")
	for _, want := range []string{"2 crit", "problem(s)", "shop/Deployment/payments · 1", "see also data/StatefulSet/postgres"} {
		if !strings.Contains(out, want) {
			t.Errorf("Overview lacks %q:\n%s", want, out)
		}
	}
	press(m, "enter")
	out = strings.Join(frameLines(m), "\n")
	if m.problemDetail() == nil || !strings.Contains(out, "(crash)") || !strings.Contains(out, "why-crash shop/payments-7f9c5d6b4-fghij") {
		t.Fatalf("enter did not open the problem:\n%s", out)
	}
	press(m, "enter")
	out = strings.Join(frameLines(m), "\n")
	if m.tab != tabPods || m.detail != "pod:pay2" || !strings.Contains(out, "Last crash") {
		t.Fatalf("enter did not open the pod of the problem (tab %s, detail %q):\n%s", m.tab, m.detail, out)
	}
	press(m, "esc")
	if m.tab != tabOverview || m.problemDetail() == nil {
		t.Fatalf("esc did not return to the problem: %s %q", m.tab, m.detail)
	}
	press(m, "esc")
	if m.tab != tabOverview || m.detail != "" {
		t.Fatalf("esc did not return to the list: %s %q", m.tab, m.detail)
	}
	// moving the selection keeps the selected problem on screen
	for i := 0; i < len(m.problems)-1; i++ {
		press(m, "down")
		first, n := m.probLines[m.probCursor][0], m.probLines[m.probCursor][1]
		if first < m.vp.YOffset || first+min(n, m.vp.Height) > m.vp.YOffset+m.vp.Height {
			t.Fatalf("problem %d (lines %d..%d) is off screen (%d..%d)", m.probCursor, first, first+n, m.vp.YOffset, m.vp.YOffset+m.vp.Height)
		}
	}
	if last := m.problems[m.probCursor]; m.probCursor != len(m.problems)-1 || last.Kind != "advice" {
		t.Fatalf("the recommendations come last: cursor %d of %d, kind %s", m.probCursor, len(m.problems), last.Kind)
	}
}

// ? explains the columns of the two tables.
func TestHelpExplainsTableColumns(t *testing.T) {
	m := demoModel(t, 120, 40)
	m.switchTab(tabPods)
	if strings.Contains(strings.Join(frameLines(m), "\n"), "share of scheduler periods") {
		t.Fatal("the glossary should only show with the full help")
	}
	press(m, "?")
	lines := frameLines(m)
	if out := strings.Join(lines, "\n"); !strings.Contains(out, "share of scheduler periods") || len(lines) != 40 {
		t.Fatalf("glossary missing or frame not %d lines (%d):\n%s", 40, len(lines), out)
	}
	m.switchTab(tabDNS)
	if out := strings.Join(frameLines(m), "\n"); strings.Contains(out, "RUNQ p99 =") {
		t.Fatalf("no table, no glossary:\n%s", out)
	}
}

// [ and ] jump between the sections of a long tab, which starts with an
// index of them.
func TestSectionJumps(t *testing.T) {
	m := demoModel(t, 120, 16)
	m.switchTab(tabNodes)
	out := strings.Join(frameLines(m), "\n")
	if len(m.sections) < 3 || !strings.Contains(out, "sections ([ and ] jump)") || !strings.Contains(out, "Control plane") {
		t.Fatalf("no section index (%d sections):\n%s", len(m.sections), out)
	}
	for i := 0; i < 3; i++ {
		before := m.vp.YOffset
		press(m, "]")
		if m.vp.YOffset <= before {
			t.Fatalf("] did not move forward (%d -> %d)", before, m.vp.YOffset)
		}
		if out := strings.Join(frameLines(m)[2:], "\n"); !strings.Contains(out, m.sections[i].title) {
			t.Fatalf("after ] section %q is not on screen:\n%s", m.sections[i].title, out)
		}
	}
	press(m, "[", "[", "[", "[")
	if m.vp.YOffset > m.sections[0].line {
		t.Fatalf("[ did not go back to the first section: offset %d", m.vp.YOffset)
	}
}

func TestFooterOnlyOffersKeysThatWork(t *testing.T) {
	m := demoModel(t, 200, 40)
	foot := func() string { l := frameLines(m); return l[len(l)-1] }
	m.switchTab(tabDNS)
	if f := foot(); strings.Contains(f, "sort") || strings.Contains(f, "details") {
		t.Errorf("DNS has no table: %q", f)
	}
	before := m.sortIdx[tabDNS]
	press(m, "s")
	if m.sortIdx[tabDNS] != before {
		t.Error("s changed the sort order of a tab without a table")
	}
	m.switchTab(tabPods)
	if f := foot(); !strings.Contains(f, "sort") || !strings.Contains(f, "details") || !strings.Contains(f, "host processes") {
		t.Errorf("Pods footer: %q", f)
	}
	rows := len(m.rowIDs)
	press(m, "a")
	if len(m.rowIDs) <= rows {
		t.Errorf("a did not add host processes: %d rows before, %d after", rows, len(m.rowIDs))
	}
}

func TestEventsNewestFirstAndFilterEverywhere(t *testing.T) {
	m := demoModel(t, 150, 44)
	m.switchTab(tabEvents)
	out := strings.Join(frameLines(m), "\n")
	if sip, dns := strings.Index(out, "SIP INVITE"), strings.Index(out, "SERVFAIL"); sip < 0 || dns < 0 || sip > dns {
		t.Errorf("the newest event (SIP, 12s ago) must come before the oldest (DNS, 50s ago):\n%s", out)
	}
	// the filter applies to the Cost tab too
	m.switchTab(tabCost)
	press(m, "/", "v", "o", "i", "c", "e", "enter")
	out = strings.Join(frameLines(m), "\n")
	if !strings.Contains(out, "voice") || strings.Contains(out, "kube-system") || strings.Contains(out, "frontend") {
		t.Errorf("Cost ignores the filter:\n%s", out)
	}
	if !strings.Contains(out, "baseline window") {
		t.Errorf("Cost should be computed over the baseline window:\n%s", out)
	}
}

func TestAppsMergesReplicas(t *testing.T) {
	m := demoModel(t, 150, 44)
	m.switchTab(tabApps)
	out := strings.Join(frameLines(m), "\n")
	if n := strings.Count(out, "/products/:id"); n != 1 {
		t.Errorf("the three frontend replicas should share one row per route, got %d:\n%s", n, out)
	}
	for _, want := range []string{"HTTP routes", "Database statements", "Slow file operations", "pg_wal"} {
		if !strings.Contains(out, want) {
			t.Errorf("Apps tab lacks %q", want)
		}
	}
}
