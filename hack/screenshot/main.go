// Command screenshot renders kubecapybara dashboard frames into standalone
// HTML files (one per tab), used to produce the screenshots in docs/. The
// data is the built-in demo cluster (--demo) or a snapshot bundle saved with
// `kubectl capybara snapshot`.
//
//	go run ./hack/screenshot --demo --out /tmp/screens
//	node hack/screenshot/png.js /tmp/screens docs/screens   # HTML -> PNG (needs playwright)
package main

import (
	"flag"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/client"
	"github.com/galq5/kubecapybara/internal/demo"
	"github.com/galq5/kubecapybara/internal/model"
	"github.com/galq5/kubecapybara/internal/tui"
)

func main() {
	var (
		file    = flag.String("from-file", "", "snapshot bundle")
		useDemo = flag.Bool("demo", false, "render the built-in demo cluster instead of a bundle")
		out     = flag.String("out", "docs/screens", "output directory")
		width   = flag.Int("width", 150, "terminal columns")
		height  = flag.Int("height", 44, "terminal rows")
		pod     = flag.String("pod", "", "entity to open on the Pods tab (e.g. pod:<uid>)")
	)
	flag.Parse()
	lipgloss.SetColorProfile(termenv.TrueColor)

	var b *client.Bundle
	switch {
	case *useDemo:
		d := demo.New(time.Now())
		b = &client.Bundle{From: d.From, To: d.To, Snapshots: d.Snapshots, Baseline: d.Baseline, Meta: d.Meta}
		if *pod == "" {
			*pod = "pod:pay2"
		}
	case *file != "":
		src, err := client.NewFileSource(*file)
		if err != nil {
			fail(err)
		}
		b = src.Bundle()
	default:
		fail(fmt.Errorf("give --demo or --from-file <bundle.json>"))
	}
	v := analysis.Build(b.Snapshots, b.Meta, analysis.Options{})
	var base *analysis.View
	if len(b.Baseline) > 0 {
		base = analysis.Build(b.Baseline, b.Meta, analysis.Options{})
	}
	res := &tui.Result{View: v, Base: base, Findings: analysis.Doctor(v, base)}
	opts := tui.Options{Source: "cluster agents in namespace capybara", Window: b.To.Sub(b.From).Round(time.Second)}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail(err)
	}
	type shot struct {
		name, tab, detail string
	}
	shots := []shot{
		{"overview", "Overview", ""}, {"network", "Network", ""}, {"pods", "Pods", ""}, {"services", "Services", ""},
		{"dns", "DNS", ""}, {"apps", "Apps", ""}, {"nodes", "Nodes", ""}, {"events", "Events", ""},
		{"security", "Security", ""}, {"cost", "Cost", ""}, {"voip", "VoIP", ""},
	}
	if *pod != "" {
		shots = append(shots, shot{"pod-detail", "Pods", *pod})
	}
	// the pod-to-pod (or pod-to-Service) connection with the most errors
	var worst *analysis.Edge
	errs := func(p *model.Pair) uint64 { return p.Retrans + p.Refused + p.Timeouts }
	for _, e := range v.Edges {
		if e.Client.Kind != analysis.KindPod {
			continue
		}
		if worst == nil || errs(e.Stats) > errs(worst.Stats) {
			worst = e
		}
	}
	if worst != nil {
		shots = append(shots, shot{"edge-detail", "Network", tui.EdgeKey(worst)})
	}
	for _, s := range shots {
		frame := tui.Frame(res, opts, *width, *height, tui.TabIndex(s.tab), s.detail)
		path := filepath.Join(*out, s.name+".html")
		if err := os.WriteFile(path, []byte(page(frame)), 0o644); err != nil {
			fail(err)
		}
		fmt.Println(path)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// palette for the 16 ANSI colours (dark theme)
var ansi16 = []string{
	"#1d2021", "#cc241d", "#98971a", "#d79921", "#458588", "#b16286", "#689d6a", "#a89984",
	"#7c6f64", "#fb4934", "#b8bb26", "#fabd2f", "#83a598", "#d3869b", "#8ec07c", "#ebdbb2",
}

const fgDefault, bgDefault = "#ebdbb2", "#1d2021"

type sgr struct {
	fg, bg                string
	bold, under, rev, dim bool
}

func (s sgr) style() string {
	fg, bg := s.fg, s.bg
	if s.rev {
		if fg == "" {
			fg = fgDefault
		}
		if bg == "" {
			bg = bgDefault
		}
		fg, bg = bg, fg
	}
	var parts []string
	if fg != "" {
		parts = append(parts, "color:"+fg)
	}
	if bg != "" {
		parts = append(parts, "background:"+bg)
	}
	if s.bold {
		parts = append(parts, "font-weight:bold")
	}
	if s.under {
		parts = append(parts, "text-decoration:underline")
	}
	if s.dim {
		parts = append(parts, "opacity:.6")
	}
	return strings.Join(parts, ";")
}

func color256(n int) string {
	if n < 16 {
		return ansi16[n]
	}
	if n >= 232 {
		g := 8 + (n-232)*10
		return fmt.Sprintf("#%02x%02x%02x", g, g, g)
	}
	n -= 16
	lv := []int{0, 95, 135, 175, 215, 255}
	return fmt.Sprintf("#%02x%02x%02x", lv[n/36], lv[(n/6)%6], lv[n%6])
}

func apply(st *sgr, params []int) {
	if len(params) == 0 {
		params = []int{0}
	}
	for i := 0; i < len(params); i++ {
		p := params[i]
		switch {
		case p == 0:
			*st = sgr{}
		case p == 1:
			st.bold = true
		case p == 2:
			st.dim = true
		case p == 4:
			st.under = true
		case p == 7:
			st.rev = true
		case p == 22:
			st.bold, st.dim = false, false
		case p == 24:
			st.under = false
		case p == 27:
			st.rev = false
		case p >= 30 && p <= 37:
			st.fg = ansi16[p-30]
		case p >= 90 && p <= 97:
			st.fg = ansi16[p-90+8]
		case p >= 40 && p <= 47:
			st.bg = ansi16[p-40]
		case p >= 100 && p <= 107:
			st.bg = ansi16[p-100+8]
		case p == 39:
			st.fg = ""
		case p == 49:
			st.bg = ""
		case (p == 38 || p == 48) && i+1 < len(params):
			var c string
			if params[i+1] == 5 && i+2 < len(params) {
				c = color256(params[i+2])
				i += 2
			} else if params[i+1] == 2 && i+4 < len(params) {
				c = fmt.Sprintf("#%02x%02x%02x", params[i+2], params[i+3], params[i+4])
				i += 4
			}
			if p == 38 {
				st.fg = c
			} else {
				st.bg = c
			}
		}
	}
}

// toHTML converts SGR-coloured text to HTML spans.
func toHTML(s string) string {
	var b strings.Builder
	var st sgr
	open := false
	flush := func() {
		if open {
			b.WriteString("</span>")
			open = false
		}
		if css := st.style(); css != "" {
			b.WriteString(`<span style="` + css + `">`)
			open = true
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				var params []int
				for _, f := range strings.Split(s[i+2:j], ";") {
					n, _ := strconv.Atoi(f)
					params = append(params, n)
				}
				apply(&st, params)
				flush()
			}
			i = j
			continue
		}
		r := s[i]
		if r < 0x80 {
			b.WriteString(html.EscapeString(string(r)))
			continue
		}
		// copy a full UTF-8 sequence
		k := i + 1
		for k < len(s) && s[k]&0xC0 == 0x80 {
			k++
		}
		b.WriteString(s[i:k])
		i = k - 1
	}
	if open {
		b.WriteString("</span>")
	}
	return b.String()
}

func page(frame string) string {
	return `<!doctype html><html><head><meta charset="utf-8"><style>
body{margin:0;background:` + bgDefault + `}
.term{display:inline-block;margin:0;padding:14px 18px;background:` + bgDefault + `;color:` + fgDefault + `;
font:13px/1.32 "DejaVu Sans Mono","Menlo","Consolas",monospace;white-space:pre}
</style></head><body><pre class="term">` + toHTML(frame) + `</pre></body></html>`
}
