package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/galq5/kubecapybara/internal/analysis"
)

// MatchProblem reports whether a problem passes the text filter.
func MatchProblem(p *analysis.Problem, f Filter) bool {
	if f.Namespace != "" && p.Kind == "workload" && !strings.HasPrefix(p.Key, f.Namespace+"/") {
		return false
	}
	if f.match(p.Title) {
		return true
	}
	for _, it := range p.Items {
		if MatchFinding(it.Finding, f) {
			return true
		}
	}
	return false
}

func plural(n int, one string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}

func sinceTag(st Style, since string) string {
	switch since {
	case "new":
		return " " + st.Accent("new")
	case "ongoing":
		return " " + st.Dim("ongoing")
	}
	return ""
}

// ProblemHeader prints what a problem is about in one line, and where to
// look next in a second: its first sign and the other problems its
// evidence points at. all lets it describe those.
func ProblemHeader(w io.Writer, st Style, p *analysis.Problem, all []analysis.Problem) {
	if p.Kind == "advice" {
		fmt.Fprintln(w, Wrap(st, fmt.Sprintf("%s %s · %s, nothing is broken: %s", st.Info("INFO"), st.Title(p.Title), plural(len(p.Items), "finding"), p.Summary()), 5))
		return
	}
	fmt.Fprintln(w, Wrap(st, fmt.Sprintf("%s %s · %s: %s", sev(st, p.Severity), st.Title(p.Title), plural(len(p.Items), "finding"), p.Summary()), 5))
	var notes []string
	if e := p.FirstSign; e != nil {
		notes = append(notes, fmt.Sprintf("first sign %s %s", e.Time.Format("15:04:05"), e.Message))
	}
	if len(p.Related) > 0 {
		var rel []string
		for _, k := range p.Related {
			desc := k
			for i := range all {
				if all[i].Key == k {
					desc = fmt.Sprintf("%s (%s, %s)", k, all[i].Severity, plural(len(all[i].Items), "finding"))
				}
			}
			rel = append(rel, desc)
		}
		notes = append(notes, "see also "+strings.Join(rel, ", "))
	}
	for _, n := range notes {
		Note(w, st, "     "+n)
	}
}

// ProblemLines prints one line per finding of a problem, likely causes
// first.
func ProblemLines(w io.Writer, st Style, p *analysis.Problem) {
	for _, it := range p.Items {
		fmt.Fprintln(w, Wrap(st, fmt.Sprintf("  %s %s %s%s", sev(st, it.Finding.Severity), st.Dim("["+it.Finding.Category+"]"), it.Headline, sinceTag(st, it.Since)), 7))
	}
}

// ProblemDetail prints every finding of a problem with its evidence (at
// most maxLines lines each, 0 = all), the rule that reported it and what
// to do about it.
func ProblemDetail(w io.Writer, st Style, p *analysis.Problem, maxLines int) {
	for i, it := range p.Items {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fd := it.Finding
		fmt.Fprintln(w, Wrap(st, fmt.Sprintf("  %s %s %s%s %s", sev(st, fd.Severity), st.Dim("["+fd.Category+"]"), fd.Title, sinceTag(st, it.Since), st.Dim("("+fd.Rule+")")), 7))
		lines := it.Lines
		if maxLines > 0 && len(lines) > maxLines {
			lines = lines[:maxLines]
		}
		for _, l := range lines {
			fmt.Fprintln(w, Wrap(st, "       • "+l, 9))
		}
		if n := len(it.Lines) - len(lines); n > 0 {
			Note(w, st, fmt.Sprintf("       … %d more", n))
		}
		if it.Hint != "" {
			fmt.Fprintln(w, Wrap(st, "       "+st.Accent("→")+" "+it.Hint, 9))
		}
	}
}

// Problems prints the doctor's findings grouped by what they are about:
// one block per workload or node with all its findings, likely causes
// first, then the recommendations.
func Problems(w io.Writer, st Style, problems []analysis.Problem, f Filter) {
	if len(problems) == 0 {
		fmt.Fprintln(w, st.OK("✔ no problems detected in this window"))
		return
	}
	var crit, warn, shown int
	for i := range problems {
		switch p := &problems[i]; {
		case p.Kind == "advice":
		case p.Severity == analysis.SevCrit:
			crit++
		default:
			warn++
		}
	}
	fmt.Fprintf(w, "%s: %s %d  %s %d\n", plural(crit+warn, "problem"), st.Crit("crit"), crit, st.Warn("warn"), warn)
	for i := range problems {
		p := &problems[i]
		if !MatchProblem(p, f) {
			continue
		}
		shown++
		fmt.Fprintln(w)
		ProblemHeader(w, st, p, problems)
		ProblemDetail(w, st, p, 0)
	}
	if shown == 0 {
		Note(w, st, "\nno finding matches the filter")
	}
}
