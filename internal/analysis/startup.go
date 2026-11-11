package analysis

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// TimelineEntry is one line of a startup timeline.
type TimelineEntry struct {
	Time     time.Time
	Source   string // k8s or ebpf
	Severity string
	Text     string
}

// StartupReport explains where a pod's startup time went.
type StartupReport struct {
	Pod      *k8smeta.Pod
	Timeline []TimelineEntry
	Phases   []Phase
	Advice   []string
	Traced   bool
}

// Phase is a measured interval of the startup.
type Phase struct {
	Name     string
	Duration time.Duration
}

// Startup builds a startup timeline for a pod from Kubernetes status and the
// agent's startup trace (execs, DNS lookups, connects, listen, probes).
func Startup(v *View, pod *k8smeta.Pod) *StartupReport {
	rep := &StartupReport{Pod: pod}
	add := func(t time.Time, src, sev, text string) {
		if t.IsZero() {
			return
		}
		rep.Timeline = append(rep.Timeline, TimelineEntry{t, src, sev, text})
	}
	add(pod.Created, "k8s", "", "pod created")
	if t, ok := pod.Conditions["PodScheduled"]; ok {
		add(t, "k8s", "", "scheduled to node "+pod.Node)
	}
	if t, ok := pod.Conditions["Initialized"]; ok {
		add(t, "k8s", "", "init containers done")
	}
	var firstStart time.Time
	for _, c := range pod.Containers {
		if !c.StartedAt.IsZero() {
			add(c.StartedAt, "k8s", "", fmt.Sprintf("container %s started (%s)", c.Name, c.Image))
			if firstStart.IsZero() || c.StartedAt.Before(firstStart) {
				firstStart = c.StartedAt
			}
		}
	}
	readyAt, ready := pod.Conditions["Ready"]
	if ready {
		add(readyAt, "k8s", "", "pod Ready (receiving traffic)")
	}

	id := "pod:" + pod.UID
	var dnsFail, connFail int
	var dnsTime time.Duration
	var firstListen time.Time
	for _, st := range v.Startups {
		if st.Endpoint.ID != id {
			continue
		}
		rep.Traced = true
		for _, e := range st.Events {
			sev := e.Severity
			if sev == model.SevInfo {
				sev = ""
			}
			text := e.Message
			switch e.Type {
			case model.EvDNSQuery, model.EvDNSFail:
				if us, err := strconv.ParseUint(e.Fields["latencyUs"], 10, 64); err == nil {
					dnsTime += time.Duration(us) * time.Microsecond
				}
				if e.Type == model.EvDNSFail {
					dnsFail++
				}
			case model.EvConnFail:
				connFail++
			case model.EvListen:
				if firstListen.IsZero() {
					firstListen = e.Time
				}
			}
			add(e.Time, "ebpf", sev, text)
		}
	}
	// probes: kubelet (host) or node IP -> pod
	var probeRefused, probeOK uint64
	_, in := v.EdgesOf(id)
	for _, e := range in {
		if e.Client.Kind == KindHost || e.Client.Kind == KindNode {
			probeRefused += e.Stats.Refused
			probeOK += e.Stats.Connects
		}
	}
	sort.SliceStable(rep.Timeline, func(i, j int) bool { return rep.Timeline[i].Time.Before(rep.Timeline[j].Time) })

	// phases. Kubernetes reports the start of the current container and the
	// last time the pod became Ready: after a restart those are later than
	// the traced first start, and a phase between them would be negative.
	phase := func(name string, d time.Duration) {
		if d >= 0 {
			rep.Phases = append(rep.Phases, Phase{name, d})
		}
	}
	if t, ok := pod.Conditions["PodScheduled"]; ok {
		phase("scheduling", t.Sub(pod.Created))
		if !firstStart.IsZero() {
			phase("image pull + init + create", firstStart.Sub(t))
		}
	}
	if !firstStart.IsZero() && !firstListen.IsZero() {
		phase("app start → listening", firstListen.Sub(firstStart))
	}
	if !firstListen.IsZero() && ready {
		phase("listening → Ready (probes)", readyAt.Sub(firstListen))
	} else if !firstStart.IsZero() && ready {
		phase("container start → Ready", readyAt.Sub(firstStart))
	}

	// advice
	if dnsFail > 0 {
		rep.Advice = append(rep.Advice, fmt.Sprintf("%d DNS lookup(s) failed during startup (%s spent in DNS) - check names and ndots", dnsFail, dnsTime.Round(time.Millisecond)))
	} else if dnsTime > time.Second {
		rep.Advice = append(rep.Advice, fmt.Sprintf("%s spent waiting for DNS during startup", dnsTime.Round(time.Millisecond)))
	}
	if connFail > 0 {
		rep.Advice = append(rep.Advice, fmt.Sprintf("%d connection attempt(s) failed during startup: a dependency was not reachable yet (retries/backoff add up)", connFail))
	}
	if probeRefused > 0 {
		rep.Advice = append(rep.Advice, fmt.Sprintf("kubelet probes were refused %d time(s) before the app listened: consider a startupProbe instead of a long initialDelaySeconds", probeRefused))
	}
	if !firstListen.IsZero() && ready && readyAt.After(firstListen) {
		gap := readyAt.Sub(firstListen)
		for _, c := range pod.Containers {
			for _, p := range c.Probes {
				if p.Kind == "readiness" && gap > time.Duration(p.Period+p.Delay+2)*time.Second && gap > 10*time.Second {
					rep.Advice = append(rep.Advice, fmt.Sprintf("Ready came %s after the app listened (readiness initialDelay %ds, period %ds): probes could be tightened",
						gap.Round(time.Second), p.Delay, p.Period))
				}
			}
		}
	}
	if !rep.Traced {
		rep.Advice = append(rep.Advice, "no eBPF startup trace: the agent only traces containers that start while it is running (and within its retention)")
	}
	return rep
}

// CrashesOf returns crash reports for an entity, newest first.
func CrashesOf(v *View, id string) []CrashView {
	var out []CrashView
	for _, c := range v.Crashes {
		if c.Endpoint.ID == id {
			out = append(out, c)
		}
	}
	return out
}

// ExplainExit decodes common exit codes.
func ExplainExit(code int32, reason string) string {
	switch {
	case reason == "OOMKilled":
		return "killed by the OOM killer (memory limit reached)"
	case code == 137:
		return "SIGKILL (OOM kill, liveness probe failure or eviction)"
	case code == 143:
		return "SIGTERM (graceful shutdown requested)"
	case code == 139:
		return "SIGSEGV (segmentation fault)"
	case code == 134:
		return "SIGABRT (abort, e.g. failed assertion or runtime panic in C code)"
	case code == 2 && strings.Contains(reason, "Error"):
		return "exit 2 (Go panic or misuse of a shell builtin)"
	case code == 1:
		return "exit 1 (application error)"
	case code == 0:
		return "exit 0 (completed)"
	}
	return fmt.Sprintf("exit %d", code)
}
