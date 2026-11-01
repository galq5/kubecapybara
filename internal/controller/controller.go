// Package controller keeps CapyFinding custom resources in sync with the
// doctor's findings (kubectl get capyfindings -A) and sends notifications
// when findings fire or resolve.
package controller

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/galq5/kubecapybara/internal/analysis"
	"github.com/galq5/kubecapybara/internal/client"
)

// GVR of the CapyFinding resource.
var GVR = schema.GroupVersionResource{Group: "capybara.dev", Version: "v1alpha1", Resource: "capyfindings"}

const (
	labelManaged  = "capybara.dev/managed"
	labelRule     = "capybara.dev/rule"
	labelSeverity = "capybara.dev/severity"

	stateActive   = "Active"
	stateResolved = "Resolved"
)

// Config configures the controller.
type Config struct {
	Namespace    string // namespace for findings not tied to a pod
	Cluster      string // name used in notifications
	Interval     time.Duration
	Window       time.Duration
	Baseline     time.Duration
	ResolveAfter time.Duration // a finding not seen for this long is resolved
	KeepResolved time.Duration // resolved findings are deleted after this
	MinSeverity  analysis.Severity
	SLOs         []analysis.SLO
	Options      analysis.Options
}

// Controller reconciles findings.
type Controller struct {
	cfg      Config
	src      client.Source
	dyn      dynamic.Interface
	notifier Notifier
	log      *slog.Logger
	now      func() time.Time
}

// New creates a controller.
func New(cfg Config, src client.Source, dyn dynamic.Interface, n Notifier, log *slog.Logger) *Controller {
	if cfg.ResolveAfter == 0 {
		cfg.ResolveAfter = 10 * time.Minute
	}
	if cfg.KeepResolved == 0 {
		cfg.KeepResolved = time.Hour
	}
	if n == nil {
		n = Multi{}
	}
	return &Controller{cfg: cfg, src: src, dyn: dyn, notifier: n, log: log, now: time.Now}
}

// Run reconciles every Interval until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		if err := c.RunOnce(ctx); err != nil {
			c.log.Warn("reconcile failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// RunOnce evaluates the doctor and reconciles once.
func (c *Controller) RunOnce(ctx context.Context) error {
	to := c.now()
	from := to.Add(-c.cfg.Window)
	snaps, errs := c.src.Snapshots(ctx, from, to, false)
	for _, e := range errs {
		c.log.Warn("agent", "err", e)
	}
	if len(snaps) == 0 {
		return fmt.Errorf("no data from agents")
	}
	meta, err := c.src.Meta(ctx)
	if err != nil {
		return err
	}
	v := analysis.Build(snaps, meta, c.cfg.Options)
	var base *analysis.View
	if c.cfg.Baseline > 0 {
		if bs, _ := c.src.Snapshots(ctx, from.Add(-c.cfg.Baseline), from, true); len(bs) > 0 {
			base = analysis.Build(bs, meta, c.cfg.Options)
			if base.From.Before(from.Add(-c.cfg.Baseline)) {
				base.From = from.Add(-c.cfg.Baseline)
			}
			if base.To.After(from) {
				base.To = from
			}
		}
	}
	return c.Reconcile(ctx, analysis.DoctorWith(v, base, c.cfg.SLOs), v)
}

var nonName = regexp.MustCompile(`[^a-z0-9-]+`)

// identity returns where a finding lives and its stable name: one object
// per rule and subject (the workload of its first subject, or the cluster).
func (c *Controller) identity(f analysis.Finding, v *analysis.View) (ns, name, subject string) {
	ns, subject = c.cfg.Namespace, "cluster"
	if len(f.Subjects) > 0 {
		subject = f.Subjects[0]
		if e := v.Entities[f.Subjects[0]]; e != nil {
			subject = e.Endpoint.WorkloadKey()
			if e.Endpoint.Namespace != "" {
				ns = e.Endpoint.Namespace
			}
		}
	}
	h := fnv.New32a()
	h.Write([]byte(f.Rule + "|" + subject))
	rule := strings.Trim(nonName.ReplaceAllString(strings.ToLower(f.Rule), "-"), "-")
	if len(rule) > 40 {
		rule = strings.TrimRight(rule[:40], "-")
	}
	if rule == "" {
		rule = "finding"
	}
	return ns, fmt.Sprintf("%s-%08x", rule, h.Sum32()), subject
}

func strs(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func (c *Controller) spec(f analysis.Finding, subject string) map[string]any {
	return map[string]any{
		"rule": f.Rule, "severity": f.Severity.String(), "category": f.Category, "title": f.Title,
		"details": strs(f.Detail), "hint": f.Hint, "subject": subject, "subjects": strs(f.Subjects),
	}
}

// Reconcile creates/updates objects for current findings and resolves or
// deletes the ones that went away.
func (c *Controller) Reconcile(ctx context.Context, findings []analysis.Finding, v *analysis.View) error {
	now := c.now().UTC()
	ts := now.Format(time.RFC3339)
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Severity < c.cfg.MinSeverity || f.Rule == "" {
			continue
		}
		ns, name, subject := c.identity(f, v)
		if seen[ns+"/"+name] {
			continue // several findings of one rule for the same subject: keep the first (highest ranked)
		}
		seen[ns+"/"+name] = true
		res := c.dyn.Resource(GVR).Namespace(ns)
		cur, err := res.Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "capybara.dev/v1alpha1", "kind": "CapyFinding",
				"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{
					labelManaged: "true", labelRule: name[:strings.LastIndexByte(name, '-')], labelSeverity: strings.ToLower(f.Severity.String())}},
				"spec":   c.spec(f, subject),
				"status": map[string]any{"state": stateActive, "firstSeen": ts, "lastSeen": ts, "occurrences": int64(1)},
			}}
			if _, err := res.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
				c.log.Warn("create finding", "name", name, "err", err)
				continue
			}
			c.notify(ctx, "firing", ns, name, f)
		case err != nil:
			c.log.Warn("get finding", "name", name, "err", err)
		default:
			reopened, _, _ := unstructured.NestedString(cur.Object, "status", "state")
			occ, _, _ := unstructured.NestedInt64(cur.Object, "status", "occurrences")
			_ = unstructured.SetNestedField(cur.Object, c.spec(f, subject), "spec")
			_ = unstructured.SetNestedField(cur.Object, stateActive, "status", "state")
			_ = unstructured.SetNestedField(cur.Object, ts, "status", "lastSeen")
			_ = unstructured.SetNestedField(cur.Object, occ+1, "status", "occurrences")
			unstructured.RemoveNestedField(cur.Object, "status", "resolvedAt")
			labels := cur.GetLabels()
			if labels == nil {
				labels = map[string]string{}
			}
			labels[labelManaged] = "true"
			labels[labelSeverity] = strings.ToLower(f.Severity.String())
			cur.SetLabels(labels)
			if _, err := res.Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
				c.log.Warn("update finding", "name", name, "err", err)
				continue
			}
			if reopened == stateResolved {
				c.notify(ctx, "firing", ns, name, f)
			}
		}
	}

	list, err := c.dyn.Resource(GVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: labelManaged + "=true"})
	if err != nil {
		return err
	}
	for i := range list.Items {
		obj := &list.Items[i]
		key := obj.GetNamespace() + "/" + obj.GetName()
		if seen[key] {
			continue
		}
		state, _, _ := unstructured.NestedString(obj.Object, "status", "state")
		res := c.dyn.Resource(GVR).Namespace(obj.GetNamespace())
		switch state {
		case stateActive:
			last, _, _ := unstructured.NestedString(obj.Object, "status", "lastSeen")
			lt, err := time.Parse(time.RFC3339, last)
			if err != nil || now.Sub(lt) < c.cfg.ResolveAfter {
				continue
			}
			_ = unstructured.SetNestedField(obj.Object, stateResolved, "status", "state")
			_ = unstructured.SetNestedField(obj.Object, ts, "status", "resolvedAt")
			if _, err := res.Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				c.log.Warn("resolve finding", "name", key, "err", err)
				continue
			}
			c.notify(ctx, "resolved", obj.GetNamespace(), obj.GetName(), findingOf(obj))
		case stateResolved:
			at, _, _ := unstructured.NestedString(obj.Object, "status", "resolvedAt")
			rt, err := time.Parse(time.RFC3339, at)
			if err == nil && now.Sub(rt) >= c.cfg.KeepResolved {
				if err := res.Delete(ctx, obj.GetName(), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
					c.log.Warn("delete finding", "name", key, "err", err)
				}
			}
		}
	}
	return nil
}

// findingOf rebuilds a Finding from a stored object (for notifications).
func findingOf(obj *unstructured.Unstructured) analysis.Finding {
	get := func(k string) string { s, _, _ := unstructured.NestedString(obj.Object, "spec", k); return s }
	details, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "details")
	f := analysis.Finding{Rule: get("rule"), Category: get("category"), Title: get("title"), Hint: get("hint"), Detail: details}
	switch get("severity") {
	case "CRIT":
		f.Severity = analysis.SevCrit
	case "WARN":
		f.Severity = analysis.SevWarn
	}
	return f
}

func (c *Controller) notify(ctx context.Context, event, ns, name string, f analysis.Finding) {
	n := Notification{Event: event, Cluster: c.cfg.Cluster, Namespace: ns, Name: name, Rule: f.Rule,
		Severity: f.Severity.String(), Category: f.Category, Title: f.Title, Details: f.Detail, Hint: f.Hint, Time: c.now().UTC()}
	if err := c.notifier.Notify(ctx, n); err != nil {
		c.log.Warn("notification failed", "finding", ns+"/"+name, "err", err)
	}
}
