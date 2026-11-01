// Package client fetches data from kubecapybara agents, either through the
// Kubernetes API server pod proxy (no port-forward needed), from explicit
// agent URLs, or from a saved snapshot bundle.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// Source provides snapshots, profiles and metadata.
type Source interface {
	// Snapshots returns one snapshot per agent for [from, to].
	Snapshots(ctx context.Context, from, to time.Time) ([]*model.Snapshot, []error)
	// Profile runs a CPU profile of an entity on a node.
	Profile(ctx context.Context, node, entity string, seconds, hz int) (*model.Profile, error)
	// Meta returns cluster metadata (nil when unavailable).
	Meta(ctx context.Context) (*k8smeta.Meta, error)
	// Describe returns a short description for status lines.
	Describe() string
}

// Bundle is a portable snapshot export (kubectl capybara snapshot).
type Bundle struct {
	Created   time.Time         `json:"created"`
	From      time.Time         `json:"from"`
	To        time.Time         `json:"to"`
	Snapshots []*model.Snapshot `json:"snapshots"`
	Baseline  []*model.Snapshot `json:"baseline,omitempty"`
	Meta      *k8smeta.Meta     `json:"meta,omitempty"`
}

// ---------------------------------------------------------------- kube

// KubeSource discovers agent pods and talks to them via the API server proxy.
type KubeSource struct {
	CS            kubernetes.Interface
	Namespace     string // agent namespace
	Selector      string // agent pod label selector
	Port          int
	ClusterDomain string

	metaMu  sync.Mutex
	meta    *k8smeta.Meta
	metaTTL time.Duration
}

// NewKubeSource creates a source for agents deployed in namespace ns.
func NewKubeSource(cs kubernetes.Interface, ns, selector string, port int, clusterDomain string) *KubeSource {
	return &KubeSource{CS: cs, Namespace: ns, Selector: selector, Port: port, ClusterDomain: clusterDomain, metaTTL: 30 * time.Second}
}

func (k *KubeSource) Describe() string { return "cluster agents in namespace " + k.Namespace }

func (k *KubeSource) agents(ctx context.Context) ([]corev1.Pod, error) {
	pods, err := k.CS.CoreV1().Pods(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: k.Selector})
	if err != nil {
		return nil, fmt.Errorf("listing agent pods in %s: %w", k.Namespace, err)
	}
	var out []corev1.Pod
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no running agents found in namespace %q (selector %q) - is the DaemonSet deployed?", k.Namespace, k.Selector)
	}
	return out, nil
}

func (k *KubeSource) get(ctx context.Context, pod, path string, params map[string]string) ([]byte, error) {
	return k.CS.CoreV1().Pods(k.Namespace).ProxyGet("http", pod, strconv.Itoa(k.Port), path, params).DoRaw(ctx)
}

func rangeParams(from, to time.Time) map[string]string {
	return map[string]string{
		"from": strconv.FormatInt(from.Unix(), 10),
		"to":   strconv.FormatInt(to.Unix(), 10),
	}
}

func (k *KubeSource) Snapshots(ctx context.Context, from, to time.Time) ([]*model.Snapshot, []error) {
	agents, err := k.agents(ctx)
	if err != nil {
		return nil, []error{err}
	}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		out  []*model.Snapshot
		errs []error
	)
	sem := make(chan struct{}, 16)
	for _, p := range agents {
		wg.Add(1)
		go func(p corev1.Pod) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			raw, err := k.get(ctx, p.Name, "/v1/snapshot", rangeParams(from, to))
			var snap model.Snapshot
			if err == nil {
				err = json.Unmarshal(raw, &snap)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("agent %s (node %s): %w", p.Name, p.Spec.NodeName, err))
				return
			}
			if snap.Node == "" {
				snap.Node = p.Spec.NodeName
			}
			out = append(out, &snap)
		}(p)
	}
	wg.Wait()
	sortSnaps(out)
	return out, errs
}

func (k *KubeSource) Profile(ctx context.Context, node, entity string, seconds, hz int) (*model.Profile, error) {
	agents, err := k.agents(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range agents {
		if p.Spec.NodeName != node {
			continue
		}
		// ProxyGet only issues GETs; the profile endpoint accepts GET too.
		raw, err := k.get(ctx, p.Name, "/v1/profile", map[string]string{
			"entity": entity, "seconds": strconv.Itoa(seconds), "hz": strconv.Itoa(hz),
		})
		if err != nil {
			return nil, err
		}
		var prof model.Profile
		if err := json.Unmarshal(raw, &prof); err != nil {
			return nil, err
		}
		return &prof, nil
	}
	return nil, fmt.Errorf("no agent running on node %s", node)
}

func (k *KubeSource) Meta(ctx context.Context) (*k8smeta.Meta, error) {
	k.metaMu.Lock()
	defer k.metaMu.Unlock()
	if k.meta != nil && time.Since(k.meta.Loaded) < k.metaTTL {
		return k.meta, nil
	}
	m, err := k8smeta.Load(ctx, k.CS, k.ClusterDomain)
	if err != nil {
		if k.meta != nil {
			return k.meta, nil
		}
		return nil, err
	}
	k.meta = m
	return m, nil
}

// ---------------------------------------------------------------- direct

// DirectSource talks to agents at explicit URLs (e.g. http://node:9876).
type DirectSource struct {
	URLs   []string
	Client *http.Client
	// MetaSource optionally provides metadata (e.g. a kube client).
	MetaFn func(ctx context.Context) (*k8smeta.Meta, error)
}

func (d *DirectSource) Describe() string { return fmt.Sprintf("%d agent URL(s)", len(d.URLs)) }

func (d *DirectSource) httpc() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return &http.Client{Timeout: 3 * time.Minute}
}

func (d *DirectSource) fetch(ctx context.Context, base, path string, q url.Values) ([]byte, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	u.Path = path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpc().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s: %s", u.Host, resp.Status, string(b))
	}
	return b, nil
}

func (d *DirectSource) Snapshots(ctx context.Context, from, to time.Time) ([]*model.Snapshot, []error) {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		out  []*model.Snapshot
		errs []error
	)
	q := url.Values{}
	for k, v := range rangeParams(from, to) {
		q.Set(k, v)
	}
	for _, base := range d.URLs {
		wg.Add(1)
		go func(base string) {
			defer wg.Done()
			raw, err := d.fetch(ctx, base, "/v1/snapshot", q)
			var snap model.Snapshot
			if err == nil {
				err = json.Unmarshal(raw, &snap)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("agent %s: %w", base, err))
				return
			}
			out = append(out, &snap)
		}(base)
	}
	wg.Wait()
	sortSnaps(out)
	return out, errs
}

func (d *DirectSource) Profile(ctx context.Context, node, entity string, seconds, hz int) (*model.Profile, error) {
	q := url.Values{"entity": {entity}, "seconds": {strconv.Itoa(seconds)}, "hz": {strconv.Itoa(hz)}}
	var lastErr error
	for _, base := range d.URLs {
		// find the agent for the node
		raw, err := d.fetch(ctx, base, "/v1/status", nil)
		if err != nil {
			lastErr = err
			continue
		}
		var st struct {
			Node string `json:"node"`
		}
		_ = json.Unmarshal(raw, &st)
		if node != "" && st.Node != node && len(d.URLs) > 1 {
			continue
		}
		raw, err = d.fetch(ctx, base, "/v1/profile", q)
		if err != nil {
			return nil, err
		}
		var prof model.Profile
		return &prof, json.Unmarshal(raw, &prof)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no agent for node %s", node)
	}
	return nil, lastErr
}

func (d *DirectSource) Meta(ctx context.Context) (*k8smeta.Meta, error) {
	if d.MetaFn != nil {
		return d.MetaFn(ctx)
	}
	return nil, nil
}

// ---------------------------------------------------------------- file

// FileSource replays a saved bundle.
type FileSource struct {
	Path   string
	bundle *Bundle
}

// NewFileSource loads a bundle from disk.
func NewFileSource(path string) (*FileSource, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bundle Bundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if bundle.Meta != nil {
		bundle.Meta.Index()
	}
	return &FileSource{Path: path, bundle: &bundle}, nil
}

func (f *FileSource) Describe() string {
	return fmt.Sprintf("snapshot %s (%s)", f.Path, f.bundle.Created.Format(time.RFC3339))
}

// Bundle returns the loaded bundle.
func (f *FileSource) Bundle() *Bundle { return f.bundle }

func (f *FileSource) Snapshots(ctx context.Context, from, to time.Time) ([]*model.Snapshot, []error) {
	// a bundle holds a single window: return the baseline for older ranges
	if len(f.bundle.Baseline) > 0 && !to.After(f.bundle.From) {
		return f.bundle.Baseline, nil
	}
	return f.bundle.Snapshots, nil
}

func (f *FileSource) Profile(context.Context, string, string, int, int) (*model.Profile, error) {
	return nil, errors.New("profiling is not available when reading from a snapshot file")
}

func (f *FileSource) Meta(context.Context) (*k8smeta.Meta, error) { return f.bundle.Meta, nil }

func sortSnaps(s []*model.Snapshot) {
	sort.Slice(s, func(i, j int) bool { return s[i].Node < s[j].Node })
}
