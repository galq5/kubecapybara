package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/kubernetes"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// HubSelector finds the capybara-hub Service in the agent namespace.
const HubSelector = "app.kubernetes.io/name=capybara-hub"

// HubSource reads everything from capybara-hub (one request per refresh
// instead of one per agent), either through the API server Service proxy
// or at a direct URL.
type HubSource struct {
	// Through the API server: CS, Namespace, Service and Port.
	CS        kubernetes.Interface
	Namespace string
	Service   string
	Port      int
	// Or directly (in-cluster clients, port-forward): URL.
	URL    string
	Client *http.Client

	Token       string
	TokenSecret string // read with CS when Token is empty

	// ScopeNamespace and Top are applied by the hub (see hub.Scope).
	ScopeNamespace string
	Top            int

	tokenOnce sync.Once
	metaMu    sync.Mutex
	meta      *k8smeta.Meta
	metaAt    time.Time
}

// DiscoverHub returns the hub Service of a namespace and its port, or ""
// when no hub is deployed.
func DiscoverHub(ctx context.Context, cs kubernetes.Interface, ns string) (string, int, error) {
	l, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{LabelSelector: HubSelector})
	if err != nil {
		return "", 0, err
	}
	for _, s := range l.Items {
		for _, p := range s.Spec.Ports {
			if p.Name == "http" || len(s.Spec.Ports) == 1 {
				return s.Name, int(p.Port), nil
			}
		}
	}
	return "", 0, nil
}

func (h *HubSource) Describe() string {
	d := "capybara-hub"
	if h.URL != "" {
		d += " " + h.URL
	} else {
		d += " in namespace " + h.Namespace
	}
	if h.ScopeNamespace != "" {
		d += ", namespace " + h.ScopeNamespace
	}
	if h.Top > 0 {
		d += fmt.Sprintf(", top %d", h.Top)
	}
	return d
}

func (h *HubSource) token(ctx context.Context) string {
	h.tokenOnce.Do(func() {
		if h.Token != "" || h.CS == nil || h.TokenSecret == "" {
			return
		}
		if s, err := h.CS.CoreV1().Secrets(h.Namespace).Get(ctx, h.TokenSecret, metav1.GetOptions{}); err == nil {
			h.Token = strings.TrimSpace(string(s.Data["token"]))
		}
	})
	return h.Token
}

func (h *HubSource) get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	tok := h.token(ctx)
	if h.URL == "" {
		req := h.CS.CoreV1().RESTClient().Get().Namespace(h.Namespace).Resource("services").SubResource("proxy").
			Name(utilnet.JoinSchemeNamePort("http", h.Service, strconv.Itoa(h.Port))).Suffix(path)
		for k, vs := range q {
			for _, v := range vs {
				req = req.Param(k, v)
			}
		}
		if tok != "" {
			req = req.SetHeader(TokenHeader, tok)
		}
		b, err := req.DoRaw(ctx)
		if apierrors.IsForbidden(err) {
			return nil, fmt.Errorf("capybara-hub %s/%s: %w (needs get on services/proxy in %s; or bypass the hub with --hub=off)", h.Namespace, h.Service, err, h.Namespace)
		}
		if err != nil {
			return nil, fmt.Errorf("capybara-hub %s/%s%s: %w", h.Namespace, h.Service, path, hubErr(err, b))
		}
		return b, nil
	}
	u, err := url.Parse(h.URL)
	if err != nil {
		return nil, err
	}
	u.Path, u.RawQuery = path, q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if tok != "" {
		req.Header.Set(TokenHeader, tok)
	}
	hc := h.Client
	if hc == nil {
		hc = &http.Client{Timeout: 3 * time.Minute}
	}
	resp, err := hc.Do(req) // the transport asks for and decodes gzip
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("capybara-hub %s: %s: %s", path, resp.Status, string(b))
	}
	return b, nil
}

func hubErr(err error, body []byte) error {
	if len(body) > 0 && len(body) < 512 {
		return fmt.Errorf("%w: %s", err, string(body))
	}
	return err
}

// hubSnapshots mirrors hub.SnapshotsResponse (kept here to avoid importing
// the server package into the CLI).
type hubSnapshots struct {
	Snapshots []*model.Snapshot `json:"snapshots"`
	Errors    []string          `json:"errors"`
	Meta      *k8smeta.Meta     `json:"meta"`
}

const hubMetaTTL = 30 * time.Second

func (h *HubSource) scopeParams(q url.Values) {
	if h.ScopeNamespace != "" {
		q.Set("namespace", h.ScopeNamespace)
	}
	if h.Top > 0 {
		q.Set("top", strconv.Itoa(h.Top))
	}
}

func (h *HubSource) Snapshots(ctx context.Context, from, to time.Time, lite bool) ([]*model.Snapshot, []error) {
	q := url.Values{}
	for k, v := range rangeParams(from, to, lite) {
		q.Set(k, v)
	}
	h.scopeParams(q)
	// Metadata rides along with live (non-lite) requests: pruned to what the
	// scoped data needs, or the full set at most every hubMetaTTL.
	scoped := h.ScopeNamespace != "" || h.Top > 0
	h.metaMu.Lock()
	wantMeta := !lite && (scoped || h.meta == nil || time.Since(h.metaAt) > hubMetaTTL)
	h.metaMu.Unlock()
	if wantMeta {
		q.Set("meta", "1")
	}
	b, err := h.get(ctx, "/v1/snapshots", q)
	if err != nil {
		return nil, []error{err}
	}
	var resp hubSnapshots
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, []error{fmt.Errorf("capybara-hub: %w", err)}
	}
	var errs []error
	for _, e := range resp.Errors {
		errs = append(errs, errors.New(e))
	}
	if resp.Meta != nil {
		resp.Meta.Index()
		h.metaMu.Lock()
		h.meta, h.metaAt = resp.Meta, time.Now()
		h.metaMu.Unlock()
	}
	return resp.Snapshots, errs
}

func (h *HubSource) Meta(ctx context.Context) (*k8smeta.Meta, error) {
	h.metaMu.Lock()
	defer h.metaMu.Unlock()
	if h.meta != nil && time.Since(h.metaAt) < hubMetaTTL {
		return h.meta, nil
	}
	q := url.Values{}
	if h.ScopeNamespace != "" {
		q.Set("namespace", h.ScopeNamespace)
	}
	b, err := h.get(ctx, "/v1/meta", q)
	if err != nil {
		if h.meta != nil {
			return h.meta, nil
		}
		return nil, err
	}
	var m k8smeta.Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m.Index()
	h.meta, h.metaAt = &m, time.Now()
	return h.meta, nil
}

func (h *HubSource) Changes(ctx context.Context, since time.Time) ([]k8smeta.Change, error) {
	b, err := h.get(ctx, "/v1/changes", url.Values{"since": {strconv.FormatInt(since.Unix(), 10)}})
	if err != nil {
		return nil, err
	}
	var out []k8smeta.Change
	return out, json.Unmarshal(b, &out)
}

func (h *HubSource) PodEvents(ctx context.Context, ns, uid string) ([]k8smeta.PodEvent, error) {
	b, err := h.get(ctx, "/v1/podevents", url.Values{"namespace": {ns}, "uid": {uid}})
	if err != nil {
		return nil, err
	}
	var out []k8smeta.PodEvent
	return out, json.Unmarshal(b, &out)
}

func (h *HubSource) Profile(ctx context.Context, node, entity string, seconds, hz int) (*model.Profile, error) {
	b, err := h.get(ctx, "/v1/profile", url.Values{"node": {node}, "entity": {entity},
		"seconds": {strconv.Itoa(seconds)}, "hz": {strconv.Itoa(hz)}})
	if err != nil {
		return nil, err
	}
	var p model.Profile
	return &p, json.Unmarshal(b, &p)
}

func (h *HubSource) Counters(ctx context.Context, node, entity string, seconds int) (*model.Counters, error) {
	b, err := h.get(ctx, "/v1/counters", url.Values{"node": {node}, "entity": {entity}, "seconds": {strconv.Itoa(seconds)}})
	if err != nil {
		return nil, err
	}
	var c model.Counters
	return &c, json.Unmarshal(b, &c)
}
