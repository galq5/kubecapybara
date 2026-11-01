// Package k8smeta loads the Kubernetes metadata needed to turn raw IPs and
// pod UIDs reported by agents into names, workloads, nodes and zones.
package k8smeta

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Meta is a point-in-time view of cluster metadata. It is serialisable so
// it can be embedded in snapshot bundles.
type Meta struct {
	Loaded        time.Time              `json:"loaded"`
	ClusterDomain string                 `json:"clusterDomain"`
	Pods          map[string]*Pod        `json:"pods"` // by UID
	Services      []*Service             `json:"services"`
	Nodes         map[string]*Node       `json:"nodes"`       // by name
	ReplicaSets   map[string]*ReplicaSet `json:"replicaSets"` // ns/name
	Deployments   map[string]*Deployment `json:"deployments"` // ns/name
	APIServerIPs  []string               `json:"apiServerIPs,omitempty"`

	podsByIP     map[string]*Pod
	svcByIP      map[string]*Service
	svcByKey     map[string]*Service
	nodesByIP    map[string]*Node
	apiServerIPs map[string]bool
}

// Pod is the subset of a pod we need.
type Pod struct {
	UID          string               `json:"uid"`
	Namespace    string               `json:"namespace"`
	Name         string               `json:"name"`
	Node         string               `json:"node"`
	IP           string               `json:"ip"`
	IPs          []string             `json:"ips,omitempty"`
	HostNetwork  bool                 `json:"hostNetwork,omitempty"`
	Labels       map[string]string    `json:"labels,omitempty"`
	OwnerKind    string               `json:"ownerKind,omitempty"`
	OwnerName    string               `json:"ownerName,omitempty"`
	Workload     string               `json:"workload"` // e.g. Deployment/payments
	TemplateHash string               `json:"templateHash,omitempty"`
	Phase        string               `json:"phase"`
	Created      time.Time            `json:"created"`
	Started      time.Time            `json:"started,omitempty"`
	Deleting     bool                 `json:"deleting,omitempty"`
	Conditions   map[string]time.Time `json:"conditions,omitempty"` // type -> lastTransition (only True)
	Containers   []Container          `json:"containers"`
	DNSPolicy    string               `json:"dnsPolicy,omitempty"`
	Ndots        string               `json:"ndots,omitempty"`
}

// Container is the subset of a container (spec + status) we need.
type Container struct {
	Name            string    `json:"name"`
	ID              string    `json:"id,omitempty"`
	Image           string    `json:"image,omitempty"`
	Ports           []int32   `json:"ports,omitempty"`
	Ready           bool      `json:"ready"`
	Restarts        int32     `json:"restarts"`
	State           string    `json:"state,omitempty"`
	StateReason     string    `json:"stateReason,omitempty"`
	StartedAt       time.Time `json:"startedAt,omitempty"`
	LastReason      string    `json:"lastReason,omitempty"`
	LastExitCode    int32     `json:"lastExitCode,omitempty"`
	LastFinished    time.Time `json:"lastFinished,omitempty"`
	MemLimit        int64     `json:"memLimit,omitempty"`
	CPULimitMilli   int64     `json:"cpuLimitMilli,omitempty"`
	MemRequest      int64     `json:"memRequest,omitempty"`
	CPURequestMilli int64     `json:"cpuRequestMilli,omitempty"`
	Init            bool      `json:"init,omitempty"`
	Probes          []Probe   `json:"probes,omitempty"`
}

// Probe describes a liveness/readiness/startup probe.
type Probe struct {
	Kind   string `json:"kind"` // liveness readiness startup
	Type   string `json:"type"` // http tcp exec grpc
	Port   int32  `json:"port,omitempty"`
	Path   string `json:"path,omitempty"`
	Period int32  `json:"period,omitempty"`
	Delay  int32  `json:"delay,omitempty"`
}

// Service is the subset of a service we need.
type Service struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	ClusterIPs []string          `json:"clusterIPs,omitempty"`
	Type       string            `json:"type"`
	Selector   map[string]string `json:"selector,omitempty"`
	Ports      []ServicePort     `json:"ports,omitempty"`
}

// ServicePort maps a service port to a target port.
type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"targetPort,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

// Node is the subset of a node we need.
type Node struct {
	Name   string   `json:"name"`
	IPs    []string `json:"ips"`
	Zone   string   `json:"zone,omitempty"`
	Region string   `json:"region,omitempty"`
}

// ReplicaSet links pods to deployments.
type ReplicaSet struct {
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	Deployment string    `json:"deployment,omitempty"`
	Revision   string    `json:"revision,omitempty"`
	Hash       string    `json:"hash,omitempty"`
	Created    time.Time `json:"created"`
}

// Deployment is the subset of a deployment we need.
type Deployment struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Revision  string            `json:"revision,omitempty"`
	Selector  map[string]string `json:"selector,omitempty"`
}

// Load reads the metadata from the API server.
func Load(ctx context.Context, cs kubernetes.Interface, clusterDomain string) (*Meta, error) {
	m := &Meta{
		Loaded:        time.Now(),
		ClusterDomain: clusterDomain,
		Pods:          map[string]*Pod{},
		Nodes:         map[string]*Node{},
		ReplicaSets:   map[string]*ReplicaSet{},
		Deployments:   map[string]*Deployment{},
	}
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	for i := range nodes.Items {
		n := &nodes.Items[i]
		node := &Node{
			Name:   n.Name,
			Zone:   firstLabel(n.Labels, "topology.kubernetes.io/zone", "failure-domain.beta.kubernetes.io/zone"),
			Region: firstLabel(n.Labels, "topology.kubernetes.io/region", "failure-domain.beta.kubernetes.io/region"),
		}
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
				node.IPs = append(node.IPs, a.Address)
			}
		}
		m.Nodes[n.Name] = node
	}
	pods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	for i := range pods.Items {
		p := convertPod(&pods.Items[i])
		m.Pods[p.UID] = p
	}
	svcs, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	for i := range svcs.Items {
		s := &svcs.Items[i]
		svc := &Service{Namespace: s.Namespace, Name: s.Name, Type: string(s.Spec.Type), Selector: s.Spec.Selector}
		for _, ip := range s.Spec.ClusterIPs {
			if ip != "" && ip != corev1.ClusterIPNone {
				svc.ClusterIPs = append(svc.ClusterIPs, ip)
			}
		}
		for _, p := range s.Spec.Ports {
			svc.Ports = append(svc.Ports, ServicePort{Name: p.Name, Port: p.Port, TargetPort: p.TargetPort.String(), Protocol: string(p.Protocol)})
		}
		m.Services = append(m.Services, svc)
	}
	// optional: workload ownership (RBAC may forbid; degrade gracefully)
	if rss, err := cs.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range rss.Items {
			m.addRS(&rss.Items[i])
		}
	}
	if deps, err := cs.AppsV1().Deployments("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range deps.Items {
			d := &deps.Items[i]
			dep := &Deployment{Namespace: d.Namespace, Name: d.Name, Revision: d.Annotations["deployment.kubernetes.io/revision"]}
			if d.Spec.Selector != nil {
				dep.Selector = d.Spec.Selector.MatchLabels
			}
			m.Deployments[d.Namespace+"/"+d.Name] = dep
		}
	}
	// apiserver endpoints
	m.apiServerIPs = map[string]bool{}
	m.APIServerIPs = nil
	if slices, err := cs.DiscoveryV1().EndpointSlices("default").List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=kubernetes"}); err == nil {
		for _, sl := range slices.Items {
			for _, ep := range sl.Endpoints {
				for _, a := range ep.Addresses {
					m.apiServerIPs[a] = true
				}
			}
		}
	}
	for ip := range m.apiServerIPs {
		m.APIServerIPs = append(m.APIServerIPs, ip)
	}
	m.Index()
	return m, nil
}

func (m *Meta) addRS(rs *appsv1.ReplicaSet) {
	r := &ReplicaSet{
		Namespace: rs.Namespace,
		Name:      rs.Name,
		Revision:  rs.Annotations["deployment.kubernetes.io/revision"],
		Hash:      rs.Labels["pod-template-hash"],
		Created:   rs.CreationTimestamp.Time,
	}
	for _, o := range rs.OwnerReferences {
		if o.Kind == "Deployment" {
			r.Deployment = o.Name
		}
	}
	m.ReplicaSets[rs.Namespace+"/"+rs.Name] = r
}

func firstLabel(l map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := l[k]; v != "" {
			return v
		}
	}
	return ""
}

func convertPod(p *corev1.Pod) *Pod {
	pod := &Pod{
		UID:          string(p.UID),
		Namespace:    p.Namespace,
		Name:         p.Name,
		Node:         p.Spec.NodeName,
		IP:           p.Status.PodIP,
		HostNetwork:  p.Spec.HostNetwork,
		Labels:       p.Labels,
		TemplateHash: p.Labels["pod-template-hash"],
		Phase:        string(p.Status.Phase),
		Created:      p.CreationTimestamp.Time,
		Deleting:     p.DeletionTimestamp != nil,
		Conditions:   map[string]time.Time{},
		DNSPolicy:    string(p.Spec.DNSPolicy),
	}
	for _, ip := range p.Status.PodIPs {
		pod.IPs = append(pod.IPs, ip.IP)
	}
	if p.Status.StartTime != nil {
		pod.Started = p.Status.StartTime.Time
	}
	if p.Spec.DNSConfig != nil {
		for _, o := range p.Spec.DNSConfig.Options {
			if o.Name == "ndots" && o.Value != nil {
				pod.Ndots = *o.Value
			}
		}
	}
	for _, c := range p.Status.Conditions {
		if c.Status == corev1.ConditionTrue {
			pod.Conditions[string(c.Type)] = c.LastTransitionTime.Time
		}
	}
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			pod.OwnerKind, pod.OwnerName = o.Kind, o.Name
		}
	}
	pod.Workload = workloadOf(pod)

	status := map[string]corev1.ContainerStatus{}
	for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		status[cs.Name] = cs
	}
	add := func(c corev1.Container, init bool) {
		ct := Container{Name: c.Name, Image: c.Image, Init: init}
		for _, port := range c.Ports {
			ct.Ports = append(ct.Ports, port.ContainerPort)
		}
		if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
			ct.MemLimit = q.Value()
		}
		if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
			ct.CPULimitMilli = q.MilliValue()
		}
		if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
			ct.MemRequest = q.Value()
		}
		if q, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
			ct.CPURequestMilli = q.MilliValue()
		}
		for kind, pr := range map[string]*corev1.Probe{"liveness": c.LivenessProbe, "readiness": c.ReadinessProbe, "startup": c.StartupProbe} {
			if pr == nil {
				continue
			}
			probe := Probe{Kind: kind, Period: pr.PeriodSeconds, Delay: pr.InitialDelaySeconds}
			switch {
			case pr.HTTPGet != nil:
				probe.Type, probe.Path = "http", pr.HTTPGet.Path
				probe.Port = resolvePort(c, pr.HTTPGet.Port.String())
			case pr.TCPSocket != nil:
				probe.Type = "tcp"
				probe.Port = resolvePort(c, pr.TCPSocket.Port.String())
			case pr.GRPC != nil:
				probe.Type, probe.Port = "grpc", pr.GRPC.Port
			case pr.Exec != nil:
				probe.Type = "exec"
			}
			ct.Probes = append(ct.Probes, probe)
		}
		sort.Slice(ct.Probes, func(i, j int) bool { return ct.Probes[i].Kind < ct.Probes[j].Kind })
		if st, ok := status[c.Name]; ok {
			ct.ID = trimRuntime(st.ContainerID)
			ct.Ready = st.Ready
			ct.Restarts = st.RestartCount
			switch {
			case st.State.Running != nil:
				ct.State = "running"
				ct.StartedAt = st.State.Running.StartedAt.Time
			case st.State.Waiting != nil:
				ct.State = "waiting"
				ct.StateReason = st.State.Waiting.Reason
			case st.State.Terminated != nil:
				ct.State = "terminated"
				ct.StateReason = st.State.Terminated.Reason
			}
			if t := st.LastTerminationState.Terminated; t != nil {
				ct.LastReason = t.Reason
				ct.LastExitCode = t.ExitCode
				ct.LastFinished = t.FinishedAt.Time
			}
		}
		pod.Containers = append(pod.Containers, ct)
	}
	for _, c := range p.Spec.InitContainers {
		add(c, true)
	}
	for _, c := range p.Spec.Containers {
		add(c, false)
	}
	return pod
}

func resolvePort(c corev1.Container, port string) int32 {
	for _, p := range c.Ports {
		if p.Name == port {
			return p.ContainerPort
		}
	}
	var n int32
	fmt.Sscanf(port, "%d", &n)
	return n
}

func trimRuntime(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[i+3:]
	}
	return id
}

func workloadOf(p *Pod) string {
	switch p.OwnerKind {
	case "":
		return "Pod/" + p.Name
	case "ReplicaSet":
		if p.TemplateHash != "" && strings.HasSuffix(p.OwnerName, "-"+p.TemplateHash) {
			return "Deployment/" + strings.TrimSuffix(p.OwnerName, "-"+p.TemplateHash)
		}
		return "ReplicaSet/" + p.OwnerName
	case "Job":
		// CronJob jobs are named <cronjob>-<timestamp>
		if i := strings.LastIndexByte(p.OwnerName, '-'); i > 0 && len(p.OwnerName)-i == 9 {
			return "CronJob/" + p.OwnerName[:i]
		}
	}
	return p.OwnerKind + "/" + p.OwnerName
}

// PodEvent is a Kubernetes Event about a pod (Scheduled, Pulling, Pulled...).
type PodEvent struct {
	Reason  string    `json:"reason"`
	Message string    `json:"message"`
	Type    string    `json:"type"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Count   int32     `json:"count"`
}

// LoadPodEvents lists the events of a pod, oldest first.
func LoadPodEvents(ctx context.Context, cs kubernetes.Interface, ns, uid string) ([]PodEvent, error) {
	list, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{FieldSelector: "involvedObject.uid=" + uid})
	if err != nil {
		return nil, err
	}
	var out []PodEvent
	for _, e := range list.Items {
		first, last := e.FirstTimestamp.Time, e.LastTimestamp.Time
		if first.IsZero() {
			first = e.EventTime.Time
		}
		if first.IsZero() {
			first = e.CreationTimestamp.Time
		}
		if last.IsZero() {
			last = first
		}
		out = append(out, PodEvent{Reason: e.Reason, Message: e.Message, Type: e.Type, First: first, Last: last, Count: e.Count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].First.Before(out[j].First) })
	return out, nil
}

// PodRequests sums the CPU (millicores) and memory requests and limits of
// the regular containers of a pod.
func (p *Pod) Requests() (cpuReq, cpuLim, memReq, memLim int64) {
	for _, c := range p.Containers {
		if c.Init {
			continue
		}
		cpuReq += c.CPURequestMilli
		cpuLim += c.CPULimitMilli
		memReq += c.MemRequest
		memLim += c.MemLimit
	}
	return
}

// Index builds the lookup tables. It must be called after deserialising.
func (m *Meta) Index() {
	m.podsByIP = map[string]*Pod{}
	m.svcByIP = map[string]*Service{}
	m.svcByKey = map[string]*Service{}
	m.nodesByIP = map[string]*Node{}
	m.apiServerIPs = map[string]bool{}
	for _, ip := range m.APIServerIPs {
		m.apiServerIPs[ip] = true
	}
	for _, p := range m.Pods {
		if p.HostNetwork || p.Phase == "Succeeded" || p.Phase == "Failed" {
			continue
		}
		for _, ip := range append([]string{p.IP}, p.IPs...) {
			if ip == "" {
				continue
			}
			// prefer running, non-deleting pods when IPs are reused
			if cur, ok := m.podsByIP[ip]; ok && !cur.Deleting && cur.Created.After(p.Created) {
				continue
			}
			m.podsByIP[ip] = p
		}
	}
	for _, s := range m.Services {
		m.svcByKey[s.Namespace+"/"+s.Name] = s
		for _, ip := range s.ClusterIPs {
			m.svcByIP[ip] = s
		}
		if s.Namespace == "default" && s.Name == "kubernetes" {
			for _, ip := range s.ClusterIPs {
				m.apiServerIPs[ip] = true
			}
		}
	}
	for _, n := range m.Nodes {
		for _, ip := range n.IPs {
			m.nodesByIP[ip] = n
		}
	}
}

// PodByIP returns the (non hostNetwork) pod owning an IP.
func (m *Meta) PodByIP(ip string) *Pod { return m.podsByIP[ip] }

// ServiceByIP returns the service with a cluster IP.
func (m *Meta) ServiceByIP(ip string) *Service { return m.svcByIP[ip] }

// Service returns a service by namespace/name.
func (m *Meta) Service(ns, name string) *Service { return m.svcByKey[ns+"/"+name] }

// NodeByIP returns the node with an address.
func (m *Meta) NodeByIP(ip string) *Node { return m.nodesByIP[ip] }

// IsAPIServer reports whether ip belongs to the Kubernetes API server.
func (m *Meta) IsAPIServer(ip string) bool { return m.apiServerIPs[ip] }

// ZoneOf returns the zone of a node.
func (m *Meta) ZoneOf(node string) string {
	if n, ok := m.Nodes[node]; ok {
		return n.Zone
	}
	return ""
}

// FindPods returns pods matching "name", "ns/name" or a name prefix.
func (m *Meta) FindPods(ns, query string) []*Pod {
	if i := strings.IndexByte(query, '/'); i > 0 && !strings.Contains(query[:i], "=") {
		ns, query = query[:i], query[i+1:]
	}
	var exact, prefix []*Pod
	for _, p := range m.Pods {
		if ns != "" && p.Namespace != ns {
			continue
		}
		switch {
		case p.Name == query || p.UID == query:
			exact = append(exact, p)
		case strings.HasPrefix(p.Name, query):
			prefix = append(prefix, p)
		}
	}
	out := exact
	if len(out) == 0 {
		out = prefix
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// PodsOfService returns the pods selected by a service.
func (m *Meta) PodsOfService(s *Service) []*Pod {
	if len(s.Selector) == 0 {
		return nil
	}
	var out []*Pod
	for _, p := range m.Pods {
		if p.Namespace == s.Namespace && matches(s.Selector, p.Labels) {
			out = append(out, p)
		}
	}
	return out
}

// ServicesOfPod returns the services selecting a pod.
func (m *Meta) ServicesOfPod(p *Pod) []*Service {
	var out []*Service
	for _, s := range m.Services {
		if s.Namespace == p.Namespace && len(s.Selector) > 0 && matches(s.Selector, p.Labels) {
			out = append(out, s)
		}
	}
	return out
}

func matches(sel, labels map[string]string) bool {
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// Matches reports whether labels satisfy a selector.
func Matches(sel, labels map[string]string) bool { return matches(sel, labels) }
