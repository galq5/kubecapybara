package analysis

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	"github.com/galq5/kubecapybara/internal/k8smeta"
)

var volatileLabels = map[string]bool{
	"pod-template-hash": true, "controller-revision-hash": true, "statefulset.kubernetes.io/pod-name": true,
	"pod-template-generation": true, "batch.kubernetes.io/controller-uid": true, "controller-uid": true,
	"batch.kubernetes.io/job-name": true, "job-name": true,
}

// stableLabels picks labels that identify a workload's pods.
func stableLabels(m *k8smeta.Meta, p *k8smeta.Pod) map[string]string {
	if p.OwnerKind == "ReplicaSet" {
		if rs := m.ReplicaSets[p.Namespace+"/"+p.OwnerName]; rs != nil && rs.Deployment != "" {
			if d := m.Deployments[p.Namespace+"/"+rs.Deployment]; d != nil && len(d.Selector) > 0 {
				return d.Selector
			}
		}
	}
	for _, k := range []string{"app.kubernetes.io/name", "app", "k8s-app", "name"} {
		if v, ok := p.Labels[k]; ok {
			out := map[string]string{k: v}
			if inst, ok := p.Labels["app.kubernetes.io/instance"]; ok && k == "app.kubernetes.io/name" {
				out["app.kubernetes.io/instance"] = inst
			}
			return out
		}
	}
	out := map[string]string{}
	for k, v := range p.Labels {
		if !volatileLabels[k] {
			out[k] = v
		}
	}
	return out
}

type peerKey struct {
	peer string
	port intstr.IntOrString
	prot string
}

// SuggestNetworkPolicy generates a NetworkPolicy allowing exactly the
// traffic observed for a workload (e.g. "Deployment/payments") in ns.
func SuggestNetworkPolicy(v *View, ns, workload string) (string, error) {
	var pods []*k8smeta.Pod
	ids := map[string]bool{}
	for _, p := range v.Meta.Pods {
		_, wname, _ := strings.Cut(p.Workload, "/")
		if p.Namespace == ns && (p.Workload == workload || strings.EqualFold(wname, workload)) {
			pods = append(pods, p)
			ids["pod:"+p.UID] = true
		}
	}
	if len(pods) == 0 {
		return "", fmt.Errorf("no pods found for workload %q in namespace %s", workload, ns)
	}
	sel := stableLabels(v.Meta, pods[0])
	name := strings.ToLower(strings.ReplaceAll(pods[0].Workload, "/", "-")) + "-observed"

	ingress := map[peerKey]networkingv1.NetworkPolicyPeer{}
	egress := map[peerKey]networkingv1.NetworkPolicyPeer{}
	var notes []string
	dns := false

	peerFor := func(ep Endpoint, port uint16) (networkingv1.NetworkPolicyPeer, intstr.IntOrString, bool) {
		switch ep.Kind {
		case KindPod:
			p := v.Meta.Pods[strings.TrimPrefix(ep.ID, "pod:")]
			if p == nil {
				return networkingv1.NetworkPolicyPeer{}, intstr.IntOrString{}, false
			}
			return networkingv1.NetworkPolicyPeer{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": p.Namespace}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: stableLabels(v.Meta, p)},
			}, intstr.FromInt32(int32(port)), true
		case KindService:
			s := v.Meta.Service(ep.Namespace, ep.Name)
			if s == nil || len(s.Selector) == 0 {
				return networkingv1.NetworkPolicyPeer{}, intstr.IntOrString{}, false
			}
			target := intstr.FromInt32(int32(port))
			for _, sp := range s.Ports {
				if sp.Port == int32(port) {
					if n, err := strconv.Atoi(sp.TargetPort); err == nil {
						target = intstr.FromInt32(int32(n))
					} else if sp.TargetPort != "" {
						target = intstr.FromString(sp.TargetPort)
					}
				}
			}
			return networkingv1.NetworkPolicyPeer{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": s.Namespace}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: s.Selector},
			}, target, true
		case KindExternal, KindNode, KindUnknown:
			a, err := netip.ParseAddr(ep.IP)
			if err != nil {
				return networkingv1.NetworkPolicyPeer{}, intstr.IntOrString{}, false
			}
			bits := 32
			if a.Is6() {
				bits = 128
			}
			if ep.DNSName != "" {
				notes = append(notes, fmt.Sprintf("%s = %s (IPs behind DNS names change; consider an egress gateway or FQDN policies)", ep.IP, ep.DNSName))
			}
			return networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: fmt.Sprintf("%s/%d", ep.IP, bits)}}, intstr.FromInt32(int32(port)), true
		}
		return networkingv1.NetworkPolicyPeer{}, intstr.IntOrString{}, false
	}
	keyOf := func(p networkingv1.NetworkPolicyPeer, port intstr.IntOrString) peerKey {
		b, _ := yaml.Marshal(p)
		return peerKey{string(b), port, "TCP"}
	}

	for _, e := range v.Edges {
		if ids[e.Server.ID] {
			if e.Client.Kind == KindHost || e.Client.Kind == KindLocal {
				continue // kubelet probes / node-local traffic are always allowed
			}
			if peer, port, ok := peerFor(e.Client, e.Port); ok {
				ingress[keyOf(peer, port)] = peer
			}
		}
		if ids[e.Client.ID] {
			if e.Server.Kind == KindLocal {
				continue
			}
			if peer, port, ok := peerFor(e.Server, e.Port); ok {
				egress[keyOf(peer, port)] = peer
			}
		}
	}
	for id := range ids {
		if e := v.Entities[id]; e != nil && e.Stats.DNS != nil && e.Stats.DNS.Queries > 0 {
			dns = true
		}
	}

	np := networkingv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"generated-by": "kubecapybara"}},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: sel},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	np.Spec.Ingress = rulesIngress(ingress)
	np.Spec.Egress = rulesEgress(egress)
	if dns {
		udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
		p53 := intstr.FromInt32(53)
		np.Spec.Egress = append(np.Spec.Egress, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
			}},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &p53}, {Protocol: &tcp, Port: &p53}},
		})
	}
	out, err := yaml.Marshal(np)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# NetworkPolicy generated by kubecapybara from traffic observed between %s and %s.\n",
		v.From.Format("2006-01-02 15:04"), v.To.Format("15:04 MST"))
	b.WriteString("# Review before applying: traffic that did not happen in this window will be denied.\n")
	sort.Strings(notes)
	for _, n := range uniq(notes) {
		b.WriteString("#   " + n + "\n")
	}
	b.Write(out)
	return b.String(), nil
}

func uniq(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func sortedKeys(m map[peerKey]networkingv1.NetworkPolicyPeer) []peerKey {
	keys := make([]peerKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].peer != keys[j].peer {
			return keys[i].peer < keys[j].peer
		}
		return keys[i].port.String() < keys[j].port.String()
	})
	return keys
}

func rulesIngress(m map[peerKey]networkingv1.NetworkPolicyPeer) []networkingv1.NetworkPolicyIngressRule {
	byPeer := map[string]*networkingv1.NetworkPolicyIngressRule{}
	var order []string
	for _, k := range sortedKeys(m) {
		r, ok := byPeer[k.peer]
		if !ok {
			r = &networkingv1.NetworkPolicyIngressRule{From: []networkingv1.NetworkPolicyPeer{m[k]}}
			byPeer[k.peer] = r
			order = append(order, k.peer)
		}
		tcp := corev1.ProtocolTCP
		port := k.port
		r.Ports = append(r.Ports, networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &port})
	}
	var out []networkingv1.NetworkPolicyIngressRule
	for _, p := range order {
		out = append(out, *byPeer[p])
	}
	return out
}

func rulesEgress(m map[peerKey]networkingv1.NetworkPolicyPeer) []networkingv1.NetworkPolicyEgressRule {
	byPeer := map[string]*networkingv1.NetworkPolicyEgressRule{}
	var order []string
	for _, k := range sortedKeys(m) {
		r, ok := byPeer[k.peer]
		if !ok {
			r = &networkingv1.NetworkPolicyEgressRule{To: []networkingv1.NetworkPolicyPeer{m[k]}}
			byPeer[k.peer] = r
			order = append(order, k.peer)
		}
		tcp := corev1.ProtocolTCP
		port := k.port
		r.Ports = append(r.Ports, networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &port})
	}
	var out []networkingv1.NetworkPolicyEgressRule
	for _, p := range order {
		out = append(out, *byPeer[p])
	}
	return out
}
