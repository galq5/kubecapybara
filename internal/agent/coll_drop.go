package agent

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/galq5/kubecapybara/internal/bpf"
	"github.com/galq5/kubecapybara/internal/model"
)

// dropCollector: packet drops with kernel drop reasons.
type dropCollector struct {
	a       *Agent
	objs    bpf.DropObjects
	l       linker
	reasons map[uint32]string
}

func (c *dropCollector) Name() string { return "drops" }

func (c *dropCollector) Start(a *Agent) error {
	c.a = a
	c.reasons = dropReasons()
	if err := bpf.LoadDropObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("load (needs Linux 5.17+ drop reasons): %w", err)
	}
	return c.l.tracing(c.objs.OnKfreeSkb, "tp_btf/kfree_skb")
}

// dropReasons reads enum skb_drop_reason from kernel BTF.
func dropReasons() map[uint32]string {
	out := map[uint32]string{}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return out
	}
	var e *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &e); err != nil {
		return out
	}
	for _, v := range e.Values {
		name := strings.TrimPrefix(v.Name, "SKB_DROP_REASON_")
		out[uint32(v.Value)] = name
	}
	return out
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	}
	return fmt.Sprintf("proto-%d", p)
}

func (c *dropCollector) Collect(w *Window) {
	drainMap(c.objs.Drops, func(k bpf.DropDropKey, v *uint64) {
		reason, ok := c.reasons[k.Reason]
		if !ok {
			reason = fmt.Sprintf("reason-%d", k.Reason)
		}
		w.AddDrop(&model.Drop{
			Src: ip16(k.Saddr), Dst: ip16(k.Daddr), Port: k.Dport,
			Proto: protoName(k.Proto), Reason: reason, Count: *v,
		})
	})
}

func (c *dropCollector) Close() error {
	c.l.close()
	return c.objs.Close()
}
