package analysis

import (
	"sort"

	"github.com/galq5/kubecapybara/internal/model"
)

// NodeReport summarises one node for the noisy-neighbour view.
type NodeReport struct {
	Node      *NodeView
	Entities  []NodeEntity
	Drops     uint64
	Retrans   uint64
	CPUCores  float64
	DiskBytes uint64
}

// NodeEntity is a workload's resource usage on a node.
type NodeEntity struct {
	Endpoint  Endpoint
	Cores     float64
	RunQP99   float64
	RunQShare float64 // waiting-for-CPU time per on-CPU time
	Stolen    uint64  // ns of run queue delay this entity caused others
	DiskBytes uint64
	DiskP99   float64
	NetBytes  uint64
	Culprits  map[string]uint64
}

// NodeReports builds per-node noisy neighbour reports.
func NodeReports(v *View) []NodeReport {
	byNode := map[string]*NodeReport{}
	for name, n := range v.Nodes {
		byNode[name] = &NodeReport{Node: n}
	}
	for _, s := range v.Snaps {
		r := byNode[s.Node]
		for _, d := range s.Drops {
			if !benignDrops[d.Reason] {
				r.Drops += d.Count
			}
		}
		for _, p := range s.Pairs {
			if p.Side == "client" {
				r.Retrans += p.Retrans
			}
		}
	}
	stolen := map[string]uint64{} // culprit entity key -> ns
	for _, s := range v.Snaps {
		for _, e := range s.Entities {
			if e.Sched == nil {
				continue
			}
			for c, ns := range e.Sched.Culprits {
				stolen[v.entityKey(c, s.Node)] += ns
			}
		}
	}
	netBytes := map[string]uint64{}
	for _, e := range v.Edges {
		netBytes[e.Client.ID] += e.Stats.BytesTx + e.Stats.BytesRx
		if e.Side == "server" {
			netBytes[e.Server.ID] += e.Stats.BytesTx + e.Stats.BytesRx
		}
	}
	for _, s := range v.Snaps {
		r := byNode[s.Node]
		for id, e := range s.Entities {
			key := v.entityKey(id, s.Node)
			ev := v.Entities[key]
			if ev == nil {
				continue
			}
			ne := NodeEntity{Endpoint: ev.Endpoint, Stolen: stolen[key], NetBytes: netBytes[ev.Endpoint.ID]}
			if sc := e.Sched; sc != nil {
				ne.Cores = float64(sc.OnCPUNs) / 1e9 / v.Seconds()
				ne.RunQP99 = sc.RunQ.P99()
				ne.RunQShare = ratio(float64(sc.OffNs[model.StateRunQ]), float64(sc.OnCPUNs))
				ne.Culprits = sc.Culprits
			}
			if io := e.IO; io != nil {
				ne.DiskBytes = io.ReadBytes + io.WriteBytes
				ne.DiskP99 = io.Lat.P99()
			}
			if ne.Cores == 0 && ne.DiskBytes == 0 && ne.NetBytes == 0 {
				continue
			}
			r.CPUCores += ne.Cores
			r.DiskBytes += ne.DiskBytes
			r.Entities = append(r.Entities, ne)
		}
		sort.Slice(r.Entities, func(i, j int) bool { return r.Entities[i].Cores > r.Entities[j].Cores })
	}
	var out []NodeReport
	for _, r := range byNode {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node.Name < out[j].Node.Name })
	return out
}
