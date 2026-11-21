package model

import (
	"sort"
	"time"
)

// Off-CPU state names used in SchedStats.OffNs.
const (
	StateRunQ  = "runq"
	StateDisk  = "disk"
	StateNet   = "net"
	StatePoll  = "poll"
	StateLock  = "lock"
	StateSleep = "sleep"
	StateOther = "other"
)

// OffStates lists off-CPU states in kernel index order.
var OffStates = []string{StateRunQ, StateDisk, StateNet, StatePoll, StateLock, StateSleep, StateOther}

// Snapshot is what an agent returns for a time range. All counters are
// totals over [From, To]; gauges are the latest value in the range.
type Snapshot struct {
	Node       string                  `json:"node"`
	Version    string                  `json:"version,omitempty"`
	From       time.Time               `json:"from"`
	To         time.Time               `json:"to"`
	Collectors map[string]string       `json:"collectors,omitempty"` // name -> "ok" or error
	Pairs      []*Pair                 `json:"pairs,omitempty"`
	Entities   map[string]*EntityStats `json:"entities,omitempty"`
	Drops      []*Drop                 `json:"drops,omitempty"`
	NodeStats  NodeStats               `json:"nodeStats"`
	DNSNames   map[string]string       `json:"dnsNames,omitempty"` // ip -> hostname learned from DNS answers
	Events     []Event                 `json:"events,omitempty"`
	Listens    []Listen                `json:"listens,omitempty"`
	Crashes    []CrashReport           `json:"crashes,omitempty"`
	Startups   []Startup               `json:"startups,omitempty"`
	// Series holds per-entity resource samples (memory, CPU) in the range.
	Series map[string][]ResourceSample `json:"series,omitempty"`
}

// Pair is TCP traffic between a client and a server endpoint as observed
// from one socket side on this node.
type Pair struct {
	Client string `json:"client,omitempty"`
	Server string `json:"server,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	Side   string `json:"side,omitempty"`  // "client" or "server": which socket we observed
	Owner  string `json:"owner,omitempty"` // entity owning the local socket

	RTT     Hist `json:"rtt"`
	Connect Hist `json:"connect"`

	BytesTx      uint64 `json:"bytesTx,omitempty"`
	BytesRx      uint64 `json:"bytesRx,omitempty"`
	Connects     uint64 `json:"connects,omitempty"`
	Closes       uint64 `json:"closes,omitempty"`
	LifetimeUs   uint64 `json:"lifetimeUs,omitempty"`
	Refused      uint64 `json:"refused,omitempty"`
	Timeouts     uint64 `json:"timeouts,omitempty"`
	SynRetrans   uint64 `json:"synRetrans,omitempty"`
	Retrans      uint64 `json:"retrans,omitempty"`
	RetransLarge uint64 `json:"retransLarge,omitempty"`
	RstSent      uint64 `json:"rstSent,omitempty"`
	RstRcvd      uint64 `json:"rstRcvd,omitempty"`
	MTUReduced   uint64 `json:"mtuReduced,omitempty"`
	// ZeroWindow counts 100ms samples in which the server/peer advertised a
	// zero receive window (it was not reading fast enough).
	ZeroWindow uint64 `json:"zeroWindow,omitempty"`
	// OpenConns / IdleConns are gauges (highest value in the range):
	// established connections and those without received data for 30s.
	OpenConns uint64 `json:"openConns,omitempty"`
	IdleConns uint64 `json:"idleConns,omitempty"`
}

// PairKey identifies a Pair.
type PairKey struct {
	Client, Server string
	Port           uint16
	Side, Owner    string
}

// Key returns the identity of the pair.
func (p *Pair) Key() PairKey {
	return PairKey{p.Client, p.Server, p.Port, p.Side, p.Owner}
}

// Add merges counters of o into p.
func (p *Pair) Add(o *Pair) {
	p.RTT.Add(o.RTT)
	p.Connect.Add(o.Connect)
	p.BytesTx += o.BytesTx
	p.BytesRx += o.BytesRx
	p.Connects += o.Connects
	p.Closes += o.Closes
	p.LifetimeUs += o.LifetimeUs
	p.Refused += o.Refused
	p.Timeouts += o.Timeouts
	p.SynRetrans += o.SynRetrans
	p.Retrans += o.Retrans
	p.RetransLarge += o.RetransLarge
	p.RstSent += o.RstSent
	p.RstRcvd += o.RstRcvd
	p.MTUReduced += o.MTUReduced
	p.ZeroWindow += o.ZeroWindow
	if o.OpenConns > p.OpenConns {
		p.OpenConns = o.OpenConns
	}
	if o.IdleConns > p.IdleConns {
		p.IdleConns = o.IdleConns
	}
}

// AddConcurrent merges a different connection set observed over the same
// time (another flow or owner): like Add, but open/idle connections, gauges
// that Add max-merges over time, are summed.
func (p *Pair) AddConcurrent(o *Pair) {
	open, idle := p.OpenConns+o.OpenConns, p.IdleConns+o.IdleConns
	p.Add(o)
	p.OpenConns, p.IdleConns = open, idle
}

// Clone returns a deep copy.
func (p *Pair) Clone() *Pair {
	c := *p
	c.RTT = Hist{}
	c.Connect = Hist{}
	c.RTT.Add(p.RTT)
	c.Connect.Add(p.Connect)
	return &c
}

// EntityStats holds everything known about one workload entity on a node.
// An entity is a pod ("pod:<uid>") or a host cgroup ("host:<path>").
type EntityStats struct {
	ID         string                   `json:"id"`
	PodUID     string                   `json:"podUID,omitempty"`
	Cgroup     string                   `json:"cgroup,omitempty"`
	Sched      *SchedStats              `json:"sched,omitempty"`
	IO         *IOStats                 `json:"io,omitempty"`
	Res        *Resources               `json:"res,omitempty"`
	DNS        *DNSStats                `json:"dns,omitempty"`
	DNSServer  *DNSStats                `json:"dnsServer,omitempty"`
	HTTP       map[string]*HTTPEndpoint `json:"http,omitempty"`
	ConnErrors map[string]uint64        `json:"connErrors,omitempty"`
	Net        *NetStats                `json:"net,omitempty"`
	DB         map[string]*DBQuery      `json:"db,omitempty"`    // proto|query
	Files      map[string]*FileStats    `json:"files,omitempty"` // path
	SIP        *SIPStats                `json:"sip,omitempty"`
	RTP        *RTPStats                `json:"rtp,omitempty"`
}

// DBQuery aggregates client-side database requests of one statement shape.
type DBQuery struct {
	Proto  string `json:"proto"` // postgres, mysql, redis
	Query  string `json:"query"` // normalized statement or command
	Count  uint64 `json:"count"`
	Errors uint64 `json:"errors,omitempty"`
	Lat    Hist   `json:"lat"`
	// ErrorKinds counts errors by protocol error name (e.g. Cassandra
	// ReadTimeout, Unavailable, Overloaded) when the protocol reports one.
	ErrorKinds map[string]uint64 `json:"errorKinds,omitempty"`
}

// Merge adds o into q.
func (q *DBQuery) Merge(o *DBQuery) {
	q.Count += o.Count
	q.Errors += o.Errors
	q.Lat.Add(o.Lat)
	for k, v := range o.ErrorKinds {
		if q.ErrorKinds == nil {
			q.ErrorKinds = map[string]uint64{}
		}
		q.ErrorKinds[k] += v
	}
}

// FileStats aggregates slow operations on one file.
type FileStats struct {
	Path   string `json:"path"`
	FSType string `json:"fs,omitempty"`
	Reads  uint64 `json:"reads,omitempty"`
	Writes uint64 `json:"writes,omitempty"`
	Fsyncs uint64 `json:"fsyncs,omitempty"`
	WaitNs uint64 `json:"waitNs"`
	MaxNs  uint64 `json:"maxNs"`
	Bytes  uint64 `json:"bytes,omitempty"`
}

// Merge adds o into f.
func (f *FileStats) Merge(o *FileStats) {
	f.Reads += o.Reads
	f.Writes += o.Writes
	f.Fsyncs += o.Fsyncs
	f.WaitNs += o.WaitNs
	f.Bytes += o.Bytes
	if o.MaxNs > f.MaxNs {
		f.MaxNs = o.MaxNs
	}
	if f.FSType == "" {
		f.FSType = o.FSType
	}
}

// Ops returns the number of slow operations.
func (f *FileStats) Ops() uint64 { return f.Reads + f.Writes + f.Fsyncs }

// MaxDBQueries, MaxFiles and MaxHTTPEndpoints bound per-entity
// cardinality. Collectors enforce them per collection interval and Merge
// over time ranges; what does not fit is folded into an "(other)" entry.
const (
	MaxDBQueries     = 200
	MaxFiles         = 100
	MaxHTTPEndpoints = 200
)

// NetStats are TCP counters of a pod's network namespace (TcpExt, deltas).
type NetStats struct {
	ListenOverflows uint64 `json:"listenOverflows,omitempty"` // accept queue full
	ListenDrops     uint64 `json:"listenDrops,omitempty"`
	ZeroWindowDrops uint64 `json:"zeroWindowDrops,omitempty"` // dropped: our receive window was closed
	ToZeroWindowAdv uint64 `json:"toZeroWindowAdv,omitempty"` // we advertised a zero window (slow reader)
	RcvQueueDrops   uint64 `json:"rcvqDrops,omitempty"`
	BacklogDrops    uint64 `json:"backlogDrops,omitempty"`
	Timeouts        uint64 `json:"timeouts,omitempty"` // RTO timeouts
}

// Merge adds o into n.
func (n *NetStats) Merge(o *NetStats) {
	n.ListenOverflows += o.ListenOverflows
	n.ListenDrops += o.ListenDrops
	n.ZeroWindowDrops += o.ZeroWindowDrops
	n.ToZeroWindowAdv += o.ToZeroWindowAdv
	n.RcvQueueDrops += o.RcvQueueDrops
	n.BacklogDrops += o.BacklogDrops
	n.Timeouts += o.Timeouts
}

// Merge adds o into e.
func (e *EntityStats) Merge(o *EntityStats) {
	if o.SIP != nil {
		if e.SIP == nil {
			e.SIP = &SIPStats{}
		}
		e.SIP.Merge(o.SIP)
	}
	if o.RTP != nil {
		if e.RTP == nil {
			e.RTP = &RTPStats{}
		}
		e.RTP.Merge(o.RTP)
	}
	if e.PodUID == "" {
		e.PodUID = o.PodUID
	}
	if e.Cgroup == "" {
		e.Cgroup = o.Cgroup
	}
	if o.Sched != nil {
		if e.Sched == nil {
			e.Sched = &SchedStats{}
		}
		e.Sched.Merge(o.Sched)
	}
	if o.IO != nil {
		if e.IO == nil {
			e.IO = &IOStats{}
		}
		e.IO.Merge(o.IO)
	}
	if o.Res != nil {
		if e.Res == nil {
			e.Res = &Resources{}
		}
		e.Res.Merge(o.Res)
	}
	if o.DNS != nil {
		if e.DNS == nil {
			e.DNS = &DNSStats{}
		}
		e.DNS.Merge(o.DNS)
	}
	if o.DNSServer != nil {
		if e.DNSServer == nil {
			e.DNSServer = &DNSStats{}
		}
		e.DNSServer.Merge(o.DNSServer)
	}
	for k, v := range o.HTTP {
		if e.HTTP == nil {
			e.HTTP = map[string]*HTTPEndpoint{}
		}
		cur, ok := e.HTTP[k]
		if !ok && len(e.HTTP) >= MaxHTTPEndpoints {
			// the same "<role> <method> (other)" route the agent folds into
			k = v.Role + " " + v.Method + " (other)"
			if cur, ok = e.HTTP[k]; !ok {
				cur, ok = &HTTPEndpoint{Role: v.Role, Method: v.Method, Path: "(other)"}, true
				e.HTTP[k] = cur
			}
		}
		if ok {
			cur.Merge(v)
			continue
		}
		c := *v
		c.Status = copyMap(v.Status)
		c.Lat = Hist{}
		c.Lat.Add(v.Lat)
		e.HTTP[k] = &c
	}
	for k, v := range o.ConnErrors {
		if e.ConnErrors == nil {
			e.ConnErrors = map[string]uint64{}
		}
		e.ConnErrors[k] += v
	}
	if o.Net != nil {
		if e.Net == nil {
			e.Net = &NetStats{}
		}
		e.Net.Merge(o.Net)
	}
	for k, v := range o.DB {
		if e.DB == nil {
			e.DB = map[string]*DBQuery{}
		}
		cur, ok := e.DB[k]
		if !ok {
			if len(e.DB) >= MaxDBQueries {
				k = v.Proto + "|(other)"
				cur = e.DB[k]
			}
			if cur == nil {
				cur = &DBQuery{Proto: v.Proto, Query: v.Query}
				if len(e.DB) >= MaxDBQueries {
					cur.Query = "(other)"
				}
				e.DB[k] = cur
			}
		}
		cur.Merge(v)
	}
	for k, v := range o.Files {
		if e.Files == nil {
			e.Files = map[string]*FileStats{}
		}
		cur, ok := e.Files[k]
		if !ok {
			if len(e.Files) >= MaxFiles {
				k = "(other files)"
				cur = e.Files[k]
			}
			if cur == nil {
				cur = &FileStats{Path: v.Path}
				if len(e.Files) >= MaxFiles {
					cur.Path = k
				}
				e.Files[k] = cur
			}
		}
		cur.Merge(v)
	}
}

// SchedStats is the thread time breakdown of an entity.
type SchedStats struct {
	OnCPUNs      uint64            `json:"oncpuNs,omitempty"`
	OffNs        map[string]uint64 `json:"offNs,omitempty"`
	RunQ         Hist              `json:"runq"`
	ReclaimNs    uint64            `json:"reclaimNs,omitempty"`
	ReclaimCount uint64            `json:"reclaimCount,omitempty"`
	Wakeups      uint64            `json:"wakeups,omitempty"`
	// Culprits: entity ID -> nanoseconds of run queue delay it caused us.
	Culprits map[string]uint64 `json:"culprits,omitempty"`
}

// Merge adds o into s.
func (s *SchedStats) Merge(o *SchedStats) {
	s.OnCPUNs += o.OnCPUNs
	for k, v := range o.OffNs {
		if s.OffNs == nil {
			s.OffNs = map[string]uint64{}
		}
		s.OffNs[k] += v
	}
	s.RunQ.Add(o.RunQ)
	s.ReclaimNs += o.ReclaimNs
	s.ReclaimCount += o.ReclaimCount
	s.Wakeups += o.Wakeups
	for k, v := range o.Culprits {
		if s.Culprits == nil {
			s.Culprits = map[string]uint64{}
		}
		s.Culprits[k] += v
	}
}

// TotalNs returns total accounted thread time.
func (s *SchedStats) TotalNs() uint64 {
	t := s.OnCPUNs
	for _, v := range s.OffNs {
		t += v
	}
	return t
}

// IOStats is block I/O issued by an entity.
type IOStats struct {
	ReadBytes  uint64 `json:"readBytes,omitempty"`
	WriteBytes uint64 `json:"writeBytes,omitempty"`
	ReadOps    uint64 `json:"readOps,omitempty"`
	WriteOps   uint64 `json:"writeOps,omitempty"`
	Lat        Hist   `json:"lat"`
}

// Merge adds o into s.
func (s *IOStats) Merge(o *IOStats) {
	s.ReadBytes += o.ReadBytes
	s.WriteBytes += o.WriteBytes
	s.ReadOps += o.ReadOps
	s.WriteOps += o.WriteOps
	s.Lat.Add(o.Lat)
}

// Resources are cgroup filesystem statistics of a pod.
type Resources struct {
	// gauges (latest)
	MemCurrent    uint64    `json:"memCurrent,omitempty"`
	MemMax        uint64    `json:"memMax,omitempty"` // 0 = unlimited
	CPUQuotaMilli uint64    `json:"cpuQuotaMilli,omitempty"`
	PSICPU        float64   `json:"psiCpu,omitempty"` // "some" avg10 %
	PSIMem        float64   `json:"psiMem,omitempty"`
	PSIIO         float64   `json:"psiIo,omitempty"`
	SampledAt     time.Time `json:"sampledAt,omitempty"`
	// counters (deltas)
	CPUUsageUs  uint64 `json:"cpuUsageUs,omitempty"`
	Periods     uint64 `json:"periods,omitempty"`
	Throttled   uint64 `json:"throttled,omitempty"`
	ThrottledUs uint64 `json:"throttledUs,omitempty"`
	OOMKills    uint64 `json:"oomKills,omitempty"`
	WallUs      uint64 `json:"wallUs,omitempty"` // sampling wall time covered by the counters
	MemPeak     uint64 `json:"memPeak,omitempty"`
	// CPUPeakMilli is the highest CPU usage of any collection interval in
	// the range (max-merged, so minute rollups keep it for hours).
	CPUPeakMilli float64 `json:"cpuPeakMilli,omitempty"`
}

// Merge adds o into r (gauges take the latest sample).
func (r *Resources) Merge(o *Resources) {
	if !o.SampledAt.Before(r.SampledAt) {
		r.MemCurrent = o.MemCurrent
		r.MemMax = o.MemMax
		r.CPUQuotaMilli = o.CPUQuotaMilli
		r.PSICPU = o.PSICPU
		r.PSIMem = o.PSIMem
		r.PSIIO = o.PSIIO
		r.SampledAt = o.SampledAt
	}
	if o.CPUPeakMilli > r.CPUPeakMilli {
		r.CPUPeakMilli = o.CPUPeakMilli
	}
	if o.MemPeak > r.MemPeak {
		r.MemPeak = o.MemPeak
	}
	if o.MemCurrent > r.MemPeak {
		r.MemPeak = o.MemCurrent
	}
	r.CPUUsageUs += o.CPUUsageUs
	r.Periods += o.Periods
	r.Throttled += o.Throttled
	r.ThrottledUs += o.ThrottledUs
	r.OOMKills += o.OOMKills
	r.WallUs += o.WallUs
}

// DNSStats summarises DNS traffic of an entity (as a client or a server).
type DNSStats struct {
	Queries    uint64              `json:"queries,omitempty"`
	Responses  uint64              `json:"responses,omitempty"`
	Timeouts   uint64              `json:"timeouts,omitempty"`
	RCodes     map[string]uint64   `json:"rcodes,omitempty"`
	Lat        Hist                `json:"lat"`
	NdotsWaste uint64              `json:"ndotsWaste,omitempty"`
	Names      map[string]*DNSName `json:"names,omitempty"`
}

// DNSName is per query name statistics.
type DNSName struct {
	Count    uint64 `json:"count,omitempty"`
	NXDomain uint64 `json:"nx,omitempty"`
	Errors   uint64 `json:"err,omitempty"`
	Timeouts uint64 `json:"timeouts,omitempty"`
	LatSumUs uint64 `json:"latSumUs,omitempty"`
	Answered uint64 `json:"answered,omitempty"`
}

// MaxDNSNames bounds the number of distinct names tracked per entity.
const MaxDNSNames = 300

// Merge adds o into d.
func (d *DNSStats) Merge(o *DNSStats) {
	d.Queries += o.Queries
	d.Responses += o.Responses
	d.Timeouts += o.Timeouts
	d.NdotsWaste += o.NdotsWaste
	d.Lat.Add(o.Lat)
	for k, v := range o.RCodes {
		if d.RCodes == nil {
			d.RCodes = map[string]uint64{}
		}
		d.RCodes[k] += v
	}
	for k, v := range o.Names {
		if d.Names == nil {
			d.Names = map[string]*DNSName{}
		}
		cur, ok := d.Names[k]
		if !ok {
			if len(d.Names) >= MaxDNSNames {
				k = "(other)" // as Name() does: per-name failures still add up
				cur = d.Names[k]
			}
			if cur == nil {
				cur = &DNSName{}
				d.Names[k] = cur
			}
		}
		cur.Count += v.Count
		cur.NXDomain += v.NXDomain
		cur.Errors += v.Errors
		cur.Timeouts += v.Timeouts
		cur.LatSumUs += v.LatSumUs
		cur.Answered += v.Answered
	}
}

// Name returns (creating if needed and allowed) the stats for a name.
func (d *DNSStats) Name(n string) *DNSName {
	if d.Names == nil {
		d.Names = map[string]*DNSName{}
	}
	if v, ok := d.Names[n]; ok {
		return v
	}
	if len(d.Names) >= MaxDNSNames {
		n = "(other)"
		if v, ok := d.Names[n]; ok {
			return v
		}
	}
	v := &DNSName{}
	d.Names[n] = v
	return v
}

// HTTPEndpoint aggregates HTTP/1.x requests for one route.
type HTTPEndpoint struct {
	Role   string            `json:"role"` // client or server
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Count  uint64            `json:"count"`
	Status map[string]uint64 `json:"status,omitempty"` // "2xx" ... "5xx"
	Lat    Hist              `json:"lat"`
}

// Merge adds o into h.
func (h *HTTPEndpoint) Merge(o *HTTPEndpoint) {
	h.Count += o.Count
	h.Lat.Add(o.Lat)
	for k, v := range o.Status {
		if h.Status == nil {
			h.Status = map[string]uint64{}
		}
		h.Status[k] += v
	}
}

// Errors returns the number of 5xx responses.
func (h *HTTPEndpoint) Errors() uint64 { return h.Status["5xx"] }

// Drop is a count of dropped packets for a flow and reason.
type Drop struct {
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Port   uint16 `json:"port,omitempty"`
	Proto  string `json:"proto"`
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}

// DropKey identifies a Drop.
type DropKey struct {
	Src, Dst      string
	Port          uint16
	Proto, Reason string
}

// Key returns the identity of the drop.
func (d *Drop) Key() DropKey { return DropKey{d.Src, d.Dst, d.Port, d.Proto, d.Reason} }

// NodeStats are node-level health metrics.
type NodeStats struct {
	CPUs                  int     `json:"cpus,omitempty"`
	Load1                 float64 `json:"load1,omitempty"`
	ConntrackCount        uint64  `json:"conntrackCount,omitempty"`
	ConntrackMax          uint64  `json:"conntrackMax,omitempty"`
	ConntrackInsertFailed uint64  `json:"conntrackInsertFailed,omitempty"` // delta
	ConntrackDrop         uint64  `json:"conntrackDrop,omitempty"`         // delta
	ConntrackEarlyDrop    uint64  `json:"conntrackEarlyDrop,omitempty"`    // delta
	PSICPU                float64 `json:"psiCpu,omitempty"`
	PSIMem                float64 `json:"psiMem,omitempty"`
	PSIIO                 float64 `json:"psiIo,omitempty"`
	// network stack (deltas unless noted)
	NICs            map[string]*NICStats `json:"nics,omitempty"`
	SoftnetDropped  uint64               `json:"softnetDropped,omitempty"`  // input backlog full
	SoftnetSqueezed uint64               `json:"softnetSqueezed,omitempty"` // NAPI budget/time ran out
	NetRxTopShare   float64              `json:"netRxTopShare,omitempty"`   // gauge: share of NET_RX softirqs on the busiest CPU
	NetRxCPU        int                  `json:"netRxCpu,omitempty"`        // gauge: that CPU
	SampledAt       time.Time            `json:"sampledAt,omitempty"`
}

// Merge adds o into n (gauges take the latest sample).
func (n *NodeStats) Merge(o NodeStats) {
	if !o.SampledAt.Before(n.SampledAt) {
		n.CPUs = o.CPUs
		n.Load1 = o.Load1
		n.ConntrackCount = o.ConntrackCount
		n.ConntrackMax = o.ConntrackMax
		n.PSICPU = o.PSICPU
		n.PSIMem = o.PSIMem
		n.PSIIO = o.PSIIO
		n.SampledAt = o.SampledAt
	}
	n.ConntrackInsertFailed += o.ConntrackInsertFailed
	n.ConntrackDrop += o.ConntrackDrop
	n.ConntrackEarlyDrop += o.ConntrackEarlyDrop
	n.SoftnetDropped += o.SoftnetDropped
	n.SoftnetSqueezed += o.SoftnetSqueezed
	if o.NetRxTopShare > 0 {
		n.NetRxTopShare, n.NetRxCPU = o.NetRxTopShare, o.NetRxCPU
	}
	for name, s := range o.NICs {
		if n.NICs == nil {
			n.NICs = map[string]*NICStats{}
		}
		cur, ok := n.NICs[name]
		if !ok {
			cur = &NICStats{}
			n.NICs[name] = cur
		}
		cur.Add(s)
	}
}

// NICStats are interface counters (deltas).
type NICStats struct {
	RxBytes   uint64 `json:"rxBytes,omitempty"`
	TxBytes   uint64 `json:"txBytes,omitempty"`
	RxErrors  uint64 `json:"rxErrors,omitempty"`
	TxErrors  uint64 `json:"txErrors,omitempty"`
	RxDropped uint64 `json:"rxDropped,omitempty"`
	TxDropped uint64 `json:"txDropped,omitempty"`
	RxMissed  uint64 `json:"rxMissed,omitempty"` // ring buffer overflow
}

// Add adds o into s.
func (s *NICStats) Add(o *NICStats) {
	s.RxBytes += o.RxBytes
	s.TxBytes += o.TxBytes
	s.RxErrors += o.RxErrors
	s.TxErrors += o.TxErrors
	s.RxDropped += o.RxDropped
	s.TxDropped += o.TxDropped
	s.RxMissed += o.RxMissed
}

// Event types.
const (
	EvExec        = "exec"
	EvExecSession = "exec_session" // interactive exec into a container (kubectl exec -it)
	EvShell       = "suspicious_shell"
	EvExit        = "exit"
	EvSignal      = "signal"
	EvOOM         = "oom"
	EvListen      = "listen"
	EvConnect     = "connect"
	EvConnFail    = "conn_fail"
	EvDNSFail     = "dns_fail"
	EvDNSQuery    = "dns_query"
	EvHTTPError   = "http_5xx"
	EvRetrans     = "retrans"
	EvSIP         = "sip"
)

// Severities.
const (
	SevInfo = "info"
	SevWarn = "warn"
	SevCrit = "crit"
)

// Event is a notable occurrence attributed to an entity.
type Event struct {
	Time     time.Time         `json:"time"`
	Entity   string            `json:"entity"`
	Type     string            `json:"type"`
	Severity string            `json:"sev,omitempty"`
	PID      uint32            `json:"pid,omitempty"`
	Comm     string            `json:"comm,omitempty"`
	Message  string            `json:"msg"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// Listen is a listening socket owned by an entity.
type Listen struct {
	Entity string    `json:"entity"`
	Port   uint16    `json:"port"`
	Addr   string    `json:"addr"`
	Comm   string    `json:"comm,omitempty"`
	Time   time.Time `json:"time"`
}

// ResourceSample is one flight-recorder sample of an entity's resources.
type ResourceSample struct {
	Time         time.Time `json:"t"`
	MemCurrent   uint64    `json:"mem"`
	MemMax       uint64    `json:"memMax,omitempty"`
	CPUMilli     float64   `json:"cpuMilli"`
	ThrottledPct float64   `json:"throttledPct,omitempty"`
}

// CrashReport is a frozen flight recorder snapshot taken when a container
// died abnormally.
type CrashReport struct {
	Entity string           `json:"entity"`
	Time   time.Time        `json:"time"`
	Reason string           `json:"reason"`
	Events []Event          `json:"events"`
	Series []ResourceSample `json:"series,omitempty"`
}

// Startup is the timeline of the first moments of a new entity.
type Startup struct {
	Entity    string    `json:"entity"`
	FirstSeen time.Time `json:"firstSeen"`
	Events    []Event   `json:"events"`
}

// Profile is the result of an on-demand CPU profile.
type Profile struct {
	Entity   string        `json:"entity"`
	Node     string        `json:"node"`
	Duration time.Duration `json:"duration"`
	Hz       int           `json:"hz"`
	Samples  uint64        `json:"samples"`
	Stacks   []Stack       `json:"stacks"`
}

// Stack is a folded stack (root first) with its sample count.
type Stack struct {
	Comm   string   `json:"comm"`
	Frames []string `json:"frames"`
	Count  uint64   `json:"count"`
}

func copyMap(m map[string]uint64) map[string]uint64 {
	if m == nil {
		return nil
	}
	c := make(map[string]uint64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// SortedKeys returns map keys sorted by descending value.
func SortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] == m[keys[j]] {
			return keys[i] < keys[j]
		}
		return m[keys[i]] > m[keys[j]]
	})
	return keys
}

// Counters are hardware performance counters of an entity and of the
// whole node over the same interval (scaled for multiplexing).
type Counters struct {
	Entity           string        `json:"entity"`
	Node             string        `json:"node"`
	Duration         time.Duration `json:"duration"`
	Cycles           uint64        `json:"cycles"`
	Instructions     uint64        `json:"instructions"`
	CacheRefs        uint64        `json:"cacheRefs"`
	CacheMisses      uint64        `json:"cacheMisses"`
	NodeCycles       uint64        `json:"nodeCycles"`
	NodeInstructions uint64        `json:"nodeInstructions"`
	NodeCacheRefs    uint64        `json:"nodeCacheRefs"`
	NodeCacheMisses  uint64        `json:"nodeCacheMisses"`
}

func div(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// IPC is instructions per cycle of the entity (and of the node).
func (c *Counters) IPC() float64     { return div(c.Instructions, c.Cycles) }
func (c *Counters) NodeIPC() float64 { return div(c.NodeInstructions, c.NodeCycles) }

// MissRate is the share of cache references that missed.
func (c *Counters) MissRate() float64     { return div(c.CacheMisses, c.CacheRefs) }
func (c *Counters) NodeMissRate() float64 { return div(c.NodeCacheMisses, c.NodeCacheRefs) }
