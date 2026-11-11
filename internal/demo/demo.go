// Package demo builds a small synthetic cluster with a few typical problems
// (a noisy neighbour, a replica that was OOM killed, ndots waste, a slow
// database, a blocked connection, lossy voice calls). It backs the dashboard
// tests and the screenshots in docs/, so both can be reproduced without a
// cluster.
package demo

import (
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

// Cluster is the demo data: one snapshot per node for the current window,
// one per node for the baseline window before it, and the metadata.
type Cluster struct {
	From, To  time.Time
	Snapshots []*model.Snapshot
	Baseline  []*model.Snapshot
	Meta      *k8smeta.Meta
}

func hist(us uint64, n int) model.Hist {
	var h model.Hist
	for i := 0; i < n; i++ {
		h.Observe(us + uint64(i%7)*us/10)
	}
	return h
}

// New builds the demo cluster as observed over the minute before now.
func New(now time.Time) *Cluster {
	from, to := now.Add(-time.Minute), now
	c := &Cluster{From: from, To: to, Meta: meta(now)}
	c.Snapshots = snapshots(now, from, to, 60, true)
	c.Baseline = snapshots(now, from.Add(-time.Hour), from, 3600, false)
	return c
}

func meta(now time.Time) *k8smeta.Meta {
	pod := func(uid, ns, name, node, ip, app, kind, hash string, cpuReq, memReq, memLim int64) *k8smeta.Pod {
		p := &k8smeta.Pod{UID: uid, Namespace: ns, Name: name, Node: node, IP: ip,
			Labels: map[string]string{"app": app}, OwnerKind: kind, OwnerName: app,
			Workload: kind + "/" + app, Phase: "Running", Created: now.Add(-3 * time.Hour),
			Conditions: map[string]time.Time{"PodScheduled": now.Add(-3 * time.Hour), "Ready": now.Add(-3*time.Hour + 20*time.Second)},
			Containers: []k8smeta.Container{{Name: app, Image: "registry.example.com/" + app + ":1.4.2", Ports: []int32{8080}, Ready: true, State: "running",
				StartedAt: now.Add(-3*time.Hour + 5*time.Second), CPURequestMilli: cpuReq, MemRequest: memReq, MemLimit: memLim}}}
		if hash != "" {
			p.OwnerKind, p.OwnerName, p.TemplateHash, p.Workload = "ReplicaSet", app+"-"+hash, hash, "Deployment/"+app
			p.Labels["pod-template-hash"] = hash
		}
		return p
	}
	m := &k8smeta.Meta{ClusterDomain: "cluster.local",
		Pods: map[string]*k8smeta.Pod{
			"fe1":   pod("fe1", "shop", "frontend-6d4f7c9b8-x2kqp", "node-a", "10.0.1.10", "frontend", "", "6d4f7c9b8", 500, 512<<20, 1<<30),
			"fe2":   pod("fe2", "shop", "frontend-6d4f7c9b8-m9wzt", "node-b", "10.0.2.10", "frontend", "", "6d4f7c9b8", 500, 512<<20, 1<<30),
			"fe3":   pod("fe3", "shop", "frontend-6d4f7c9b8-p7hnc", "node-c", "10.0.3.10", "frontend", "", "6d4f7c9b8", 500, 512<<20, 1<<30),
			"pay1":  pod("pay1", "shop", "payments-7f9c5d6b4-abcde", "node-b", "10.0.2.20", "payments", "", "7f9c5d6b4", 2000, 2<<30, 4<<30),
			"pay2":  pod("pay2", "shop", "payments-7f9c5d6b4-fghij", "node-c", "10.0.3.20", "payments", "", "7f9c5d6b4", 2000, 2<<30, 4<<30),
			"pg1":   pod("pg1", "data", "postgres-0", "node-c", "10.0.3.30", "postgres", "StatefulSet", "", 1000, 4<<30, 4<<30),
			"fs1":   pod("fs1", "voice", "freeswitch-0", "node-a", "10.0.1.40", "freeswitch", "StatefulSet", "", 2000, 1<<30, 2<<30),
			"cart1": pod("cart1", "shop", "cart-5b8d7f6c9-t4wzn", "node-b", "10.0.2.30", "cart", "", "5b8d7f6c9", 200, 256<<20, 512<<20),
			"dns1":  pod("dns1", "kube-system", "coredns-5d78c9869d-8xk2p", "node-a", "10.0.1.2", "coredns", "", "5d78c9869d", 100, 70<<20, 170<<20),
		},
		Services: []*k8smeta.Service{
			{Namespace: "shop", Name: "payments", ClusterIPs: []string{"10.96.0.50"}, Selector: map[string]string{"app": "payments"}, Ports: []k8smeta.ServicePort{{Port: 80, TargetPort: "8080"}}},
			{Namespace: "data", Name: "postgres", ClusterIPs: []string{"10.96.0.60"}, Selector: map[string]string{"app": "postgres"}, Ports: []k8smeta.ServicePort{{Port: 5432, TargetPort: "5432"}}},
			{Namespace: "kube-system", Name: "kube-dns", ClusterIPs: []string{"10.96.0.10"}, Selector: map[string]string{"app": "coredns"}, Ports: []k8smeta.ServicePort{{Port: 53, TargetPort: "53"}}},
		},
		Nodes: map[string]*k8smeta.Node{
			"node-a": {Name: "node-a", IPs: []string{"192.168.0.1"}, Zone: "eu-west-1a"},
			"node-b": {Name: "node-b", IPs: []string{"192.168.0.2"}, Zone: "eu-west-1b"},
			"node-c": {Name: "node-c", IPs: []string{"192.168.0.3"}, Zone: "eu-west-1c"},
		},
		ReplicaSets: map[string]*k8smeta.ReplicaSet{
			"shop/frontend-6d4f7c9b8": {Namespace: "shop", Name: "frontend-6d4f7c9b8", Deployment: "frontend", Revision: "12", Hash: "6d4f7c9b8"},
			"shop/payments-7f9c5d6b4": {Namespace: "shop", Name: "payments-7f9c5d6b4", Deployment: "payments", Revision: "31", Hash: "7f9c5d6b4"},
			"shop/cart-5b8d7f6c9":     {Namespace: "shop", Name: "cart-5b8d7f6c9", Deployment: "cart", Revision: "1", Hash: "5b8d7f6c9", Created: now.Add(-58 * time.Second)},
		},
		Deployments: map[string]*k8smeta.Deployment{
			"shop/frontend": {Namespace: "shop", Name: "frontend"}, "shop/payments": {Namespace: "shop", Name: "payments"},
		},
	}
	m.Pods["dns1"].Labels["k8s-app"] = "kube-dns"
	m.Pods["dns1"].Containers[0].Ports = []int32{53}
	m.Pods["pg1"].Containers[0].Ports = []int32{5432}
	m.Pods["fs1"].Containers[0].Ports = []int32{5060}
	// cart was rolled out a minute ago: its startup is traced
	cart := m.Pods["cart1"]
	cart.Created = now.Add(-58 * time.Second)
	cart.Conditions = map[string]time.Time{"PodScheduled": now.Add(-57 * time.Second), "Initialized": now.Add(-56 * time.Second), "Ready": now.Add(-21 * time.Second)}
	cart.Containers[0].StartedAt = now.Add(-49 * time.Second)
	cart.Containers[0].Probes = []k8smeta.Probe{{Kind: "readiness", Type: "http", Port: 8080, Path: "/healthz", Period: 10, Delay: 15}}
	// the bad payments replica restarted a minute ago
	bad := &m.Pods["pay2"].Containers[0]
	bad.Restarts, bad.LastReason, bad.LastExitCode, bad.LastFinished = 3, "OOMKilled", 137, now.Add(-25*time.Second)
	m.Index()
	return m
}

// snapshots builds one snapshot per node for a window of secs seconds.
// With live set it carries the events, crash report, samples and listeners
// of a full snapshot; the baseline is healthy and carries metrics only.
func snapshots(now, from, to time.Time, secs uint64, live bool) []*model.Snapshot {
	scale := secs / 60 // counters grow with the window
	ent := func(id string, cores float64, mem, memMax uint64) *model.EntityStats {
		cpuNs := uint64(cores * float64(secs) * 1e9)
		return &model.EntityStats{ID: id,
			Sched: &model.SchedStats{OnCPUNs: cpuNs, OffNs: map[string]uint64{model.StateRunQ: cpuNs / 25, model.StateNet: 40e9 * scale, model.StatePoll: 100e9 * scale, model.StateLock: 30e9 * scale},
				RunQ: hist(300, 200), Wakeups: 5000 * scale},
			Res: &model.Resources{MemCurrent: mem, MemMax: memMax, MemPeak: mem, CPUUsageUs: cpuNs / 1000, WallUs: secs * 1e6, Periods: 10 * secs, Throttled: secs / 2,
				ThrottledUs: 30000 * secs, SampledAt: to, CPUQuotaMilli: 2000, CPUPeakMilli: cores * 1000 * 1.6, PSICPU: 1.2}}
	}
	series := func(base, grow, limit uint64, cpu float64) []model.ResourceSample {
		var s []model.ResourceSample
		for i := 0; i < 30; i++ {
			s = append(s, model.ResourceSample{Time: now.Add(time.Duration(i-30) * 5 * time.Second), MemCurrent: base + uint64(i)*grow, MemMax: limit,
				CPUMilli: cpu * (0.7 + float64((i*37)%60)/100)})
		}
		return s
	}
	frontend := func(id string) *model.EntityStats {
		e := ent(id, 0.15, 300<<20, 1<<30)
		q := 400 * scale
		e.DNS = &model.DNSStats{Queries: q, Responses: q - 4*scale, Timeouts: 4 * scale, NdotsWaste: 180 * scale,
			RCodes: map[string]uint64{"NXDOMAIN": 180 * scale, "NOERROR": 210 * scale, "SERVFAIL": 6 * scale}, Lat: hist(900, 396),
			Names: map[string]*model.DNSName{
				"api.stripe.com.shop.svc.cluster.local": {Count: 90 * scale, NXDomain: 90 * scale},
				"api.stripe.com.svc.cluster.local":      {Count: 90 * scale, NXDomain: 90 * scale},
				"payments.shop.svc.cluster.local":       {Count: 130 * scale, Answered: 130 * scale, LatSumUs: 130 * scale * 700},
				"api.stripe.com":                        {Count: 90 * scale, Answered: 84 * scale, Errors: 6 * scale, LatSumUs: 84 * scale * 9000}}}
		e.HTTP = map[string]*model.HTTPEndpoint{
			"server GET /products/:id": {Role: "server", Method: "GET", Path: "/products/:id", Count: 6000 * scale, Status: map[string]uint64{"2xx": 5990 * scale, "4xx": 10 * scale}, Lat: hist(12000, 500)},
			"server POST /checkout":    {Role: "server", Method: "POST", Path: "/checkout", Count: 900 * scale, Status: map[string]uint64{"2xx": 900 * scale}, Lat: hist(60000, 300)},
			"client POST /charge":      {Role: "client", Method: "POST", Path: "/charge", Count: 900 * scale, Status: map[string]uint64{"2xx": 900 * scale}, Lat: hist(45000, 300)}}
		if live {
			e.HTTP["server POST /checkout"].Status = map[string]uint64{"2xx": 840 * scale, "5xx": 60 * scale}
			e.HTTP["server POST /checkout"].Lat = hist(180000, 300)
			e.HTTP["client POST /charge"].Status = map[string]uint64{"2xx": 840 * scale, "5xx": 60 * scale}
			e.HTTP["client POST /charge"].Lat = hist(150000, 300)
		}
		return e
	}
	payments := func(id string, bad bool) *model.EntityStats {
		e := ent(id, 0.65, 2900<<20, 4<<30)
		lat, errs := uint64(30000), uint64(5)*scale
		if bad {
			lat, errs = 900000, 190*scale
			e.Sched.OffNs[model.StateRunQ] = 20e9 * scale
			e.Sched.RunQ = hist(60000, 300)
			e.Sched.Culprits = map[string]uint64{"pod:pg1": 12e9 * scale}
			e.Res.Throttled = 4 * secs
			e.Res.MemCurrent, e.Res.MemPeak = 1200<<20, 4090<<20
		}
		e.HTTP = map[string]*model.HTTPEndpoint{"server POST /charge": {Role: "server", Method: "POST", Path: "/charge", Count: 1350 * scale,
			Status: map[string]uint64{"2xx": 1350*scale - errs, "5xx": errs}, Lat: hist(lat, 400)}}
		upd := hist(9000, 300)
		var updErr uint64
		if bad {
			upd, updErr = hist(700000, 300), 40*scale
		}
		e.DB = map[string]*model.DBQuery{
			"postgres|SELECT * FROM orders WHERE id = ?":            {Proto: "postgres", Query: "SELECT * FROM orders WHERE id = ?", Count: 4000 * scale, Lat: hist(2500, 400)},
			"postgres|UPDATE accounts SET balance = ? WHERE id = ?": {Proto: "postgres", Query: "UPDATE accounts SET balance = ? WHERE id = ?", Count: 1300 * scale, Errors: updErr, Lat: upd},
			"redis|GET": {Proto: "redis", Query: "GET", Count: 9000 * scale, Lat: hist(300, 500)}}
		return e
	}
	pair := func(c, s string, port uint16, side, owner string, rtt, conn, n, tx, rx uint64) *model.Pair {
		p := &model.Pair{Client: c, Server: s, Port: port, Side: side, Owner: owner, RTT: hist(rtt, 200), Connects: n * scale, Closes: n * scale,
			LifetimeUs: n * scale * 4e6, BytesTx: tx * scale, BytesRx: rx * scale, OpenConns: 20, IdleConns: 4}
		if side == "client" && n > 0 {
			p.Connect = hist(conn, int(n))
		}
		return p
	}
	node := func(load float64, conntrack uint64) model.NodeStats {
		return model.NodeStats{CPUs: 8, Load1: load, ConntrackCount: conntrack, ConntrackMax: 262144, PSICPU: load, PSIMem: 0.4, PSIIO: 1.1, SampledAt: to,
			NICs: map[string]*model.NICStats{"eth0": {RxBytes: (90 << 20) * secs, TxBytes: (70 << 20) * secs}}}
	}
	collectors := map[string]string{"net": "ok", "dns": "ok", "sched": "ok", "io": "ok", "proc": "ok", "drops": "ok", "cgroupfs": "ok",
		"netstat": "ok", "node": "ok", "profile": "ok", "http": "ok", "files": "ok", "voip": "ok"}

	pg := ent("pod:pg1", 1.9, 3000<<20, 4<<30)
	pg.IO = &model.IOStats{ReadBytes: (15 << 20) * secs, WriteBytes: (35 << 20) * secs, ReadOps: 150 * secs, WriteOps: 500 * secs, Lat: hist(4000, 400)}
	dns := ent("pod:dns1", 0.03, 60<<20, 170<<20)
	dns.DNSServer = &model.DNSStats{Queries: 1200 * scale, Responses: 1190 * scale, Lat: hist(400, 1190),
		RCodes: map[string]uint64{"NOERROR": 630 * scale, "NXDOMAIN": 540 * scale, "SERVFAIL": 20 * scale}}
	voice := ent("pod:fs1", 0.9, 700<<20, 2<<30)
	voice.SIP = &model.SIPStats{CallsActive: 57, CallsEnded: 40 * scale, CallSeconds: 40 * scale * 134, UserAgent: "FreeSWITCH-mod_sofia/1.10.11",
		Methods: map[string]*model.SIPMethod{
			"uas INVITE": {Method: "INVITE", Role: "uas", Requests: 60 * scale, Retrans: 2 * scale, Codes: map[string]uint64{"180": 50 * scale, "200": 44 * scale, "486": 9 * scale, "503": 7 * scale},
				FirstResp: hist(1200, 60), Ringing: hist(2100000, 50), Final: hist(6000000, 60)},
			"uac INVITE": {Method: "INVITE", Role: "uac", Requests: 60 * scale, Retrans: 1 * scale, Timeouts: 1 * scale, Codes: map[string]uint64{"180": 50 * scale, "200": 44 * scale, "486": 9 * scale, "503": 6 * scale},
				FirstResp: hist(40000, 59), Ringing: hist(1900000, 50), Final: hist(5800000, 59)},
			"uas BYE": {Method: "BYE", Role: "uas", Requests: 40 * scale, Codes: map[string]uint64{"200": 40 * scale}, FirstResp: hist(900, 40), Final: hist(900, 40)}}}
	loss := uint64(40)
	if live {
		loss = 2100
	}
	voice.RTP = &model.RTPStats{PacketsIn: 170000 * scale, PacketsOut: 171000 * scale, Expected: 171000 * scale, Lost: loss * scale, OutOfOrder: 30 * scale,
		StreamsIn: 57, StreamsOut: 57, OneWay: 1, Jitter: hist(6100, 600), JitterMaxUs: 48000,
		Streams: []*model.RTPStream{
			{SSRC: 0x5a17c3e1, Dir: "in", Peer: "203.0.113.7", PeerPort: 31544, LocalPort: 17320, Codec: "PCMA", Packets: 3000 * scale, Expected: 3000 * scale, Lost: 294 * scale, JitterUs: 31000, JitterMaxUs: 48000},
			{SSRC: 0x19be0042, Dir: "out", Peer: "198.51.100.23", PeerPort: 20110, LocalPort: 17340, Codec: "opus", Packets: 3000 * scale, OneWay: true}}}

	a := &model.Snapshot{Node: "node-a", From: from, To: to, Collectors: collectors, NodeStats: node(2.1, 40000),
		Pairs: []*model.Pair{
			pair("10.0.1.10", "10.96.0.50", 80, "client", "pod:fe1", 900, 1500, 300, 30<<20, 90<<20),
			pair("10.0.1.10", "52.94.1.7", 443, "client", "pod:fe1", 24000, 60000, 40, 2<<20, 9<<20)},
		Entities: map[string]*model.EntityStats{"pod:fe1": frontend("pod:fe1"), "pod:dns1": dns, "pod:fs1": voice,
			"host:/system.slice/kubelet.service": ent("host:/system.slice/kubelet.service", 0.05, 0, 0)}}
	b := &model.Snapshot{Node: "node-b", From: from, To: to, Collectors: collectors, NodeStats: node(3.4, 230000),
		Pairs: []*model.Pair{
			pair("10.0.1.10", "10.0.2.20", 8080, "server", "pod:pay1", 900, 0, 150, 90<<20, 30<<20),
			pair("10.0.2.10", "10.96.0.50", 80, "client", "pod:fe2", 400, 800, 300, 30<<20, 90<<20),
			pair("10.0.2.10", "10.0.2.20", 8080, "server", "pod:pay1", 300, 0, 280, 90<<20, 30<<20),
			pair("10.0.2.20", "10.96.0.60", 5432, "client", "pod:pay1", 1200, 2500, 20, 400<<20, 900<<20)},
		Entities: map[string]*model.EntityStats{"pod:fe2": frontend("pod:fe2"), "pod:pay1": payments("pod:pay1", false)}}
	slow := pair("10.0.3.20", "10.96.0.60", 5432, "client", "pod:pay2", 1100, 2400, 20, 400<<20, 900<<20)
	if live {
		slow = pair("10.0.3.20", "10.96.0.60", 5432, "client", "pod:pay2", 45000, 120000, 900, 400<<20, 900<<20)
		slow.Retrans, slow.Refused, slow.Timeouts, slow.LifetimeUs = 900, 14, 6, 900*400000
	}
	c := &model.Snapshot{Node: "node-c", From: from, To: to, Collectors: collectors, NodeStats: node(11.5, 90000),
		Pairs: []*model.Pair{
			pair("10.0.3.10", "10.96.0.50", 80, "client", "pod:fe3", 700, 900, 300, 30<<20, 90<<20),
			pair("10.0.3.10", "10.0.3.20", 8080, "server", "pod:pay2", 300, 0, 20, 4<<20, 2<<20),
			pair("10.0.2.20", "10.0.3.30", 5432, "server", "pod:pg1", 1200, 0, 20, 900<<20, 400<<20),
			pair("10.0.3.20", "10.0.3.30", 5432, "server", "pod:pg1", 300, 0, 20, 900<<20, 400<<20), slow},
		Entities: map[string]*model.EntityStats{"pod:fe3": frontend("pod:fe3"), "pod:pay2": payments("pod:pay2", live), "pod:pg1": pg}}
	if !live {
		return []*model.Snapshot{a, b, c}
	}

	// what only the live window has
	pg.IO.Lat = hist(70000, 400)
	pg.Res.MemCurrent = 3906 << 20
	pg.Files = map[string]*model.FileStats{"/var/lib/postgresql/data/pg_wal/000000010000000000000042": {
		Path: "/var/lib/postgresql/data/pg_wal/000000010000000000000042", FSType: "ext4", Fsyncs: 800, WaitNs: 22e9, MaxNs: 900e6}}
	pg.Net = &model.NetStats{ListenOverflows: 12, ListenDrops: 12}
	a.DNSNames = map[string]string{"52.94.1.7": "api.stripe.com"}
	a.Series = map[string][]model.ResourceSample{"pod:fe1": series(280<<20, 0, 1<<30, 150), "pod:fs1": series(690<<20, 0, 2<<30, 900)}
	a.Listens = []model.Listen{{Entity: "pod:fe1", Port: 8080, Addr: "0.0.0.0", Comm: "frontend"}, {Entity: "pod:fe1", Port: 6060, Addr: "0.0.0.0", Comm: "frontend"},
		{Entity: "pod:fs1", Port: 5060, Addr: "0.0.0.0", Comm: "freeswitch"}}
	a.Events = []model.Event{
		{Time: now.Add(-50 * time.Second), Entity: "pod:fe1", Type: model.EvDNSFail, Severity: model.SevWarn, Message: "DNS A api.stripe.com -> SERVFAIL (9ms)"},
		{Time: now.Add(-40 * time.Second), Entity: "pod:fe1", Type: model.EvExecSession, Severity: model.SevWarn, Message: "interactive exec session: /bin/sh (uid 0)"},
		{Time: now.Add(-35 * time.Second), Entity: "pod:fe1", Type: model.EvExec, Message: "exec curl -s http://payments/health", Fields: map[string]string{"args": "curl -s http://payments/health"}},
		{Time: now.Add(-12 * time.Second), Entity: "pod:fs1", Type: model.EvSIP, Severity: model.SevWarn, Message: "SIP INVITE sip:+4930555010@carrier.example.net to 198.51.100.23 failed: 503 Service Unavailable after 41ms"}}
	a.Drops = []*model.Drop{{Src: "10.0.1.10", Dst: "10.0.3.30", Port: 5432, Proto: "tcp", Reason: "NETFILTER_DROP", Count: 240}}
	b.Series = map[string][]model.ResourceSample{"pod:pay1": series(2800<<20, 3<<20, 4<<30, 650)}
	b.Events = []model.Event{{Time: now.Add(-20 * time.Second), Entity: "pod:pay1", Type: model.EvHTTPError, Severity: model.SevWarn, Message: "HTTP 500 for POST /charge (server, 31ms)"}}
	c.Series = map[string][]model.ResourceSample{"pod:pg1": series(3500<<20, 14<<20, 4<<30, 1900), "pod:pay2": series(1000<<20, 7<<20, 4<<30, 650)}
	oom := model.Event{Time: now.Add(-26 * time.Second), Entity: "pod:pay2", Type: model.EvOOM, Severity: model.SevCrit,
		Message: "OOM killer selected pid 4242 (anon-rss 3.9GiB, file-rss 12.0MiB, total-vm 6.1GiB)"}
	exit := model.Event{Time: now.Add(-25 * time.Second), Entity: "pod:pay2", Type: model.EvExit, Severity: model.SevCrit,
		Message: "container main process: payments (pid 4242) killed by SIGKILL"}
	c.Events = []model.Event{oom, exit,
		{Time: now.Add(-22 * time.Second), Entity: "pod:pay2", Type: model.EvListen, Message: "listening on 0.0.0.0:8080"}}
	c.Crashes = []model.CrashReport{{Entity: "pod:pay2", Time: exit.Time, Reason: "container main process: payments (pid 4242) killed by SIGKILL; OOM killed",
		Events: []model.Event{
			{Time: now.Add(-70 * time.Second), Entity: "pod:pay2", Type: model.EvConnFail, Severity: model.SevWarn, Message: "connect to 10.96.0.60:5432 timed out after 3.01s"},
			oom, exit},
		Series: series(3300<<20, 26<<20, 4<<30, 700)}}
	b.Entities["pod:cart1"] = ent("pod:cart1", 0.04, 90<<20, 512<<20)
	b.Listens = []model.Listen{{Entity: "pod:cart1", Port: 8080, Addr: "0.0.0.0", Comm: "cart"}}
	b.Startups = []model.Startup{{Entity: "pod:cart1", FirstSeen: now.Add(-49 * time.Second), Events: []model.Event{
		{Time: now.Add(-49 * time.Second), Type: model.EvExec, Message: "exec /app/cart --config /etc/cart.yaml"},
		{Time: now.Add(-48500 * time.Millisecond), Type: model.EvDNSFail, Severity: model.SevWarn, Message: "DNS A redis.shop -> NXDOMAIN (2ms)"},
		{Time: now.Add(-48400 * time.Millisecond), Type: model.EvDNSQuery, Message: "DNS A redis.shop.svc.cluster.local -> NOERROR in 1.2ms", Fields: map[string]string{"latencyUs": "1200"}},
		{Time: now.Add(-48 * time.Second), Type: model.EvConnFail, Severity: model.SevWarn, Message: "connect to 10.96.0.70:6379 refused after 310µs"},
		{Time: now.Add(-45 * time.Second), Type: model.EvConnect, Message: "connected to 10.96.0.70:6379 in 420µs"},
		{Time: now.Add(-44 * time.Second), Type: model.EvListen, Message: "listening on 0.0.0.0:8080"}}}}
	return []*model.Snapshot{a, b, c}
}
