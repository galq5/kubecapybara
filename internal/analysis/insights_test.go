package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/galq5/kubecapybara/internal/k8smeta"
	"github.com/galq5/kubecapybara/internal/model"
)

func TestRightsize(t *testing.T) {
	snaps, meta := fixture(t)
	// payments requests 2 CPU / 2Gi per pod but uses ~100m / 200Mi
	for _, p := range meta.Pods {
		if strings.HasPrefix(p.Name, "payments") {
			p.Containers[0].CPURequestMilli = 2000
			p.Containers[0].MemRequest = 2 << 30
			p.Containers[0].MemLimit = 4 << 30
		}
	}
	now := time.Now()
	for _, uid := range []string{"pay-old", "pay-new"} {
		snaps[1].Entities["pod:"+uid].Res = &model.Resources{MemCurrent: 200 << 20, MemMax: 4 << 30, CPUUsageUs: 6e6, WallUs: 60e6, SampledAt: now}
		snaps[1].Series = map[string][]model.ResourceSample{}
	}
	snaps[1].Series["pod:pay-new"] = []model.ResourceSample{{Time: now, CPUMilli: 150, MemCurrent: 210 << 20}}
	v := Build(snaps, meta, Options{})
	rows := Rightsize(v, DefaultPricing)
	var pay *RightsizeRow
	for i := range rows {
		if rows[i].Workload == "shop/Deployment/payments" {
			pay = &rows[i]
		}
	}
	if pay == nil {
		t.Fatalf("no payments row: %+v", rows)
	}
	if pay.Verdict != "over" || pay.CPURec != 180 || pay.MonthlyUSD < 50 || !pay.PeakKnown {
		t.Fatalf("unexpected recommendation: %+v", *pay)
	}
}

func TestOOMRisk(t *testing.T) {
	snaps, meta := fixture(t)
	now := time.Now()
	var ser []model.ResourceSample
	for i := 0; i < 30; i++ { // 10MiB per 5s towards a 1GiB limit
		ser = append(ser, model.ResourceSample{Time: now.Add(time.Duration(i-30) * 5 * time.Second), MemCurrent: uint64(500<<20 + i*(10<<20)), MemMax: 1 << 30})
	}
	snaps[1].Series = map[string][]model.ResourceSample{"pod:pay-new": ser}
	v := Build(snaps, meta, Options{})
	risks := OOMRisks(v)
	if len(risks) != 1 || risks[0].Endpoint.Name != "payments-new" {
		t.Fatalf("risks: %+v", risks)
	}
	// left ≈ 1024-790 = 234MiB at 2MiB/s → ~117s
	if eta := risks[0].ETA; eta < 90*time.Second || eta > 150*time.Second {
		t.Fatalf("eta %s", eta)
	}
	var found bool
	for _, f := range Doctor(v, nil) {
		if strings.Contains(f.Title, "will hit its memory limit") && f.Severity == SevCrit {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a CRIT OOM finding")
	}
}

func TestPolicyDenials(t *testing.T) {
	snaps, meta := fixture(t)
	snaps[0].Drops = []*model.Drop{
		{Src: "10.0.1.10", Dst: "10.0.2.21", Port: 5432, Proto: "tcp", Reason: "NETFILTER_DROP", Count: 7},
		{Src: "10.0.1.10", Dst: "10.0.2.21", Port: 80, Proto: "tcp", Reason: "QUEUE_PURGE", Count: 99},
	}
	v := Build(snaps, meta, Options{})
	ds := PolicyDenials(v)
	if len(ds) != 1 || ds[0].Src.Name != "frontend-abc" || ds[0].Dst.Name != "payments-new" || ds[0].Count != 7 {
		t.Fatalf("denials: %+v", ds)
	}
}

func TestNodeMatrixSlowNode(t *testing.T) {
	meta := &k8smeta.Meta{Pods: map[string]*k8smeta.Pod{}, Nodes: map[string]*k8smeta.Node{}}
	ips := map[string]string{}
	for i, n := range []string{"n1", "n2", "n3", "n4"} {
		uid := "p" + n
		ip := "10.0.0." + string(rune('1'+i))
		ips[n] = ip
		meta.Pods[uid] = &k8smeta.Pod{UID: uid, Namespace: "x", Name: uid, Node: n, IP: ip, Phase: "Running", Workload: "Pod/" + uid}
		meta.Nodes[n] = &k8smeta.Node{Name: n}
	}
	meta.Index()
	snap := &model.Snapshot{Node: "n1", From: time.Now().Add(-time.Minute), To: time.Now()}
	nodes := []string{"n1", "n2", "n3", "n4"}
	for _, a := range nodes {
		for _, b := range nodes {
			if a == b {
				continue
			}
			rtt := uint64(300)
			if a == "n4" || b == "n4" {
				rtt = 9000 // bad NIC on n4
			}
			snap.Pairs = append(snap.Pairs, &model.Pair{Client: ips[a], Server: ips[b], Port: 80, Side: "client", Owner: "pod:p" + a, RTT: hist(rtt, 20)})
		}
	}
	v := Build([]*model.Snapshot{snap}, meta, Options{})
	slow := BuildNodeMatrix(v).SlowNodes()
	if _, ok := slow["n4"]; !ok || len(slow) != 1 {
		t.Fatalf("slow nodes: %v", slow)
	}
}

func TestServiceBalance(t *testing.T) {
	snaps, meta := fixture(t)
	snaps[1].Pairs[0].Connects = 950 // pay-old
	snaps[1].Pairs[1].Connects = 50  // pay-new
	v := Build(snaps, meta, Options{})
	sbs := ServiceBalances(v)
	if len(sbs) != 1 || sbs[0].Imbalance < 1.8 || sbs[0].Backends[0].Pod.Name != "payments-old" {
		t.Fatalf("balance: %+v", sbs)
	}
}

func TestAddPodEvents(t *testing.T) {
	snaps, meta := fixture(t)
	v := Build(snaps, meta, Options{})
	pod := meta.Pods["pay-new"]
	rep := Startup(v, pod)
	t0 := pod.Created
	AddPodEvents(rep, []k8smeta.PodEvent{
		{Reason: "Scheduled", Message: "Successfully assigned", First: t0.Add(time.Second)},
		{Reason: "Pulling", Message: "Pulling image app:v2", First: t0.Add(4 * time.Second)},
		{Reason: "Pulled", Message: `Successfully pulled image "app:v2" in 41.5s (41.5s including waiting)`, First: t0.Add(46 * time.Second), Last: t0.Add(46 * time.Second)},
	})
	var pull, sandbox time.Duration
	for _, p := range rep.Phases {
		switch {
		case p.Name == "image pull":
			pull = p.Duration
		case strings.HasPrefix(p.Name, "sandbox"):
			sandbox = p.Duration
		}
	}
	if pull != 41500*time.Millisecond || sandbox != 3*time.Second {
		t.Fatalf("phases: %+v", rep.Phases)
	}
	if !strings.Contains(strings.Join(rep.Advice, "\n"), "image pulls took") {
		t.Fatalf("advice: %v", rep.Advice)
	}
}

func TestRightsizeNoCPUData(t *testing.T) {
	snaps, meta := fixture(t)
	meta.Pods["fe-1"].Containers = []k8smeta.Container{{Name: "app", CPURequestMilli: 2000}}
	// frontend only has DNS stats: no CPU measurement at all
	v := Build(snaps, meta, Options{})
	for _, r := range Rightsize(v, DefaultPricing) {
		if r.Workload == "shop/Deployment/frontend" {
			if r.Verdict != "no-data" || r.CPURec != 0 || r.MonthlyUSD != 0 {
				t.Fatalf("pod without CPU data got a recommendation: %+v", r)
			}
			return
		}
	}
	t.Fatal("frontend row missing")
}

func TestRightsizeUsesWindowPeak(t *testing.T) {
	snaps, meta := fixture(t)
	meta.Pods["pay-new"].Containers[0].CPURequestMilli = 2000
	meta.Pods["pay-old"].Containers[0].CPURequestMilli = 2000
	// a burst an hour ago survives in the rolled-up peak, not in the 10 minute series
	snaps[1].Entities["pod:pay-new"].Res = &model.Resources{CPUUsageUs: 3e6, WallUs: 60e6, CPUPeakMilli: 1500}
	v := Build(snaps, meta, Options{})
	for _, r := range Rightsize(v, DefaultPricing) {
		if r.Workload == "shop/Deployment/payments" {
			if r.CPUPeak != 1500 || r.CPURec != 1800 || r.Verdict == "over" {
				t.Fatalf("window peak ignored: %+v", r)
			}
			return
		}
	}
	t.Fatal("payments row missing")
}

func TestSlowNodeThreeNodes(t *testing.T) {
	m := NodeMatrix{Nodes: []string{"w1", "w2", "w3"}, RTT: map[string]map[string]*model.Hist{}}
	set := func(a, b string, us uint64) {
		if m.RTT[a] == nil {
			m.RTT[a] = map[string]*model.Hist{}
		}
		h := hist(us, 20)
		m.RTT[a][b] = &h
	}
	set("w1", "w2", 300)
	set("w1", "w3", 9000)
	set("w2", "w3", 9000)
	slow := m.SlowNodes()
	if _, ok := slow["w3"]; !ok || len(slow) != 1 {
		t.Fatalf("expected only w3 to be slow, got %v", slow)
	}
}

func TestServiceBalanceIgnoresTinyTraffic(t *testing.T) {
	snaps, meta := fixture(t)
	snaps[1].Pairs[0].Connects, snaps[1].Pairs[0].BytesTx, snaps[1].Pairs[0].BytesRx = 1, 200, 0
	snaps[1].Pairs[1].Connects, snaps[1].Pairs[1].BytesTx, snaps[1].Pairs[1].BytesRx = 0, 0, 0
	snaps[0].Pairs = nil
	v := Build(snaps, meta, Options{})
	if sbs := ServiceBalances(v); len(sbs) != 0 {
		t.Fatalf("200 bytes must not be judged: %+v", sbs)
	}
}

func TestMergeFoldsOverflowIntoOther(t *testing.T) {
	e := &model.EntityStats{}
	for i := 0; i < model.MaxDBQueries+5; i++ {
		e.Merge(&model.EntityStats{DB: map[string]*model.DBQuery{
			"2|q" + string(rune('A'+i%26)) + string(rune('a'+i/26)): {Proto: "postgres", Query: "q", Count: 1},
		}})
	}
	var total uint64
	for _, q := range e.DB {
		total += q.Count
	}
	if total != model.MaxDBQueries+5 || len(e.DB) > model.MaxDBQueries+1 {
		t.Fatalf("lost data on merge: total %d, %d keys", total, len(e.DB))
	}
}
