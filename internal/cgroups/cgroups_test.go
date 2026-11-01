package cgroups

import "testing"

func TestParsePath(t *testing.T) {
	cases := []struct {
		path, uid, cid, podPath string
	}{
		{
			"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod8b5a2c1e_1234_4abc_9def_0123456789ab.slice/cri-containerd-" + hex64 + ".scope",
			"8b5a2c1e-1234-4abc-9def-0123456789ab", hex64,
			"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod8b5a2c1e_1234_4abc_9def_0123456789ab.slice",
		},
		{
			"/kubepods/besteffort/pod8b5a2c1e-1234-4abc-9def-0123456789ab/" + hex64,
			"8b5a2c1e-1234-4abc-9def-0123456789ab", hex64,
			"/kubepods/besteffort/pod8b5a2c1e-1234-4abc-9def-0123456789ab",
		},
		{
			"/kubepods/besteffort/pod8b5a2c1e-1234-4abc-9def-0123456789ab",
			"8b5a2c1e-1234-4abc-9def-0123456789ab", "",
			"/kubepods/besteffort/pod8b5a2c1e-1234-4abc-9def-0123456789ab",
		},
		{"/system.slice/kubelet.service", "", "", ""},
	}
	for _, c := range cases {
		uid, cid, pp := ParsePath(c.path)
		if uid != c.uid || cid != c.cid || pp != c.podPath {
			t.Errorf("ParsePath(%q) = %q %q %q, want %q %q %q", c.path, uid, cid, pp, c.uid, c.cid, c.podPath)
		}
	}
	if e := EntityFor("/system.slice/kubelet.service"); e != "host:/system.slice/kubelet.service" {
		t.Errorf("EntityFor: %s", e)
	}
}

func TestHostPath(t *testing.T) {
	if p := HostPath("/../../../kubepods.slice/pod.slice/x.scope"); p != "/kubepods.slice/pod.slice/x.scope" {
		t.Fatal(p)
	}
	if p := HostPath("/system.slice/kubelet.service"); p != "/system.slice/kubelet.service" {
		t.Fatal(p)
	}
	if p := HostPath("/.."); p != "/" {
		t.Fatal(p)
	}
}

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
