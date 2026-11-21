package k8smeta

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestWorkloadOfJobs(t *testing.T) {
	for owner, want := range map[string]string{
		"backup-28391040": "CronJob/backup",      // <cronjob>-<scheduled time in minutes>
		"import-customer": "Job/import-customer", // 8 letters after the dash: a plain Job
		"db-migrate":      "Job/db-migrate",
		"report-2839104x": "Job/report-2839104x",
	} {
		if got := workloadOf(&Pod{OwnerKind: "Job", OwnerName: owner}); got != want {
			t.Errorf("workloadOf(Job %s) = %s, want %s", owner, got, want)
		}
	}
}

// A native sidecar (init container with restartPolicy Always) runs for the
// life of the pod: its requests are part of what the pod uses, unlike
// those of an init container that has finished.
func TestNativeSidecarsCountInRequests(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	res := func(cpu, mem string) corev1.ResourceRequirements {
		return corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(cpu), corev1.ResourceMemory: resource.MustParse(mem)}}
	}
	p := convertPod(&corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{
			{Name: "migrate", Resources: res("500m", "256Mi")},
			{Name: "proxy", RestartPolicy: &always, Resources: res("100m", "128Mi")},
		},
		Containers: []corev1.Container{{Name: "app", Resources: res("200m", "512Mi")}},
	}})
	if cpu, _, mem, _ := p.Requests(); cpu != 300 || mem != (512+128)<<20 {
		t.Errorf("requests %dm / %dMi, want 300m / 640Mi (app + native sidecar)", cpu, mem>>20)
	}
	if c := p.Containers; !c[0].Init || c[1].Init || !c[1].Sidecar || c[2].Init || c[2].Sidecar {
		t.Errorf("container kinds: %+v", c)
	}
}
