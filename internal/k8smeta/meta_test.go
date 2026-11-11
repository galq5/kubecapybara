package k8smeta

import "testing"

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
