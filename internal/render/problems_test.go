package render

import (
	"github.com/galq5/kubecapybara/internal/analysis"
	"testing"
)

func TestProblemNamespaceFilter(t *testing.T) {
	for _, ns := range []string{"shop", "other"} {
		p := analysis.Problem{Key: ns + "/Deployment/api", Title: ns + "/Deployment/api", Kind: "workload"}
		if MatchProblem(&p, Filter{Namespace: "shop"}) != (ns == "shop") {
			t.Fatalf("incorrect namespace match for %s", ns)
		}
	}
}
