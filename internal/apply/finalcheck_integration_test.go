//go:build integration

package apply

import (
	"context"
	"testing"
	"time"
)

// TestZZZFinalCheck_NoTracingPoliciesLeftLoaded implements
// step-03a-review.md R3-E3 fix F2: a final, independent check that fails
// if any tracing policy is still loaded on Tetragon after the suite runs.
// Named to sort and run last among this package's integration-tagged test
// files (go test executes a package's tests in the order their source
// files are compiled, which for the standard toolchain is lexical by
// filename; "finalcheck_integration_test.go" sorts after
// "integration_test.go"), so it observes the state every other test's own
// dialIntegration-registered t.Cleanup (fix F1) should have already left
// clean — this exists specifically to catch the case where that cleanup
// itself silently failed or was skipped.
//
// .github/workflows/ci.yml also runs this as its own explicit step
// (`-test.run TestZZZFinalCheck`) after the main suite and before any
// other cleanup, so the job fails loudly rather than only this assertion
// firing incidentally as part of a mixed test run.
func TestZZZFinalCheck_NoTracingPoliciesLeftLoaded(t *testing.T) {
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	statuses, err := client.ListTracingPolicies(ctx, "")
	if err != nil {
		t.Fatalf("ListTracingPolicies: %v", err)
	}
	if len(statuses) != 0 {
		for _, s := range statuses {
			t.Logf("leftover policy: name=%q domain=%q state=%v", s.Name, s.Domain, s.State)
		}
		t.Fatalf("%d tracing policies are still loaded after the integration suite ran; every test must clean up after itself", len(statuses))
	}
}
