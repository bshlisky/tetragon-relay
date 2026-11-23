package apply

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"

	"github.com/bshlisky/tetragon-relay/internal/verify"
)

func acceptedBundle(mode string, policies ...verify.Policy) *verify.Result {
	return &verify.Result{
		Code: verify.CodeAccept,
		Bundle: &verify.Bundle{
			Scope:    "prod-db",
			Mode:     mode,
			Policies: policies,
		},
	}
}

func fastHealthWindow() HealthWindowConfig {
	// A window this short only exists to keep this package's own tests
	// fast, never in production (ClampHealthWindow enforces
	// limits.MinApplyHealthWindow=15s there). PollInterval is
	// deliberately longer than Window so the ticker never fires within
	// it: only the one synchronous check runHealthWindow makes before
	// entering its loop, plus the GetEvents stream, are exercised,
	// keeping these tests from depending on several extra real RPC round
	// trips completing within a sub-second window on a loaded/
	// race-detector-instrumented CI machine.
	return HealthWindowConfig{Window: 4 * time.Second, PollInterval: 30 * time.Second, SurgeThreshold: 1000}
}

func newTestEngine(t *testing.T, f *fakeServer, parser *fakePolicyParser) (*Engine, *FakeAuditor, *FakeLKGStore) {
	t.Helper()
	client, cleanup := startFakeServer(t, f)
	t.Cleanup(cleanup)
	auditor := &FakeAuditor{}
	lkg := NewFakeLKGStore()
	reach := &FakeReachabilityChecker{ReachableValue: true}
	dir := t.TempDir()
	e := NewEngine(client, parser, lkg, reach, auditor, Config{
		PersistDir:   dir,
		HealthWindow: fastHealthWindow(),
	})
	return e, auditor, lkg
}

func TestApply_NotAccepted(t *testing.T) {
	f := newFakeServer()
	e, _, _ := newTestEngine(t, f, newFakePolicyParser())
	_, err := e.Apply(context.Background(), &verify.Result{Code: verify.CodeRejectedSchema})
	if !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("Apply error = %v, want ErrNotAccepted", err)
	}
}

func TestApply_HappyPath_Enforce(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Sigkill")}
	e, _, lkg := newTestEngine(t, f, parser)

	bundle := acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})
	res, err := e.Apply(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusApplied {
		t.Fatalf("Status = %v, want StatusApplied", res.Status)
	}
	if res.ModeMechanism != modeMechanismActionRewrite {
		t.Fatalf("ModeMechanism = %q", res.ModeMechanism)
	}

	// The action must NOT have been rewritten (enforce mode).
	loadedYAML := soleLoadedYAML(t, f)
	if !containsStr(loadedYAML, `"action":"Sigkill"`) {
		t.Fatalf("enforce-mode policy had its action rewritten: %s", loadedYAML)
	}

	if _, ok := lkg.Get(RelayDomain); !ok {
		t.Fatal("LKG was not updated after a successful apply")
	}
}

func TestApply_HappyPath_MonitorRewritesActions(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Sigkill")}
	e, _, _ := newTestEngine(t, f, parser)

	bundle := acceptedBundle("monitor", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})
	res, err := e.Apply(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusApplied {
		t.Fatalf("Status = %v, want StatusApplied", res.Status)
	}
	loadedYAML := soleLoadedYAML(t, f)
	if !containsStr(loadedYAML, `"action":"Post"`) {
		t.Fatalf("monitor-mode policy action was not rewritten to Post: %s", loadedYAML)
	}
}

func TestApply_IdempotentReapply(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	bundle := acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})
	if _, err := e.Apply(context.Background(), bundle); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	countAfterFirst := f.addCount

	if _, err := e.Apply(context.Background(), bundle); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if f.addCount != countAfterFirst {
		t.Fatalf("re-applying the identical bundle issued %d more AddTracingPolicy calls, want 0 (already loaded)", f.addCount-countAfterFirst)
	}
}

func TestApply_AddFailsPartway_CleansUpOnlyWhatItAdded(t *testing.T) {
	f := newFakeServer()
	f.failAddAfterN = 1 // first add succeeds, second fails
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	parser.docs["p2"] = fakeDoc{name: "p2", json: policyJSON("p2", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	bundle := acceptedBundle("enforce",
		verify.Policy{Name: "p1", Version: 1, YAML: "unused"},
		verify.Policy{Name: "p2", Version: 1, YAML: "unused"},
	)
	res, err := e.Apply(context.Background(), bundle)
	if !errors.Is(err, ErrApplyFailed) {
		t.Fatalf("Apply error = %v, want ErrApplyFailed", err)
	}
	if res.Status != StatusApplyFailed {
		t.Fatalf("Status = %v, want StatusApplyFailed", res.Status)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.domain) != 0 {
		t.Fatalf("fake server still has %d loaded policies after a failed apply was cleaned up: %v", len(f.domain), f.domain)
	}
}

func TestApply_ConfirmFails_PartiallyEnabled(t *testing.T) {
	f := newFakeServer()
	f.confirmAsState = tetragonpb.TracingPolicyState_TP_STATE_PARTIALLY_ENABLED
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	bundle := acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})
	res, err := e.Apply(context.Background(), bundle)
	if !errors.Is(err, ErrApplyFailed) {
		t.Fatalf("Apply error = %v, want ErrApplyFailed", err)
	}
	if res.Status != StatusApplyFailed {
		t.Fatalf("Status = %v, want StatusApplyFailed", res.Status)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.domain) != 0 {
		t.Fatalf("fake server still has policies loaded after a confirm failure was cleaned up: %v", f.domain)
	}
}

func TestApply_RemovalFailure_NonFatal(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	// Load v1, then supersede it with a content change so the engine
	// must delete the old loaded name; make that delete fail.
	if _, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	var oldLoadedName string
	f.mu.Lock()
	for name := range f.domain {
		oldLoadedName = name
	}
	f.failDelete[oldLoadedName] = true
	f.mu.Unlock()

	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Sigkill")} // different content -> different loaded name
	res, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}))
	if err != nil {
		t.Fatalf("second Apply: %v (removal failures must not fail the whole apply)", err)
	}
	if res.Status != StatusApplied {
		t.Fatalf("Status = %v, want StatusApplied despite the removal failure", res.Status)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.domain) != 2 {
		t.Fatalf("expected both the old (stuck) and new loaded policy to remain loaded, got %v", f.domain)
	}
}

func TestApply_HealthWindowFails_RollsBack(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	// No prior LKG: a failed first apply rolls back to "nothing".
	f.mu.Lock()
	f.healthRunning = false // GetHealth will report not-serving throughout the window
	f.mu.Unlock()

	res, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}))
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("Apply error = %v, want ErrRolledBack", err)
	}
	if res.Status != StatusRolledBack {
		t.Fatalf("Status = %v, want StatusRolledBack", res.Status)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.domain) != 0 {
		t.Fatalf("fake server still has policies loaded after rollback to an empty LKG: %v", f.domain)
	}
}

func TestApply_HealthWindowFails_RollsBackToPriorLKG(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, lkg := newTestEngine(t, f, parser)

	// First apply succeeds and becomes LKG.
	if _, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if _, ok := lkg.Get(RelayDomain); !ok {
		t.Fatal("LKG not set after first apply")
	}

	// Second apply (a bad new version) fails its health window.
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Sigkill")}
	f.mu.Lock()
	f.healthRunning = false
	f.mu.Unlock()
	res, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 2, YAML: "unused"}))
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("Apply error = %v, want ErrRolledBack", err)
	}
	if res.Status != StatusRolledBack {
		t.Fatalf("Status = %v", res.Status)
	}

	// Exactly the original (v1) loaded name should be loaded again.
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.domain) != 1 {
		t.Fatalf("expected exactly 1 loaded policy after rollback, got %v", f.domain)
	}
}

func TestApply_SingleFlight(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)
	e.mu.Lock() // simulate an apply already in progress
	defer e.mu.Unlock()

	_, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}))
	if !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("Apply error = %v, want ErrApplyInProgress", err)
	}
}

func TestApply_ForeignPolicyNeverTouched(t *testing.T) {
	f := newFakeServer()
	f.domain["some-foreign-policy"] = "" // no domain: not relay-managed at all
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	if _, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.domain["some-foreign-policy"]; !ok {
		t.Fatal("foreign policy was deleted by Apply")
	}
}

func TestReconcile_InSync(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	if _, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	report, err := e.Reconcile(context.Background(), true)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !report.InSync {
		t.Fatalf("report = %+v, want InSync", report)
	}
}

func TestReconcile_DriftReasserted(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	if _, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Simulate drift: something deleted the loaded policy out from under us.
	f.mu.Lock()
	for name := range f.domain {
		delete(f.domain, name)
	}
	f.snapshotLocked()
	f.mu.Unlock()

	report, err := e.Reconcile(context.Background(), true)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.InSync {
		t.Fatal("report.InSync = true, want drift detected")
	}
	if !report.Reasserted {
		t.Fatalf("report = %+v, want Reasserted", report)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.domain) != 1 {
		t.Fatalf("expected the policy to be reloaded after Reconcile, got %v", f.domain)
	}
}

func soleLoadedYAML(t *testing.T, f *fakeServer) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.yaml) != 1 {
		t.Fatalf("expected exactly 1 loaded policy, got %d", len(f.yaml))
	}
	for _, y := range f.yaml {
		return y
	}
	return ""
}

func containsStr(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
