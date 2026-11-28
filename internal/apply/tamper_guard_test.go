package apply

import (
	"context"
	"errors"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// tamperingLKG is an LKGStore that can report tampering (TamperReporter)
// and, once tampered, reads as empty, as internal/store does.
type tamperingLKG struct {
	*FakeLKGStore
	err error
}

func (t *tamperingLKG) Get(domain string) (LKGSet, bool) {
	if t.err != nil {
		return LKGSet{}, false
	}
	return t.FakeLKGStore.Get(domain)
}

func (t *tamperingLKG) Tampered() error { return t.err }

// TestReconcileAndRollback_RefuseOnTamperedLKG: a TAMPERED LKG store reads
// as empty; re-asserting it would unload every relay-managed policy, so
// Reconcile and rollback refuse and leave Tetragon untouched (step 4b C6).
func TestReconcileAndRollback_RefuseOnTamperedLKG(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	client, cleanup := startFakeServer(t, f)
	t.Cleanup(cleanup)
	lkg := &tamperingLKG{FakeLKGStore: NewFakeLKGStore()}
	e := NewEngine(client, parser, lkg, &FakeReachabilityChecker{ReachableValue: true}, &FakeAuditor{}, Config{PersistDir: t.TempDir(), HealthWindow: fastHealthWindow(), Sentinel: newFakeSentinel(t, f.pushLive)})
	if _, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !e.TetragonServing(context.Background()) {
		t.Fatal("TetragonServing = false on a running fake")
	}
	lkg.err = errors.New("blob hash mismatch")

	if _, err := e.Reconcile(context.Background(), true); !errors.Is(err, ErrLKGTampered) {
		t.Fatalf("Reconcile error = %v, want ErrLKGTampered", err)
	}
	e.mu.Lock()
	res, err := e.rollback(context.Background(), "test")
	e.mu.Unlock()
	if !errors.Is(err, ErrRollbackFailed) || res.Status != StatusRollbackFailed {
		t.Fatalf("rollback = %+v, %v; want ROLLBACK_FAILED", res, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.domain) != 1 {
		t.Fatalf("Tetragon changed under a tampered LKG: %v", f.domain)
	}
}

func TestTetragonServing_NotRunning(t *testing.T) {
	f := newFakeServer()
	f.healthRunning = false
	e, _, _ := newTestEngine(t, f, newFakePolicyParser())
	if e.TetragonServing(context.Background()) {
		t.Fatal("TetragonServing = true with an erroring health status")
	}
}
