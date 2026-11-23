package apply

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bshlisky/tetragon-relay/internal/verify"
)

func TestApply_UnsupportedVersion(t *testing.T) {
	f := newFakeServer()
	f.version = "v1.7.0"
	e, _, _ := newTestEngine(t, f, newFakePolicyParser())
	_, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}))
	if !errors.Is(err, ErrUnsupportedTetragonVersion) {
		t.Fatalf("Apply error = %v, want ErrUnsupportedTetragonVersion", err)
	}
}

func TestApply_ParserFailure(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.errs["p1"] = errors.New("boom")
	e, _, _ := newTestEngine(t, f, parser)
	_, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}))
	if err == nil {
		t.Fatal("Apply succeeded despite a policy parse failure")
	}
}

func TestApply_ExistingManagedListFailure(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	f.mu.Lock()
	f.listErr = status.Error(codes.Unavailable, "down")
	f.mu.Unlock()

	_, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}))
	if err == nil {
		t.Fatal("Apply succeeded despite ListTracingPolicies failing")
	}
}

func TestConfirmLoaded_PolicyMissingFromList(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	resolved, err := e.resolve(acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}).Bundle)
	if err != nil {
		t.Fatal(err)
	}
	// confirmLoaded against a server with nothing actually added.
	if err := e.confirmLoaded(context.Background(), resolved); err == nil {
		t.Fatal("confirmLoaded succeeded for a policy that was never added")
	}
}

func TestCurrentDigest_ListFailure(t *testing.T) {
	f := newFakeServer()
	e, _, _ := newTestEngine(t, f, newFakePolicyParser())
	f.mu.Lock()
	f.listErr = status.Error(codes.Unavailable, "down")
	f.mu.Unlock()
	if _, err := e.currentDigest(context.Background()); err == nil {
		t.Fatal("currentDigest succeeded despite ListTracingPolicies failing")
	}
}

func TestRollback_BadLKGContentFails(t *testing.T) {
	f := newFakeServer()
	e, _, lkg := newTestEngine(t, f, newFakePolicyParser())
	// An LKG entry whose Name is not a valid policy name makes
	// LoadedName fail inside rollback.
	_ = lkg.Put(RelayDomain, LKGSet{Policies: []LKGPolicy{{Name: "Not_Valid", Version: 1, CanonicalJSON: []byte("{}")}}})

	res, err := e.rollback(context.Background(), "test")
	if !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("rollback error = %v, want ErrRollbackFailed", err)
	}
	if res.Status != StatusRollbackFailed {
		t.Fatalf("Status = %v, want StatusRollbackFailed", res.Status)
	}
}

func TestRollback_AddFailureIsRollbackFailed(t *testing.T) {
	f := newFakeServer()
	f.failAllAdds = true
	e, _, lkg := newTestEngine(t, f, newFakePolicyParser())
	_ = lkg.Put(RelayDomain, LKGSet{Policies: []LKGPolicy{{Name: "p1", Version: 1, CanonicalJSON: policyJSON("p1", "Post")}}})

	res, err := e.rollback(context.Background(), "test")
	if !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("rollback error = %v, want ErrRollbackFailed", err)
	}
	if res.Status != StatusRollbackFailed {
		t.Fatalf("Status = %v", res.Status)
	}
}

func TestRollback_ExistingManagedListFailureIsRollbackFailed(t *testing.T) {
	f := newFakeServer()
	e, _, lkg := newTestEngine(t, f, newFakePolicyParser())
	_ = lkg.Put(RelayDomain, LKGSet{Policies: []LKGPolicy{{Name: "p1", Version: 1, CanonicalJSON: policyJSON("p1", "Post")}}})
	f.mu.Lock()
	f.listErr = status.Error(codes.Unavailable, "down")
	f.mu.Unlock()

	res, err := e.rollback(context.Background(), "test")
	if !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("rollback error = %v, want ErrRollbackFailed", err)
	}
	if res.Status != StatusRollbackFailed {
		t.Fatalf("Status = %v", res.Status)
	}
}

func TestReconcile_ExistingManagedListFailure(t *testing.T) {
	f := newFakeServer()
	e, _, _ := newTestEngine(t, f, newFakePolicyParser())
	f.mu.Lock()
	f.listErr = status.Error(codes.Unavailable, "down")
	f.mu.Unlock()
	if _, err := e.Reconcile(context.Background(), false); err == nil {
		t.Fatal("Reconcile succeeded despite ListTracingPolicies failing")
	}
}

func TestReconcile_BadLKGContentFails(t *testing.T) {
	f := newFakeServer()
	e, _, lkg := newTestEngine(t, f, newFakePolicyParser())
	_ = lkg.Put(RelayDomain, LKGSet{Policies: []LKGPolicy{{Name: "Not_Valid", Version: 1, CanonicalJSON: []byte("{}")}}})
	if _, err := e.Reconcile(context.Background(), false); err == nil {
		t.Fatal("Reconcile succeeded despite an LKG entry with an invalid name")
	}
}

func TestReconcile_SingleFlight(t *testing.T) {
	f := newFakeServer()
	e, _, _ := newTestEngine(t, f, newFakePolicyParser())
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.Reconcile(context.Background(), false); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("Reconcile error = %v, want ErrApplyInProgress", err)
	}
}

func TestReconcile_DriftReassertFails(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, _, _ := newTestEngine(t, f, parser)

	if _, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Drift it, then make every subsequent add fail so the reassert itself fails.
	f.mu.Lock()
	for name := range f.domain {
		delete(f.domain, name)
	}
	f.snapshotLocked()
	f.failAllAdds = true // every add from here on fails
	f.mu.Unlock()

	report, err := e.Reconcile(context.Background(), true)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.Reasserted {
		t.Fatal("report.Reasserted = true, want false (reassert should have failed)")
	}
	if report.ReassertError == nil {
		t.Fatal("report.ReassertError is nil, want the rollback failure")
	}
}

func TestResolve_MonitorRewriteOfInvalidJSON(t *testing.T) {
	e, _, _ := newTestEngine(t, newFakeServer(), newFakePolicyParser())
	e.parser.(*fakePolicyParser).docs["p1"] = fakeDoc{name: "p1", json: []byte("not json")}
	_, err := e.resolve(acceptedBundle("monitor", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}).Bundle)
	if err == nil {
		t.Fatal("resolve succeeded despite invalid canonical JSON under monitor mode")
	}
}

func TestResolve_InvalidNameFails(t *testing.T) {
	e, _, _ := newTestEngine(t, newFakeServer(), newFakePolicyParser())
	e.parser.(*fakePolicyParser).docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	_, err := e.resolve(acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 0, YAML: "unused"}).Bundle)
	if err == nil {
		t.Fatal("resolve succeeded despite an out-of-range (zero) version")
	}
}
