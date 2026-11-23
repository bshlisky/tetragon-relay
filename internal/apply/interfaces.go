package apply

import (
	"context"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// TetragonClient is the subset of *tetra.Client (step 3 prompt Part B1's
// allowlist) this package calls. *tetra.Client satisfies this directly;
// the interface exists purely so Engine can be constructed with a fake for
// the unit tests that don't need a real fake gRPC server (step 3 prompt
// Part E1's own invariant tests still use a real *tetra.Client dialed to a
// fake server, for full RPC-sequencing fidelity).
type TetragonClient interface {
	AddTracingPolicy(ctx context.Context, yaml, domain string) error
	DeleteTracingPolicy(ctx context.Context, name, domain string) error
	ListTracingPolicies(ctx context.Context, domain string) ([]tetra.TracingPolicyStatus, error)
	GetHealth(ctx context.Context) ([]*tetragonpb.HealthStatus, error)
	GetEvents(ctx context.Context, policyNames []string) (<-chan tetra.Event, <-chan error)
	RequireVersion(ctx context.Context) (string, error)
}

var _ TetragonClient = (*tetra.Client)(nil)

// PolicyParser turns one bundle policy's YAML into a typed, canonical
// *policydoc.Doc. Re-parsing here (rather than threading internal/verify's
// own parsed docs through) keeps this package decoupled from
// internal/verify's internals: the YAML has already been accepted by
// Verify (same hash, same parser), so re-parsing is deterministic and
// side-effect-free, not a second, independent trust decision.
type PolicyParser interface {
	Parse(name, yamlDoc string) (Doc, error)
}

// Doc is the subset of *policydoc.Doc this package needs. Defined locally
// (not importing *policydoc.Doc's concrete type into every signature) so
// tests can fake it without constructing a real policy document. This
// package computes its own sha256 over CanonicalJSON() rather than relying
// on a CanonicalSHA256 method, so the interface stays minimal.
type Doc interface {
	Name() string
	CanonicalJSON() []byte
}

// LKGStore is the last-known-good store (step 3 prompt Part D6): an
// interface so step 4's persistent implementation is a drop-in later. Get
// returns ok=false if no LKG set has ever been recorded for domain
// (nothing to roll back to).
type LKGStore interface {
	Get(domain string) (LKGSet, bool)
	Put(domain string, set LKGSet) error
}

// LKGSet is one scope/domain's last-known-good policy set: enough to
// re-apply it with the same add-before-remove procedure (Part D6).
type LKGSet struct {
	// Policies is every policy in the set, keyed by its original (bundle)
	// name, with the exact canonical JSON that was loaded.
	Policies []LKGPolicy
	// Mode is the bundle mode ("monitor" or "enforce") the set was
	// loaded under (architecture doc 7.4 step 11).
	Mode string
}

// LKGPolicy is one policy within an LKGSet.
type LKGPolicy struct {
	Name          string
	Version       int
	CanonicalJSON []byte
}

// ReachabilityChecker is Part D5's control-plane-reachability callback:
// "interface; fake now, real in step 6".
type ReachabilityChecker interface {
	// Reachable reports whether the control plane was reachable at the
	// time of the call. Called repeatedly during the health window.
	Reachable(ctx context.Context) bool
}

// Auditor is Part D7's structured audit record sink: "fake now".
type Auditor interface {
	Record(event AuditEvent)
}

// AuditEvent is one structured audit record. Fields are a minimal,
// additive set; a real implementation (later step) would also attach a
// timestamp and ship it off-host (architecture doc section 10).
type AuditEvent struct {
	Step   string // e.g. "add", "delete", "health_check", "rollback"
	Detail string
	Err    error
	Domain string
	Policy string // loaded name, when applicable
}

// --- fakes (step 3 prompt: "fake now") ---

// FakeLKGStore is an in-memory LKGStore.
type FakeLKGStore struct {
	sets map[string]LKGSet
}

// NewFakeLKGStore returns an empty FakeLKGStore.
func NewFakeLKGStore() *FakeLKGStore {
	return &FakeLKGStore{sets: make(map[string]LKGSet)}
}

// Get implements LKGStore.
func (f *FakeLKGStore) Get(domain string) (LKGSet, bool) {
	s, ok := f.sets[domain]
	return s, ok
}

// Put implements LKGStore.
func (f *FakeLKGStore) Put(domain string, set LKGSet) error {
	if f.sets == nil {
		f.sets = make(map[string]LKGSet)
	}
	f.sets[domain] = set
	return nil
}

// FakeReachabilityChecker always returns a fixed value, settable by tests.
type FakeReachabilityChecker struct {
	ReachableValue bool
}

// Reachable implements ReachabilityChecker.
func (f *FakeReachabilityChecker) Reachable(context.Context) bool { return f.ReachableValue }

// FakeAuditor records every event in memory for test assertions.
type FakeAuditor struct {
	Events []AuditEvent
}

// Record implements Auditor.
func (f *FakeAuditor) Record(e AuditEvent) {
	f.Events = append(f.Events, e)
}
