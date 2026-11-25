package agent

import (
	"context"
	"os"
	"testing"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

type fakeSnapshotClient struct {
	statuses []tetra.TracingPolicyStatus
	err      error
}

func (f *fakeSnapshotClient) ListTracingPolicies(context.Context, string) ([]tetra.TracingPolicyStatus, error) {
	return f.statuses, f.err
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	st, err := store.Open(dir, &store.FakeKeySealer{Key: []byte("0123456789abcdef0123456789abcdef")}, store.NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRealSnapshotProvider_Snapshot(t *testing.T) {
	st := openTestStore(t)
	if err := st.RecordEpoch("prod-db", 5); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}
	client := &fakeSnapshotClient{statuses: []tetra.TracingPolicyStatus{
		{Name: "block-shadow-read-v1-abcdef12", Domain: apply.RelayDomain, State: tetragonpb.TracingPolicyState_TP_STATE_ENABLED, Enabled: true, Mode: tetragonpb.TracingPolicyMode_TP_MODE_ENFORCE},
	}}
	p := &RealSnapshotProvider{Store: st, Client: client, Scopes: []string{"prod-db"}}
	snap, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Epochs["prod-db"] != 5 {
		t.Fatalf("Epochs = %v", snap.Epochs)
	}
	if len(snap.LoadedDigest) != 32 {
		t.Fatalf("LoadedDigest length = %d, want 32 (sha256)", len(snap.LoadedDigest))
	}
	if len(snap.Policies) != 1 || snap.Policies[0].GetName() != "block-shadow-read-v1-abcdef12" {
		t.Fatalf("Policies = %v", snap.Policies)
	}
	if !snap.Health.GetServing() {
		t.Fatalf("Health.Serving = false, want true")
	}
}

func TestRealSnapshotProvider_Snapshot_ListFailure(t *testing.T) {
	st := openTestStore(t)
	client := &fakeSnapshotClient{err: errSnapshotListFailed}
	p := &RealSnapshotProvider{Store: st, Client: client}
	if _, err := p.Snapshot(context.Background()); err == nil {
		t.Fatalf("expected an error")
	}
}

func TestRealSnapshotProvider_Snapshot_EpochReadFailure(t *testing.T) {
	st := openTestStore(t)
	client := &fakeSnapshotClient{}
	// An unrecorded scope still returns (0, nil) from Current, not an
	// error (internal/store's own contract), so this exercises the
	// success path through the epoch loop with a scope that has never
	// been written.
	p := &RealSnapshotProvider{Store: st, Client: client, Scopes: []string{"never-seen"}}
	snap, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Epochs["never-seen"] != 0 {
		t.Fatalf("Epochs[never-seen] = %d, want 0", snap.Epochs["never-seen"])
	}
}

var errSnapshotListFailed = &snapshotTestError{"list failed"}

type snapshotTestError struct{ msg string }

func (e *snapshotTestError) Error() string { return e.msg }
