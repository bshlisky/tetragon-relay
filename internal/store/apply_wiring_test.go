package store_test

// This file exercises the actual internal/apply.Engine <-> store.Store
// wiring (apply.LKGStore is satisfied by *store.Store directly), proving
// step-04b-review.md R4B-5's required caller behavior: when Put returns
// ErrCommittedCounterLag (the index write committed, but the mirrored
// MonotonicCounter's Increment failed right after), the apply engine does
// NOT roll Tetragon back, re-apply anything, or otherwise treat the bundle
// as unsuccessful because of it. The write having committed is exactly
// why it must not: Tetragon is already correctly loaded via gRPC by the
// time Put is called (Apply's own sequencing), so rolling back here would
// undo a change that durably happened for no reason connected to whether
// Tetragon itself is healthy.
//
// internal/apply cannot import internal/store (store already imports
// apply for apply.LKGSet), so this test lives here instead, using a
// minimal local fake Tetragon client and policy parser rather than
// internal/apply's own (unexported, package-internal) test fakes.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
	"github.com/bshlisky/tetragon-relay/internal/verify"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// failAfterNCounter is a store.MonotonicCounter that lets the first
// failAfter Increment calls through to an underlying counter, then fails
// every one after that -- enough to let a store's own first-boot commit
// succeed, then force the NEXT commit's Increment to fail, reproducing
// R4B-5's "index write committed but Increment failed" window on demand.
type failAfterNCounter struct {
	underlying store.MonotonicCounter
	failAfter  int
	calls      int
}

func (c *failAfterNCounter) Read() (uint64, error) { return c.underlying.Read() }

func (c *failAfterNCounter) Increment() (uint64, error) {
	c.calls++
	if c.calls > c.failAfter {
		return 0, errSimulatedCounterFailure
	}
	return c.underlying.Increment()
}

var errSimulatedCounterFailure = errors.New("simulated monotonic counter failure")

// wiringFakeTetragonClient is a minimal apply.TetragonClient: every
// addition succeeds and immediately reports as loaded/enabled, health is
// always serving, and GetEvents forwards only what live carries (the
// wiring sentinel's events) until its context ends. Since ADR 0042 a
// silent stream no longer passes a health window: the sentinel's events
// are what prove the observation path current.
type wiringFakeTetragonClient struct {
	loaded map[string]bool
	live   chan tetra.Event
}

func newWiringFakeTetragonClient() *wiringFakeTetragonClient {
	return &wiringFakeTetragonClient{loaded: map[string]bool{}, live: make(chan tetra.Event, 1024)}
}

// wiringSentinel is an apply.Sentinel whose Fire puts the matching event
// straight on the fake client's stream (the real FileSentinel builds the
// policy and parses the nonce).
type wiringSentinel struct {
	*apply.FileSentinel
	client *wiringFakeTetragonClient
}

func newWiringSentinel(t *testing.T, c *wiringFakeTetragonClient) *wiringSentinel {
	t.Helper()
	fs, err := apply.NewFileSentinel("/usr/libexec/tetragon-relay/relayd", "/var/lib/tetragon-relay/sentinel")
	if err != nil {
		t.Fatalf("NewFileSentinel: %v", err)
	}
	return &wiringSentinel{FileSentinel: fs, client: c}
}

func (s *wiringSentinel) Fire(nonce string) error {
	s.client.live <- tetra.Event{Kprobe: &tetragonpb.ProcessKprobe{
		PolicyName: s.PolicyName(),
		Args:       []*tetragonpb.KprobeArgument{{Arg: &tetragonpb.KprobeArgument_FileArg{FileArg: &tetragonpb.KprobeFile{Path: "/var/lib/tetragon-relay/sentinel/" + nonce}}}},
	}}
	return nil
}

func (f *wiringFakeTetragonClient) AddTracingPolicy(_ context.Context, doc string, _ string) error {
	var v struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		return err
	}
	f.loaded[v.Metadata.Name] = true
	return nil
}

func (f *wiringFakeTetragonClient) DeleteTracingPolicy(_ context.Context, name string, _ string) error {
	delete(f.loaded, name)
	return nil
}

func (f *wiringFakeTetragonClient) ListTracingPolicies(_ context.Context, _ string) ([]tetra.TracingPolicyStatus, error) {
	out := make([]tetra.TracingPolicyStatus, 0, len(f.loaded))
	for name := range f.loaded {
		out = append(out, tetra.TracingPolicyStatus{Name: name, State: tetragonpb.TracingPolicyState_TP_STATE_ENABLED, Enabled: true})
	}
	return out, nil
}

func (f *wiringFakeTetragonClient) GetHealth(context.Context) ([]*tetragonpb.HealthStatus, error) {
	return []*tetragonpb.HealthStatus{{Status: tetragonpb.HealthStatusResult_HEALTH_STATUS_RUNNING}}, nil
}

func (f *wiringFakeTetragonClient) GetEvents(ctx context.Context, _ []string) (<-chan tetra.Event, <-chan error) {
	events := make(chan tetra.Event)
	errc := make(chan error)
	go func() {
		defer close(errc)
		defer close(events)
		for {
			select {
			case ev := <-f.live:
				select {
				case events <- ev:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return events, errc
}

func (f *wiringFakeTetragonClient) RequireVersion(context.Context) (string, error) {
	return "v1.8.0", nil
}

// wiringFakeDoc/wiringFakeParser mirror internal/apply's own unexported
// fakeDoc/fakePolicyParser, duplicated here since those are not exported.
type wiringFakeDoc struct {
	name string
	json []byte
}

func (d wiringFakeDoc) Name() string          { return d.name }
func (d wiringFakeDoc) CanonicalJSON() []byte { return d.json }

type wiringFakeParser struct{}

func (wiringFakeParser) Parse(name, _ string) (apply.Doc, error) {
	jsonDoc := []byte(`{"apiVersion":"cilium.io/v1alpha1","kind":"TracingPolicy","metadata":{"name":"` + name + `"},"spec":{"kprobes":[{"call":"security_bprm_check","selectors":[{"matchActions":[{"action":"Sigkill"}],"matchBinaries":[{"operator":"In","values":["/usr/bin/x"]}]}]}]}}`)
	return wiringFakeDoc{name: name, json: jsonDoc}, nil
}

// trackingFSAuditor records every apply.AuditEvent, mirroring
// apply.FakeAuditor (exported, so this is purely for clarity at the call
// site here).
func TestApplyEngine_LKGStorePutErrorDoesNotRollBackTetragon(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// failAfter=1: the store's own first-boot commit (Open on an empty
	// directory) consumes the first successful Increment; the engine's
	// subsequent Put (LKG write) then hits the simulated failure,
	// reproducing R4B-5's exact window.
	counter := &failAfterNCounter{underlying: store.NewFakeMonotonicCounter(), failAfter: 1}
	s, err := store.Open(dir, &store.FakeKeySealer{Key: []byte("test-hmac-key-0123456789abcdef")}, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := newWiringFakeTetragonClient()
	auditor := &apply.FakeAuditor{}
	reach := &apply.FakeReachabilityChecker{ReachableValue: true}
	engine := apply.NewEngine(client, wiringFakeParser{}, s, reach, auditor, apply.Config{
		PersistDir: t.TempDir(),
		HealthWindow: apply.HealthWindowConfig{
			Window:             200 * time.Millisecond,
			PollInterval:       2 * time.Second, // longer than Window: no mid-window poll fires
			SurgeThreshold:     1000,
			SentinelInterval:   20 * time.Millisecond,
			SentinelMaxLatency: time.Second,
			SettleMargin:       10 * time.Millisecond,
		},
		Sentinel: newWiringSentinel(t, client),
	})

	bundle := &verify.Result{
		Code: verify.CodeAccept,
		Bundle: &verify.Bundle{
			Scope:    "prod-db",
			Mode:     "enforce",
			Policies: []verify.Policy{{Name: "p1", Version: 1, YAML: "unused"}},
		},
	}

	res, err := engine.Apply(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if res.Status != apply.StatusApplied {
		t.Fatalf("Status = %v, want StatusApplied (R4B-5: a durably-committed-but-counter-lagging LKG write must never cause a rollback)", res.Status)
	}

	var sawCommittedCounterLag bool
	for _, e := range auditor.Events {
		if e.Step == "lkg_put_failed" && errors.Is(e.Err, store.ErrCommittedCounterLag) {
			sawCommittedCounterLag = true
		}
		if e.Step == "health_window_failed" || e.Step == "rollback_failed" || e.Step == "rollback" {
			t.Fatalf("unexpected rollback-related audit event: %+v", e)
		}
	}
	if !sawCommittedCounterLag {
		t.Fatalf("expected an lkg_put_failed audit event wrapping store.ErrCommittedCounterLag; events: %+v", auditor.Events)
	}

	// The LKG write itself is durable despite the reported error (Part
	// C5/R4B-5): a fresh read sees it. LKGStore.Put is keyed by the
	// engine's configured domain (apply.RelayDomain, since Config.Domain
	// was left unset above), not the bundle's scope.
	got, ok := s.Get(apply.RelayDomain)
	if !ok {
		t.Fatalf("Get after the Put that returned ErrCommittedCounterLag: ok = false, want the write to be durable")
	}
	if got.Mode != "enforce" {
		t.Fatalf("Get = %+v, want the committed LKG set", got)
	}
}
