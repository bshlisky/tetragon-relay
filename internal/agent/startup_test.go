package agent_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
)

func TestRunCryptoSelfTest_Succeeds(t *testing.T) {
	caps, err := agent.RunCryptoSelfTest()
	if err != nil {
		t.Fatalf("RunCryptoSelfTest: %v", err)
	}
	if !caps.MLDSAAvailable {
		t.Fatalf("MLDSAAvailable = false, want true in this development environment (crypto/mldsa is not FIPS-restricted here); MLDSAErr = %v", caps.MLDSAErr)
	}
}

func testConfig(t *testing.T, initialRoot []byte) (agent.Config, *store.FakeMonotonicCounter) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	counter := store.NewFakeMonotonicCounter()
	return agent.Config{
		StoreDir:         dir,
		Sealer:           &store.FakeKeySealer{Key: []byte("agent-test-key-0123456789abcdef")},
		Counter:          counter,
		InitialRootBytes: initialRoot,
		Auditor:          &agent.FakeAuditor{},
	}, counter
}

func TestStartup_FirstBoot_AdoptsInitialRoot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	initialRoot, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, _ := testConfig(t, initialRoot)

	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}
	defer func() { _ = res.Store.Close() }()
	if !res.FirstBoot {
		t.Fatalf("FirstBoot = false, want true")
	}
	if res.TrustRoot == nil || res.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot = %+v, want version 1", res.TrustRoot)
	}
	if raw, version, ok, err := res.Store.TrustRoot(); err != nil || !ok || version != 1 || string(raw) != string(initialRoot) {
		t.Fatalf("persisted root = (ok=%v, version=%d, err=%v), want (true, 1, nil) with the initial root's raw bytes", ok, version, err)
	}
}

func TestStartup_FirstBoot_NoInitialRootIsAnError(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg, _ := testConfig(t, nil)
	if _, err := agent.Startup(cfg, now); !errors.Is(err, agent.ErrNoTrustRoot) {
		t.Fatalf("err = %v, want ErrNoTrustRoot", err)
	}
}

func TestStartup_Reopen_UsesPersistedRootWhenNoInitialRootConfigured(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	initialRoot, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, initialRoot)

	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg.InitialRootBytes = nil
	cfg.Counter = counter // same counter, simulating a real restart against the same TPM NV counter
	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.FirstBoot {
		t.Fatalf("FirstBoot = true on a reopen, want false")
	}
	if res2.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot.Version = %d, want 1 (persisted)", res2.TrustRoot.Version)
	}
}

func TestStartup_ForwardChain_AdoptsNewerRPMRoot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, v1RootKeys := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)

	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v2Root := rotatedRoot(t, 2, now.Add(365*24*time.Hour), v1RootKeys)
	cfg.InitialRootBytes = v2Root
	cfg.Counter = counter

	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.FirstBoot {
		t.Fatalf("FirstBoot = true, want false")
	}
	if res2.TrustRoot.Version != 2 {
		t.Fatalf("TrustRoot.Version = %d, want 2 (chained forward)", res2.TrustRoot.Version)
	}
	if _, version, ok, err := res2.Store.TrustRoot(); err != nil || !ok || version != 2 {
		t.Fatalf("persisted version = (%d, ok=%v, err=%v), want (2, true, nil)", version, ok, err)
	}
}

func TestStartup_IgnoresOlderOrEqualRPMRoot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, v1RootKeys := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)

	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	v2Root := rotatedRoot(t, 2, now.Add(365*24*time.Hour), v1RootKeys)
	if err := res.Store.PersistTrustRoot(v2Root, 2); err != nil {
		t.Fatalf("PersistTrustRoot (test setup): %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The RPM still only ships v1; it must be ignored, not treated as a
	// downgrade error, and the persisted v2 root must remain current.
	cfg.InitialRootBytes = v1Root
	cfg.Counter = counter
	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.TrustRoot.Version != 2 {
		t.Fatalf("TrustRoot.Version = %d, want 2 (the older RPM root must be ignored)", res2.TrustRoot.Version)
	}
}

func TestStartup_TamperedStorePropagatesError(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	initialRoot, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, _ := testConfig(t, initialRoot)

	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Chmod(cfg.StoreDir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	auditor := cfg.Auditor.(*agent.FakeAuditor)
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "store_open" && errors.Is(e.Err, store.ErrTampered) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no store_open/TAMPERED audit event recorded; events = %+v", auditor.Events)
	}
}

func TestStartup_NilAuditorIsConfigError(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg, _ := testConfig(t, nil)
	cfg.Auditor = nil
	if _, err := agent.Startup(cfg, now); err == nil {
		t.Fatalf("expected an error for a nil Auditor")
	}
}

func TestStartup_MalformedInitialRootAtFirstBoot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg, _ := testConfig(t, []byte("not a valid root envelope"))
	if _, err := agent.Startup(cfg, now); !errors.Is(err, agent.ErrInitialRootInvalid) {
		t.Fatalf("err = %v, want ErrInitialRootInvalid", err)
	}
}

func TestStartup_MalformedRPMRootOnReopenIsIgnored(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	initialRoot, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, initialRoot)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg.InitialRootBytes = []byte("garbage, not a root envelope at all")
	cfg.Counter = counter
	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup with a malformed RPM root: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot.Version = %d, want 1 (persisted, malformed RPM root ignored)", res2.TrustRoot.Version)
	}
}

func TestStartup_RPMRootMoreThanOneVersionAheadIsIgnored(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, v1RootKeys := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A root claiming version 3 (skipping 2) cannot chain from the
	// persisted version 1 in one Update call.
	v3Root := rotatedRoot(t, 3, now.Add(365*24*time.Hour), v1RootKeys)
	cfg.InitialRootBytes = v3Root
	cfg.Counter = counter
	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot.Version = %d, want 1 (version-skip RPM root ignored, not chained)", res2.TrustRoot.Version)
	}
}

// --- step-04b-review.md R4B-1: forward root chaining across multiple versions ---

func TestStartup_MultiVersionChain_TwoVersionsBehindAcceptsBothSteps(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, v1Keys := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v2Root, v2Keys := rotatedRootWithKeys(t, 2, now.Add(365*24*time.Hour), v1Keys)
	v3Root := rotatedRoot(t, 3, now.Add(365*24*time.Hour), v2Keys)

	cfg.InitialRootBytes = nil // root.json never changes; the two new versions ship under roots/
	cfg.AvailableRPMRoots = map[uint64][]byte{2: v2Root, 3: v3Root}
	cfg.Counter = counter

	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.TrustRoot.Version != 3 {
		t.Fatalf("TrustRoot.Version = %d, want 3 (both forward steps accepted)", res2.TrustRoot.Version)
	}
	if _, version, ok, err := res2.Store.TrustRoot(); err != nil || !ok || version != 3 {
		t.Fatalf("persisted version = (%d, ok=%v, err=%v), want (3, true, nil)", version, ok, err)
	}
}

func TestStartup_MultiVersionChain_GapStopsAtTheGap(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, v1Keys := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v2Root, v2Keys := rotatedRootWithKeys(t, 2, now.Add(365*24*time.Hour), v1Keys)
	_, v3Keys := rotatedRootWithKeys(t, 3, now.Add(365*24*time.Hour), v2Keys)
	v4Root := rotatedRoot(t, 4, now.Add(365*24*time.Hour), v3Keys)

	// version 3 is missing: the chain can reach 2, but not 4 (which
	// only chains from 3).
	cfg.InitialRootBytes = nil
	cfg.AvailableRPMRoots = map[uint64][]byte{2: v2Root, 4: v4Root}
	cfg.Counter = counter

	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.TrustRoot.Version != 2 {
		t.Fatalf("TrustRoot.Version = %d, want 2 (stopped at the gap at version 3)", res2.TrustRoot.Version)
	}
}

func TestStartup_MultiVersionChain_MisnamedFileIsIgnoredAndAudited(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, v1Keys := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v2Root, _ := rotatedRootWithKeys(t, 2, now.Add(365*24*time.Hour), v1Keys)
	// This file is NAMED "3.root.json" but its own metadata declares
	// version 2 -- a mismatch step-04b-review.md R4B-1 requires be
	// ignored (never trusted by file name alone) and audited.
	cfg.InitialRootBytes = nil
	cfg.AvailableRPMRoots = map[uint64][]byte{3: v2Root}
	cfg.Counter = counter
	auditor := cfg.Auditor.(*agent.FakeAuditor)

	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot.Version = %d, want 1 (misnamed file never adopted)", res2.TrustRoot.Version)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "trust_root_candidate" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no trust_root_candidate audit event for the misnamed file; events = %+v", auditor.Events)
	}
}

func TestStartup_MultiVersionChain_MaliciousNonChainingFileStopsTheWalk(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A root honestly named and declaring version 2, but self-signed by
	// an entirely unrelated key set -- it satisfies its OWN threshold
	// (so it parses/self-verifies fine as a candidate) but was never
	// signed by any threshold of the PERSISTED v1 root's keys, so it
	// must fail to chain, exactly the "attacker or stale mirror serves
	// a file claiming a higher version that does not chain" case.
	malicious, _ := standardRoot(t, 2, now.Add(365*24*time.Hour))
	cfg.InitialRootBytes = nil
	cfg.AvailableRPMRoots = map[uint64][]byte{2: malicious}
	cfg.Counter = counter
	auditor := cfg.Auditor.(*agent.FakeAuditor)

	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot.Version = %d, want 1 (malicious non-chaining root rejected, persisted root kept)", res2.TrustRoot.Version)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "trust_root" && e.Err != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audited chain-verification failure; events = %+v", auditor.Events)
	}
}

func TestStartup_MultiVersionChain_UnparsableFileIsIgnoredAndAudited(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg.InitialRootBytes = nil
	cfg.AvailableRPMRoots = map[uint64][]byte{2: []byte("not a valid root envelope at all")}
	cfg.Counter = counter
	auditor := cfg.Auditor.(*agent.FakeAuditor)

	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	if res2.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot.Version = %d, want 1 (unparsable file never adopted)", res2.TrustRoot.Version)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "trust_root_candidate" && e.Err != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("no trust_root_candidate audit event for the unparsable file; events = %+v", auditor.Events)
	}
}

func TestStartup_MultiVersionChain_DuplicateVersionDifferentContentIsIgnored(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Two entirely independent, self-signed roots that both happen to
	// declare version 2 (e.g. a stale mirror and the real RPM
	// disagreeing): root.json's candidate is considered first, so the
	// AvailableRPMRoots entry with different bytes for the same version
	// must be ignored and audited, not silently picked.
	v2RootA, _ := standardRoot(t, 2, now.Add(365*24*time.Hour))
	v2RootB, _ := standardRoot(t, 2, now.Add(365*24*time.Hour))
	cfg.InitialRootBytes = v2RootA
	cfg.AvailableRPMRoots = map[uint64][]byte{2: v2RootB}
	cfg.Counter = counter
	auditor := cfg.Auditor.(*agent.FakeAuditor)

	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	// Neither v2RootA nor v2RootB is signed by the persisted v1 root's
	// keys, so the walk cannot chain to either -- this test only
	// exercises the duplicate-detection branch itself.
	if res2.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot.Version = %d, want 1", res2.TrustRoot.Version)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "trust_root_candidate" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no trust_root_candidate audit event; events = %+v", auditor.Events)
	}
}

func TestStartup_MultiVersionChain_StepBoundStopsTheWalk(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, v1Keys := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Build a chain of exactly limits.MaxRootChainFiles (64) consecutive
	// versions (2..65) via AvailableRPMRoots -- the maximum this
	// package's own config-size check allows -- plus one more (66) via
	// the root.json slot, so there is still a USABLE candidate waiting
	// right when the step bound is reached, proving the bound (not a
	// gap) is what stopped the walk.
	const n = 64
	available := make(map[uint64][]byte, n)
	keys := v1Keys
	for v := uint64(2); v <= uint64(1+n); v++ {
		raw, newKeys := rotatedRootWithKeys(t, int(v), now.Add(365*24*time.Hour), keys)
		available[v] = raw
		keys = newKeys
	}
	oneMore := rotatedRoot(t, int(2+n), now.Add(365*24*time.Hour), keys)

	cfg.InitialRootBytes = oneMore // folded in as the (persisted+65)th candidate
	cfg.AvailableRPMRoots = available
	cfg.Counter = counter
	auditor := cfg.Auditor.(*agent.FakeAuditor)

	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Startup: %v", err)
	}
	defer func() { _ = res2.Store.Close() }()
	wantVersion := uint64(1 + n)
	if res2.TrustRoot.Version != wantVersion {
		t.Fatalf("TrustRoot.Version = %d, want %d (stopped at the %d-step bound with one more candidate still available)", res2.TrustRoot.Version, wantVersion, n)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "trust_root" && e.Err == nil && strings.Contains(e.Detail, "reached the") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit event recording the step bound being reached; events = %+v", auditor.Events)
	}
}

func TestStartup_MultiVersionChain_PersistFailureAfterSuccessfulWalk(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, v1Keys := standardRoot(t, 1, now.Add(365*24*time.Hour))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// failAfter=2: the store's own first-boot commit (generation 1) and
	// first boot's own PersistTrustRoot of the initial root (generation
	// 2) each consume one successful Increment; the chain-walk's own
	// PersistTrustRoot call on the SECOND Startup (generation 3) then
	// hits the simulated failure.
	counter := &agentFailAfterNCounter{underlying: store.NewFakeMonotonicCounter(), failAfter: 2}
	cfg := agent.Config{
		StoreDir:         dir,
		Sealer:           &store.FakeKeySealer{Key: []byte("agent-test-key-0123456789abcdef")},
		Counter:          counter,
		InitialRootBytes: v1Root,
		Auditor:          &agent.FakeAuditor{},
	}
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v2Root := rotatedRoot(t, 2, now.Add(365*24*time.Hour), v1Keys)
	cfg.InitialRootBytes = v2Root
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); err == nil {
		t.Fatalf("expected an error: the chain-walk's PersistTrustRoot should fail via the simulated counter lag")
	}
}

type agentFailAfterNCounter struct {
	underlying store.MonotonicCounter
	failAfter  int
	calls      int
}

func (c *agentFailAfterNCounter) Read() (uint64, error) { return c.underlying.Read() }

func (c *agentFailAfterNCounter) Increment() (uint64, error) {
	c.calls++
	if c.calls > c.failAfter {
		return 0, errAgentSimulatedCounterFailure
	}
	return c.underlying.Increment()
}

var errAgentSimulatedCounterFailure = errors.New("simulated monotonic counter failure")

func TestStartup_MultiVersionChain_TooManyFilesIsConfigError(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Root, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, counter := testConfig(t, v1Root)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cfg.Counter = counter

	tooMany := make(map[uint64][]byte, 65)
	for i := uint64(2); i < 2+65; i++ {
		tooMany[i] = []byte("unused")
	}
	cfg.AvailableRPMRoots = tooMany
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); !errors.Is(err, agent.ErrTooManyRootFiles) {
		t.Fatalf("err = %v, want ErrTooManyRootFiles", err)
	}
}

// TestStartup_PersistedRootWithValidHMACButFailingTrustVerificationIsTampered
// implements step-04b-review.md's answer to open question 3: "Add a test
// asserting that Startup rejects (as tamper) a persisted root whose bytes
// carry a valid HMAC but fail trust verification." internal/store's own
// HMAC only ever covers index integrity (the bytes are exactly what this
// package itself wrote); it says nothing about whether those bytes parse
// or self-verify as valid trust-root metadata -- store.PersistTrustRoot
// does not parse raw at all (store has no internal/trust dependency), so
// garbage bytes persist with a perfectly valid HMAC. internal/agent's own
// re-verification with trust.LoadInitialRoot at every startup is the
// layer that must catch this (docs/reports/step-04b.md's open question 3
// answer, repeated in step-04b-review.md: "the agent's re-verification...
// is the right layer").
func TestStartup_PersistedRootWithValidHMACButFailingTrustVerificationIsTampered(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-test-key-0123456789abcdef")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// PersistTrustRoot computes a correct index HMAC over whatever bytes
	// it is given -- it never parses them. This is exactly how an
	// attacker with the HMAC key (but not a valid root signature) could
	// forge a persisted root: the store-level integrity check passes,
	// but the bytes are not valid trust-root metadata at all.
	if err := st.PersistTrustRoot([]byte("not a valid root envelope at all"), 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	auditor := &agent.FakeAuditor{}
	cfg := agent.Config{StoreDir: dir, Sealer: sealer, Counter: counter, Auditor: auditor}
	if _, err := agent.Startup(cfg, now); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want store.ErrTampered", err)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "trust_root" && e.Err != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("no trust_root audit event recording the parse failure; events = %+v", auditor.Events)
	}
}

func TestStartup_SealerUnavailable(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg, _ := testConfig(t, nil)
	cfg.Sealer = &store.FakeKeySealer{Err: errTestSealerBroken}
	if _, err := agent.Startup(cfg, now); !errors.Is(err, agent.ErrStoreOpenFailed) {
		t.Fatalf("err = %v, want ErrStoreOpenFailed", err)
	}
}

var errTestSealerBroken = errors.New("sealer broken")

func TestStartup_HandsStoreToApplyLKGStoreInterface(t *testing.T) {
	// Confirms *store.Store (as returned via StartupResult.Store)
	// genuinely satisfies apply.LKGStore, so Part D1's "implement
	// apply.LKGStore on internal/store" is handed to the apply engine
	// exactly as a real caller (relayd main(), step 6) would use it.
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	initialRoot, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	cfg, _ := testConfig(t, initialRoot)
	res, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}
	defer func() { _ = res.Store.Close() }()

	var lkg apply.LKGStore = res.Store
	if err := lkg.Put("prod-db", apply.LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put via apply.LKGStore interface: %v", err)
	}
	if _, ok := lkg.Get("prod-db"); !ok {
		t.Fatalf("Get via apply.LKGStore interface: ok = false")
	}
}
