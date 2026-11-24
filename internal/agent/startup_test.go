package agent_test

import (
	"errors"
	"os"
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
	defer res.Store.Close()
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
	defer res2.Store.Close()
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
	defer res2.Store.Close()
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
	defer res2.Store.Close()
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
	defer res2.Store.Close()
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
	defer res2.Store.Close()
	if res2.TrustRoot.Version != 1 {
		t.Fatalf("TrustRoot.Version = %d, want 1 (version-skip RPM root ignored, not chained)", res2.TrustRoot.Version)
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
	defer res.Store.Close()

	var lkg apply.LKGStore = res.Store
	if err := lkg.Put("prod-db", apply.LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put via apply.LKGStore interface: %v", err)
	}
	if _, ok := lkg.Get("prod-db"); !ok {
		t.Fatalf("Get via apply.LKGStore interface: ok = false")
	}
}
