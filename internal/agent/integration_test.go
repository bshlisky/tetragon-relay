//go:build integration

// Package agent integration test (step-04c.md Part E7, step 3 prompt Part
// E3's harness). This runs only with -tags integration, against a REAL
// Tetragon v1.8.0 daemon listening on /var/run/tetragon/tetragon.sock
// (started by .github/workflows/ci.yml's "integration" job, the same one
// internal/tetra's and internal/apply's own integration suites use).
//
// It exercises internal/agent.Startup, internal/store.Store and
// internal/apply.Engine together against a real Tetragon connection: a
// bundle is verified and applied; the agent is "restarted" (the store is
// closed and reopened via a fresh Startup call, simulating relayd
// restarting while Tetragon itself keeps running); the persisted epoch
// and LKG (including ADR 0025's raw-envelope re-verification) are
// confirmed to have survived; a replay of the exact same bundle is
// confirmed rejected with REJECTED_EPOCH; and Tetragon's own loaded set
// is confirmed unchanged by the restart simulation (no RPC was ever made
// to Tetragon during it).
package agent_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

const integrationSocket = "/var/run/tetragon/tetragon.sock"

// dialIntegration/cleanupAllTracingPolicies/mustLookPath duplicate
// internal/apply/integration_test.go's own identically-named helpers
// (not importable here: that file is package apply, build-tag gated, and
// its helpers are unexported). step-03a-review.md R3-E3 fix F1's
// contract is preserved exactly: every loaded tracing policy is deleted
// in t.Cleanup regardless of how the test ends.
func dialIntegration(t *testing.T) *tetra.Client {
	t.Helper()
	cfg := tetra.Config{
		SocketPath:           integrationSocket,
		TetragonBinaryPath:   mustLookPath(t, "tetragon"),
		RelayGroupName:       "tetragon-relay",
		AllowSELinuxDisabled: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := tetra.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial(real Tetragon): %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	t.Cleanup(func() { cleanupAllTracingPolicies(t, c) })
	return c
}

func cleanupAllTracingPolicies(t *testing.T, c *tetra.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	statuses, err := c.ListTracingPolicies(ctx, "")
	if err != nil {
		t.Logf("cleanup: ListTracingPolicies: %v", err)
		return
	}
	for _, s := range statuses {
		if err := c.DeleteTracingPolicy(ctx, s.Name, s.Domain); err != nil {
			t.Logf("cleanup: DeleteTracingPolicy(%s, domain=%s): %v", s.Name, s.Domain, err)
		}
	}
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("LookPath(%s): %v", name, err)
	}
	return p
}

// itestPolicyYAML is a real, schema-valid, guard-safe TracingPolicy: an
// observe-only ("Post") kprobe matchBinaries-scoped to a placeholder path
// that nothing on the test host ever actually executes (step-03a-review.md
// R3-E3: test policies must be scoped so they can never match anything
// outside the test), so it loads and can be listed/digested but never
// fires, affects, or enforces against any real process.
func itestPolicyYAML(name string) string {
	return fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: %q
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    selectors:
      - matchBinaries:
        - operator: "In"
          values:
          - "/tmp/testbin-agent-itest/placeholder"
        matchActions:
        - action: "Post"
`, name)
}

// TestIntegration_AgentRestartPersistsEpochAndLKG implements step-04c.md
// Part E7: apply a bundle, simulate an agent restart (close and re-open
// the store, run Startup), confirm the epoch and the LKG persisted and
// the LKG re-verifies (ADR 0025), replay the same bundle and confirm
// REJECTED_EPOCH, and confirm Tetragon's loaded set was never changed by
// the restart.
func TestIntegration_AgentRestartPersistsEpochAndLKG(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	client := dialIntegration(t)

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-itest-key-0123456789abcde")}
	counter := store.NewFakeMonotonicCounter()

	rootEnv, _, targetsKey := standardRootWithTargetsKey(t, 1, now.Add(365*24*time.Hour))
	cfg := agent.Config{
		StoreDir:         dir,
		Sealer:           sealer,
		Counter:          counter,
		InitialRootBytes: rootEnv,
		Auditor:          &agent.FakeAuditor{},
	}

	res1, err := agent.Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if !res1.FirstBoot {
		t.Fatalf("FirstBoot = false on the very first Startup, want true")
	}

	e1 := apply.NewEngine(client, apply.RealPolicyParser{}, res1.Store, &apply.FakeReachabilityChecker{ReachableValue: true}, &apply.FakeAuditor{}, apply.Config{
		PersistDir:   t.TempDir(),
		HealthWindow: apply.HealthWindowConfig{Window: 15 * time.Second, PollInterval: time.Second},
	})

	policyYAML := itestPolicyYAML("itest-agent-restart")
	envelope := buildBundleEnvelope(t, targetsKey, "itest", "enforce", 1, now, []bundlePolicySpec{
		{name: "itest-agent-restart", version: 1, yaml: policyYAML},
	})
	tv, err := res1.TrustRoot.TargetsVerifier(now)
	if err != nil {
		t.Fatalf("TargetsVerifier: %v", err)
	}

	result1 := verify.Verify(verify.Input{
		Envelope:        envelope,
		Now:             now,
		HostUUID:        "11111111-1111-4111-8111-111111111111",
		AllowedScopes:   []string{"itest"},
		TetragonVersion: "1.8.0",
		Trust:           tv,
		RootVersion:     res1.TrustRoot.Version,
		Epochs:          res1.Store,
		PolicyParser:    realLKGPolicyParser{},
		Guardrails:      allowAllGuardrailsFake{},
	})
	if result1.Code != verify.CodeAccept {
		t.Fatalf("first Verify = %v (%s), want CodeAccept", result1.Code, result1.Reason)
	}

	applyRes, err := e1.Apply(context.Background(), &result1)
	if err != nil || applyRes.Status != apply.StatusApplied {
		t.Fatalf("Apply: res=%+v err=%v", applyRes, err)
	}
	// Part D1's documented ordering ("persist a scope's epoch only after
	// a successful apply"): relayd main()'s own orchestration (step 6,
	// not yet built) is what would call this in production; this test
	// calls it directly, in the same place, to exercise the real
	// persisted-epoch/replay-rejection path end to end.
	if err := res1.Store.RecordEpoch("itest", 1); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	loadedBeforeRestart, err := client.ListTracingPolicies(ctx, apply.RelayDomain)
	cancel()
	if err != nil {
		t.Fatalf("ListTracingPolicies before restart: %v", err)
	}
	if len(loadedBeforeRestart) == 0 {
		t.Fatalf("no relay-managed policies loaded after Apply")
	}

	// Simulate an agent restart: close the store (as a real relayd
	// process exiting would release its flock) and run Startup again
	// against the SAME directory/sealer/counter, with NO RPM-shipped
	// root configured (the persisted one must be used as is) and no
	// call to Tetragon at all in between.
	if err := res1.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cfg.InitialRootBytes = nil
	res2, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("restart Startup: %v (the persisted epoch/LKG must re-verify cleanly)", err)
	}
	if res2.FirstBoot {
		t.Fatalf("FirstBoot = true on restart, want false")
	}

	gotEpoch, err := res2.Store.Current("itest")
	if err != nil {
		t.Fatalf("Current after restart: %v", err)
	}
	if gotEpoch != 1 {
		t.Fatalf("Current(itest) after restart = %d, want 1 (the epoch must survive the restart)", gotEpoch)
	}
	lkg, ok := res2.Store.Get(apply.RelayDomain)
	if !ok {
		t.Fatalf("Get(%s) after restart: ok = false, want the LKG to have survived", apply.RelayDomain)
	}
	if len(lkg.RawEnvelope) == 0 || lkg.RootVersion != res1.TrustRoot.Version {
		t.Fatalf("LKG after restart = %+v, want the original RawEnvelope/RootVersion to have survived", lkg)
	}

	// Replay: the exact same envelope, same epoch, verified again against
	// the now-restarted (but otherwise identical) trust root and the
	// REAL, persisted epoch source -- must be rejected.
	tv2, err := res2.TrustRoot.TargetsVerifier(now.Add(time.Hour))
	if err != nil {
		t.Fatalf("TargetsVerifier after restart: %v", err)
	}
	result2 := verify.Verify(verify.Input{
		Envelope:        envelope,
		Now:             now.Add(time.Hour),
		HostUUID:        "11111111-1111-4111-8111-111111111111",
		AllowedScopes:   []string{"itest"},
		TetragonVersion: "1.8.0",
		Trust:           tv2,
		RootVersion:     res2.TrustRoot.Version,
		Epochs:          res2.Store,
		PolicyParser:    realLKGPolicyParser{},
		Guardrails:      allowAllGuardrailsFake{},
	})
	if result2.Code != verify.CodeRejectedEpoch {
		t.Fatalf("replay Verify = %v (%s), want CodeRejectedEpoch", result2.Code, result2.Reason)
	}

	// Tetragon's own loaded set must be byte-for-byte unchanged by the
	// restart simulation: no RPC was made to it between the two
	// ListTracingPolicies calls.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	loadedAfterRestart, err := client.ListTracingPolicies(ctx2, apply.RelayDomain)
	cancel2()
	if err != nil {
		t.Fatalf("ListTracingPolicies after restart: %v", err)
	}
	if len(loadedAfterRestart) != len(loadedBeforeRestart) {
		t.Fatalf("Tetragon's loaded set changed across the restart: before=%v after=%v", loadedBeforeRestart, loadedAfterRestart)
	}
	beforeNames := make(map[string]bool, len(loadedBeforeRestart))
	for _, s := range loadedBeforeRestart {
		beforeNames[s.Name] = true
	}
	for _, s := range loadedAfterRestart {
		if !beforeNames[s.Name] {
			t.Fatalf("Tetragon's loaded set changed across the restart: before=%v after=%v", loadedBeforeRestart, loadedAfterRestart)
		}
	}

	if err := res2.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
