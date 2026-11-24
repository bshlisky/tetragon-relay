//go:build integration

// Package apply integration tests (step 3 prompt Part E3). These run only
// with -tags integration, against a REAL Tetragon v1.8.0 daemon listening
// on /var/run/tetragon/tetragon.sock (started by .github/workflows/ci.yml's
// "integration" job, or scripts/e2e-rhel9.sh on a real RHEL 9 host/VM).
// They are NOT run by `make ci` / the default `go test ./...` and have not
// been executed from this development environment (no Linux host with a
// real Tetragon daemon was available); see docs/reports/step-03.md section
// 13 for what that means for this file's own review status.
package apply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
	"github.com/bshlisky/tetragon-relay/internal/verify"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

const integrationSocket = "/var/run/tetragon/tetragon.sock"

// newIntegrationEngine builds an Engine configured the way a real relayd
// would be: PersistUID/PersistGID are THIS (unprivileged) process's own
// uid and the tetragon-relay group's gid, never 0 — relayd itself runs as
// an unprivileged user (packaging/systemd/tetragon-relay.service's
// User=tetragon-relay, not root), so PersistDir's chown target must be
// something this process can actually set; chowning to uid 0 would fail
// with EPERM for the same reason the integration test suite itself is
// deliberately run unprivileged (step 3 prompt Part E3).
func newIntegrationEngine(t *testing.T, client *tetra.Client) *Engine {
	t.Helper()
	return newIntegrationEngineWithPersistDir(t, client, t.TempDir())
}

func newIntegrationEngineWithPersistDir(t *testing.T, client *tetra.Client, persistDir string) *Engine {
	t.Helper()
	g, err := user.LookupGroup("tetragon-relay")
	if err != nil {
		t.Fatalf("lookup tetragon-relay group: %v", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		t.Fatalf("parse tetragon-relay gid %q: %v", g.Gid, err)
	}
	return NewEngine(client, RealPolicyParser{}, NewFakeLKGStore(), &FakeReachabilityChecker{ReachableValue: true}, &FakeAuditor{}, Config{
		PersistDir:   persistDir,
		PersistUID:   os.Getuid(),
		PersistGID:   gid,
		HealthWindow: HealthWindowConfig{Window: 15 * time.Second, PollInterval: time.Second},
	})
}

func dialIntegration(t *testing.T) *tetra.Client {
	t.Helper()
	cfg := tetra.Config{
		SocketPath:         integrationSocket,
		TetragonBinaryPath: mustLookPath(t, "tetragon"),
		RelayGroupName:     "tetragon-relay",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := tetra.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial(real Tetragon): %v", err)
	}
	// step-03a-review.md R3-E3 fix F1: every integration test must leave
	// Tetragon clean, regardless of how it ends (pass, fail, or a policy
	// it loaded was never meant to be deleted by Apply's own logic, as
	// with TestIntegration_ForeignPolicyLeftUntouched's intentionally
	// foreign policy). This CI job's Tetragon instance exists solely for
	// this test suite, so deleting every loaded policy after each test
	// function returns is safe and simpler than tracking exactly which
	// policy each test loaded.
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

// newIntegrationEngineWithAuditor is like newIntegrationEngine but also
// returns the *FakeAuditor, so a test can inspect which health-window
// failure reason (if any) drove a rollback, not just Apply's final Status.
func newIntegrationEngineWithAuditor(t *testing.T, client *tetra.Client) (*Engine, *FakeAuditor) {
	t.Helper()
	g, err := user.LookupGroup("tetragon-relay")
	if err != nil {
		t.Fatalf("lookup tetragon-relay group: %v", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		t.Fatalf("parse tetragon-relay gid %q: %v", g.Gid, err)
	}
	auditor := &FakeAuditor{}
	e := NewEngine(client, RealPolicyParser{}, NewFakeLKGStore(), &FakeReachabilityChecker{ReachableValue: true}, auditor, Config{
		PersistDir:   t.TempDir(),
		PersistUID:   os.Getuid(),
		PersistGID:   gid,
		HealthWindow: HealthWindowConfig{Window: 15 * time.Second, PollInterval: time.Second},
	})
	return e, auditor
}

// TestIntegration_LoadMonitorBundle_ThenUpgradeToEnforce covers the first
// two scenarios step 3 prompt Part E3 names: load a monitor bundle, then
// upgrade it to enforce, against a real Tetragon.
func TestIntegration_LoadMonitorBundle_ThenUpgradeToEnforce(t *testing.T) {
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	e := newIntegrationEngine(t, client)

	canaryYAML := canaryPolicyYAML("itest-canary", "Sigkill")
	monitorResult := acceptedBundleYAML("monitor", "itest-canary", 1, canaryYAML)
	res, err := e.Apply(context.Background(), monitorResult)
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("monitor apply: res=%+v err=%v", res, err)
	}

	enforceResult := acceptedBundleYAML("enforce", "itest-canary", 2, canaryYAML)
	res, err = e.Apply(context.Background(), enforceResult)
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("enforce apply: res=%+v err=%v", res, err)
	}
}

// TestIntegration_EnforcementKillsCanary_AdminPathSurvives covers the
// "prove enforcement with a canary binary" scenario: a policy that Sigkills
// a copy of a test binary, verified to actually kill it, while
// /usr/bin/bash running a harmless command survives.
func TestIntegration_EnforcementKillsCanary_AdminPathSurvives(t *testing.T) {
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	canaryPath := buildCanaryBinary(t, "/tmp/testbin-canary")
	e := newIntegrationEngine(t, client)

	yaml := canaryPolicyYAML("itest-kill-canary", "Sigkill")
	yaml = withBinaryPath(yaml, canaryPath)
	if res, err := e.Apply(context.Background(), acceptedBundleYAML("enforce", "itest-kill-canary", 1, yaml)); err != nil || res.Status != StatusApplied {
		t.Fatalf("apply: res=%+v err=%v", res, err)
	}

	cmd := exec.Command(canaryPath)
	if err := cmd.Run(); err == nil {
		t.Fatal("canary binary was not killed by the enforcement policy")
	}

	if out, err := exec.Command("/usr/bin/bash", "-c", "cat /etc/hostname").CombinedOutput(); err != nil {
		t.Fatalf("/usr/bin/bash running `cat /etc/hostname` did not survive: %v: %s", err, out)
	}
}

// adminPathPolicyYAML builds a Sigkill policy on the real "/usr/bin/bash"
// admin-path entry (internal/apply/admin.go's compiled-in,
// non-configurable adminPathBinaries map; architect review R2D-1/DN-1,
// docs/reviews/step-02d-review.md). matchPIDs scopes enforcement to pid
// (this test's own process) and its descendants only (followForks: true;
// tetragon.io/docs/concepts/tracing-policy/selectors/, "PIDs filter":
// "Matches any descendant processes of the matching PIDs"), so a real
// "/usr/bin/bash" invocation anywhere else on the host — including the CI
// runner's own step-execution shell — is never affected.
// isNamespacePID: false matches the host PID, which is what this test's
// own exec.Command-spawned child actually has (tetragon.io/docs/reference/
// tracing-policy/, TracingPolicy.spec.kprobes[].selectors[].matchPIDs[]).
func adminPathPolicyYAML(name string, pid int) string {
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
          - "/usr/bin/bash"
        matchPIDs:
        - operator: "In"
          followForks: true
          isNamespacePID: false
          values:
          - %d
        matchActions:
        - action: "Sigkill"
`, name, pid)
}

// TestIntegration_RollbackOnAdminPathKill covers the "rollback when the
// health window sees a forbidden admin-path kill" scenario, against the
// real, compiled-in "/usr/bin/bash" admin-path entry (not a configurable
// test-only addition: admin.go's own doc comment is explicit that this
// package does not add a config knob for the admin-path set). Scoped via
// matchPIDs to this test's own process tree (step-03a-review.md R3-E3 fix
// F1/F2's intent — never affect anything outside this test — achieved by
// PID scoping rather than path scoping, since testing the real,
// non-configurable admin-path list requires using one of its real paths).
//
// security_bprm_check's process/matchBinaries describe the CALLER of
// exec, not the binary image about to replace it (ADR 0020): bash must
// itself exec something external to trigger the hook at all, and two
// external commands (not one) avoid bash's single-trailing-command exec
// tail-call optimization, which would otherwise replace bash's own image
// before ever calling security_bprm_check again as a distinct caller.
func TestIntegration_RollbackOnAdminPathKill(t *testing.T) {
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	e, auditor := newIntegrationEngineWithAuditor(t, client)

	pid := os.Getpid()
	yaml := adminPathPolicyYAML("itest-admin-kill", pid)

	// Resolve the loaded name exactly as Engine.resolve() will (no mode
	// rewrite happens in enforce mode, so finalJSON == canonicalJSON),
	// so this test can subscribe to the same events Apply's own health
	// window will, independently of Apply's internal bookkeeping, and
	// assert on their actual fields.
	doc, err := RealPolicyParser{}.Parse("itest-admin-kill", yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	loadedName, err := LoadedName("itest-admin-kill", 1, doc.CanonicalJSON())
	if err != nil {
		t.Fatalf("LoadedName: %v", err)
	}

	eventsCtx, cancelEvents := context.WithCancel(context.Background())
	events, errc := client.GetEvents(eventsCtx, []string{loadedName})

	var mu sync.Mutex
	var firstEventAt time.Time
	var firstEventBinary string
	sawKillEvent := false
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					return
				}
				if ev.Kprobe == nil {
					continue
				}
				mu.Lock()
				if firstEventAt.IsZero() {
					firstEventAt = time.Now()
					firstEventBinary = ev.Kprobe.GetProcess().GetBinary()
				}
				if ev.Kprobe.GetAction() == tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL {
					sawKillEvent = true
				}
				mu.Unlock()
			case _, ok := <-errc:
				if !ok {
					return
				}
			}
		}
	}()

	stop := make(chan struct{})
	bgDone := make(chan struct{})
	sawExecKilled := false
	go func() {
		defer close(bgDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			cmd := exec.Command("/usr/bin/bash", "-c", "/usr/bin/true; /usr/bin/true")
			runErr := cmd.Run()
			if runErr != nil && cmd.ProcessState != nil {
				if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
					mu.Lock()
					sawExecKilled = true
					mu.Unlock()
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()

	applyStartedAt := time.Now()
	res, applyErr := e.Apply(context.Background(), acceptedBundleYAML("enforce", "itest-admin-kill", 1, yaml))

	close(stop)
	<-bgDone
	cancelEvents()
	<-watchDone

	if applyErr == nil {
		t.Fatal("Apply succeeded despite targeting an admin-path binary; expected a rollback")
	}
	if res == nil || res.Status != StatusRolledBack {
		t.Fatalf("res=%+v err=%v, want StatusRolledBack", res, applyErr)
	}

	mu.Lock()
	gotFirstEventAt, gotBinary, gotKillEvent, gotExecKilled := firstEventAt, firstEventBinary, sawKillEvent, sawExecKilled
	mu.Unlock()

	if gotFirstEventAt.IsZero() {
		t.Fatal("no security_bprm_check event observed for /usr/bin/bash")
	}
	// E1 (step-03a-review.md R3-E3): elapsed time from Apply() starting
	// (which itself calls AddTracingPolicy before opening the health
	// window's own GetEvents subscription) to this test's independent
	// subscription seeing the first matching event. This is a slight
	// over-estimate of pure BPF-attach latency (it also includes
	// AddTracingPolicy's own round trip and this goroutine's own
	// scheduling), not an exact measurement of it alone.
	t.Logf("E1: Apply() start -> first matching security_bprm_check event: %s", gotFirstEventAt.Sub(applyStartedAt))
	if gotBinary != "/usr/bin/bash" {
		t.Errorf("observed event process.binary = %q, want /usr/bin/bash", gotBinary)
	}
	if !gotKillEvent {
		t.Error("no KPROBE_ACTION_SIGKILL event observed")
	}
	if !gotExecKilled {
		t.Error("the exec loop never observed a bash process terminated by SIGKILL")
	}
	// The event's pid is a descendant of this test's own pid by
	// construction, not independently re-verified here: the policy's own
	// matchPIDs (operator In, followForks: true, values: [pid]) is what
	// the kernel enforces before this process ever sees an event or a
	// kill at all, so observing either one already proves it; re-reading
	// /proc post-mortem for an already-SIGKILL'd (and possibly already
	// reaped) process would be racy without adding any real assurance.

	foundAdminPathAudit := false
	for _, ev := range auditor.Events {
		if ev.Step == "health_window_failed" && ev.Detail == string(reasonAdminPathEnforced) {
			foundAdminPathAudit = true
		}
	}
	if !foundAdminPathAudit {
		t.Error("no health_window_failed audit event with reason admin_path_enforcement_event was recorded")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	statuses, err := client.ListTracingPolicies(ctx, RelayDomain)
	if err != nil {
		t.Fatalf("ListTracingPolicies: %v", err)
	}
	if len(statuses) != 0 {
		t.Errorf("relay-managed policies still loaded after rollback: %v", statuses)
	}
}

// TestIntegration_RestartReloadsPersistedSet covers "Tetragon restart
// reloads the persisted set from the policy dir": this test only verifies
// internal/apply.PersistDir wrote files Tetragon's own --tracing-policy-dir
// loader (cmd/tetragon/main.go:694-726, ADR 0016) would read; actually
// restarting the system Tetragon process is left to scripts/e2e-rhel9.sh's
// manual procedure, not automated here.
func TestIntegration_RestartReloadsPersistedSet(t *testing.T) {
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	dir := "/etc/tetragon/tetragon.tp.d/relay"
	e := newIntegrationEngineWithPersistDir(t, client, dir)
	yaml := canaryPolicyYAML("itest-persist", "Post")
	if res, err := e.Apply(context.Background(), acceptedBundleYAML("enforce", "itest-persist", 1, yaml)); err != nil || res.Status != StatusApplied {
		t.Fatalf("apply: res=%+v err=%v", res, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("PersistDir did not write into %s: %v (%d entries)", dir, err, len(entries))
	}
}

// TestIntegration_ForeignPolicyLeftUntouched loads a policy directly via
// a second, independent client with no relay-managed domain, and confirms
// Apply never deletes it.
func TestIntegration_ForeignPolicyLeftUntouched(t *testing.T) {
	foreignClient := dialIntegration(t)
	defer func() { _ = foreignClient.Close() }()
	if err := foreignClient.AddTracingPolicy(context.Background(), canaryPolicyYAML("itest-foreign", "Post"), ""); err != nil {
		t.Fatalf("load foreign policy: %v", err)
	}

	client := dialIntegration(t)
	defer func() { _ = client.Close() }()
	e := newIntegrationEngine(t, client)
	if res, err := e.Apply(context.Background(), acceptedBundleYAML("enforce", "itest-managed", 1, canaryPolicyYAML("itest-managed", "Post"))); err != nil || res.Status != StatusApplied {
		t.Fatalf("apply: res=%+v err=%v", res, err)
	}

	list, err := client.ListTracingPolicies(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range list {
		if p.Name == "itest-foreign" {
			found = true
		}
	}
	if !found {
		t.Fatal("foreign policy was removed")
	}
}

func canaryPolicyYAML(name, action string) string {
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
          - "/tmp/testbin/placeholder"
        matchActions:
        - action: %q
`, name, action)
}

func withBinaryPath(yaml, path string) string {
	return replaceAllLiteral(yaml, "/tmp/testbin/placeholder", path)
}

func replaceAllLiteral(s, old, newStr string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + newStr
		s = s[i+len(old):]
	}
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func acceptedBundleYAML(mode, name string, version int, yaml string) *verify.Result {
	sum := sha256.Sum256([]byte(yaml))
	return &verify.Result{
		Code: verify.CodeAccept,
		Bundle: &verify.Bundle{
			Scope: "itest",
			Mode:  mode,
			Policies: []verify.Policy{
				{Name: name, Version: version, SHA256: hex.EncodeToString(sum[:]), YAML: yaml},
			},
		},
	}
}

func buildCanaryBinary(t *testing.T, path string) string {
	t.Helper()
	src := "package main\nfunc main() { select {} }\n"
	dir := t.TempDir()
	mainGo := dir + "/main.go"
	if err := os.WriteFile(mainGo, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/tmp/testbin", 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", path, mainGo)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build canary binary: %v: %s", err, out)
	}
	return path
}
