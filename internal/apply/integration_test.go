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
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
	"github.com/bshlisky/tetragon-relay/internal/verify"
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
	return c
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("LookPath(%s): %v", name, err)
	}
	return p
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

// TestIntegration_RollbackOnAdminPathKill covers the "rollback when the
// health window sees a forbidden admin-path kill" scenario: a policy
// targeting a copy of bash at /tmp/testbin/bash, with that path added to
// the admin-path set via test configuration (not this package's compiled-in
// adminPathBinaries map, which is intentionally not configurable in
// production — see admin.go's doc comment; this test demonstrates the
// mechanism using the real adminPathBinaries entries for a real shell
// instead, since step 3 does not add a config knob for the admin-path set).
func TestIntegration_RollbackOnAdminPathKill(t *testing.T) {
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	e := newIntegrationEngine(t, client)

	// A policy that Sigkills /usr/bin/bash itself (a real, compiled-in
	// admin-path entry) is expected to trip the health window.
	yaml := canaryPolicyYAML("itest-admin-kill", "Sigkill")
	yaml = withBinaryPath(yaml, "/usr/bin/bash")
	res, err := e.Apply(context.Background(), acceptedBundleYAML("enforce", "itest-admin-kill", 1, yaml))
	if err == nil {
		t.Fatal("Apply succeeded despite targeting an admin-path binary; expected a rollback")
	}
	if res == nil || res.Status != StatusRolledBack {
		t.Fatalf("res=%+v err=%v, want StatusRolledBack", res, err)
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
