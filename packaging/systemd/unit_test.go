// Package systemd holds packaging/systemd/tetragon-relay.service plus a
// test (step-03a-review.md R3-3: "CI must mirror production") that parses
// it directly, so a future change that widens the unit's privilege or
// writable paths fails the build rather than silently drifting from
// architecture doc section 8.6/8.7.
package systemd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// wantReadWritePaths is architecture doc section 8.6's filesystem table:
// the relay's own state directory, its spool directory, and the one
// subdirectory of Tetragon's policy directory internal/apply.PersistDir
// manages. These are the only three paths the production unit may ever
// grant write access to.
var wantReadWritePaths = []string{
	"/var/lib/tetragon-relay",
	"/var/spool/tetragon-relay",
	"/etc/tetragon/tetragon.tp.d/relay",
}

func unitFilePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed to resolve this test file's own path")
	}
	return filepath.Join(filepath.Dir(thisFile), "tetragon-relay.service")
}

// parseUnitDirectives is a minimal systemd unit file parser: it reads
// "Key=Value" lines (ignoring blank lines, "#"-comments, and "[Section]"
// headers) into a map. It is intentionally not a general INI parser (this
// test only needs to read a handful of [Service] directives out of one
// specific, repo-owned file), and deliberately does not resolve repeated
// keys (systemd itself has per-directive repetition semantics that do not
// matter here, since this file sets each of the directives this test
// cares about exactly once).
func parseUnitDirectives(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is this package's own fixed source file, not attacker-controlled
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		out[key] = val
	}
	return out
}

// execStartPreLines returns every "ExecStartPre=" directive's value, in
// file order (parseUnitDirectives' map collapses repeated keys to the
// last one, which is wrong for ExecStartPre: systemd runs every
// occurrence, in order).
func execStartPreLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is this package's own fixed source file, not attacker-controlled
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if val, ok := strings.CutPrefix(line, "ExecStartPre="); ok {
			out = append(out, val)
		}
	}
	return out
}

// TestProductionUnit_ProvisionsTPMBeforeHostFacts implements
// docs/prompts/step-05a.md Part C3: the TPM NV counter index must be
// provisioned (relay-probe --provision-tpm, root via the leading "+") on
// every unit start, before relayd itself is ever exec'd, and before (or
// at least alongside) the existing host-facts probe -- both are
// ExecStartPre=+ lines run as root ahead of the unprivileged ExecStart.
func TestProductionUnit_ProvisionsTPMBeforeHostFacts(t *testing.T) {
	lines := execStartPreLines(t, unitFilePath(t))
	var tpmIdx, factsIdx = -1, -1
	for i, l := range lines {
		if strings.Contains(l, "--provision-tpm") {
			tpmIdx = i
		}
		if strings.Contains(l, "--facts-path") {
			factsIdx = i
		}
	}
	if tpmIdx < 0 {
		t.Fatalf("no ExecStartPre= line invokes relay-probe --provision-tpm; lines = %v", lines)
	}
	if !strings.HasPrefix(lines[tpmIdx], "+") {
		t.Errorf("the --provision-tpm ExecStartPre line does not start with '+' (must run as root: owner authorization is required to define the NV index): %q", lines[tpmIdx])
	}
	if !strings.Contains(lines[tpmIdx], "--tpm-device /dev/tpmrm0") {
		t.Errorf("the --provision-tpm ExecStartPre line does not pin --tpm-device to /dev/tpmrm0 (architecture doc 8.6: never /dev/tpm0): %q", lines[tpmIdx])
	}
	if factsIdx < 0 {
		t.Fatalf("no ExecStartPre= line invokes relay-probe's host-facts mode; lines = %v", lines)
	}
	if tpmIdx > factsIdx {
		t.Errorf("TPM provisioning (index %d) runs AFTER the host-facts probe (index %d); order is not required by the architecture doc but this test pins the current, deliberate order", tpmIdx, factsIdx)
	}
}

// TestProductionUnit_NoCapabilities implements step-03a-review.md R3-3:
// the production unit must grant no capabilities at all. R3-1 reverted
// commit 6be5137's CAP_SYS_PTRACE grant (architecture doc P9/section 8.7:
// "no capabilities"); this test fails the build if either capability
// directive is ever reintroduced, non-empty, in either direction
// (CapabilityBoundingSet alone, without AmbientCapabilities, would still
// let the process retain the capability across exec via file capabilities
// on its own binary — both must be empty).
func TestProductionUnit_NoCapabilities(t *testing.T) {
	directives := parseUnitDirectives(t, unitFilePath(t))
	for _, key := range []string{"CapabilityBoundingSet", "AmbientCapabilities"} {
		got, ok := directives[key]
		if !ok {
			t.Fatalf("%s is not set at all in the unit file (want present and empty)", key)
		}
		if got != "" {
			t.Errorf("%s = %q, want empty (no capabilities granted)", key, got)
		}
	}
}

// TestProductionUnit_ReadWritePathsExactlySectionEightSix implements
// step-03a-review.md R3-3: the unit may grant write access to exactly
// architecture doc section 8.6's three relay-owned paths and nothing
// else, in the documented order — R3-2's whole point was ensuring
// PersistDir never needs anything beyond .../tetragon.tp.d/relay, so a
// future change widening ReadWritePaths= (to make some other change
// "just work") fails this test instead of silently drifting from
// production's least-privilege posture.
func TestProductionUnit_ReadWritePathsExactlySectionEightSix(t *testing.T) {
	directives := parseUnitDirectives(t, unitFilePath(t))
	got, ok := directives["ReadWritePaths"]
	if !ok {
		t.Fatal("ReadWritePaths is not set in the unit file")
	}
	gotPaths := strings.Fields(got)
	if len(gotPaths) != len(wantReadWritePaths) {
		t.Fatalf("ReadWritePaths = %v, want exactly %v", gotPaths, wantReadWritePaths)
	}
	for i, p := range wantReadWritePaths {
		if gotPaths[i] != p {
			t.Errorf("ReadWritePaths[%d] = %q, want %q", i, gotPaths[i], p)
		}
	}
}
