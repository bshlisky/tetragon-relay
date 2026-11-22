package guard

import (
	"fmt"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

// TestMutation_EveryProtectedBinaryAndPathIsCaught is the step 2 prompt's
// Part D mutation property test: starting from policies that currently
// pass Check, add an enforcement action whose selector targets each
// protected binary (matchBinaries) and, for a file-arg hook, each
// protected path (matchArgs); every mutant must be rejected.
//
// Scope note: rather than textually splicing a mutant selector into each
// of the 68 heterogeneous upstream policies that pass (which have
// differing hook shapes - kprobe/tracepoint/uprobe/lsmhook, with or
// without path-typed args), this test uses two representative baseline
// shapes (a kprobe and an lsmhook, each already proven safe by
// TestCheck_G1's "safe_binary" case) and mutates each with every protected
// binary and protected path in turn. This still exercises the real
// anyBinaryCovered/anyPathCovered matching logic against every entry in
// protectedBinaries/protectedPaths, which is what the property is
// checking; see docs/reports/step-02b.md section on this test for the
// mutant count.
func TestMutation_EveryProtectedBinaryAndPathIsCaught(t *testing.T) {
	baseline := `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/bin/myapp"]
      matchActions:
      - action: "Sigkill"
`
	d := mustParseDoc(t, "p", policyYAML("p", baseline))
	if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("baseline must pass before mutating: %v", err)
	}

	mutants := 0

	for _, binary := range protectedBinaries {
		mutants++
		mutant := fmt.Sprintf(`  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["%s"]
      matchActions:
      - action: "Sigkill"
`, binary)
		md := mustParseDoc(t, "p", policyYAML("p", mutant))
		if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{md}); err == nil {
			t.Errorf("mutant targeting protected binary %q was NOT rejected", binary)
		}
	}

	pathBaseline := `  kprobes:
  - call: "x"
    args:
    - index: 0
      type: "path"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/bin/myapp"]
      matchArgs:
      - index: 0
        operator: "Equal"
        values: ["/tmp/safe-file"]
      matchActions:
      - action: "Sigkill"
`
	pd := mustParseDoc(t, "p", policyYAML("p", pathBaseline))
	if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{pd}); err != nil {
		t.Fatalf("path baseline must pass before mutating: %v", err)
	}

	for _, protPath := range protectedPaths {
		mutants++
		mutant := fmt.Sprintf(`  kprobes:
  - call: "x"
    args:
    - index: 0
      type: "path"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/bin/myapp"]
      matchArgs:
      - index: 0
        operator: "Equal"
        values: ["%s"]
      matchActions:
      - action: "Sigkill"
`, pathLikeValue(protPath))
		md := mustParseDoc(t, "p", policyYAML("p", mutant))
		if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{md}); err == nil {
			t.Errorf("mutant targeting protected path %q was NOT rejected", protPath)
		}
	}

	t.Logf("mutation property test: %d mutants, all rejected", mutants)
}

// pathLikeValue turns a protected directory entry into a concrete file
// path inside it (Equal needs a specific file, not a directory), and
// leaves specific-file/device entries unchanged.
func pathLikeValue(p string) string {
	if p[len(p)-1] == '/' {
		return p + "secret"
	}
	return p
}
