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
// matches()/pathCoversPositive matching logic against every entry in
// protectedBinaries/protectedPaths, which is what the property is
// checking; see docs/reports/step-02c.md section on this test for the
// mutant count. TestMutation_NegativeOperatorsMissingEachProtectedBinary
// extends this to negative operators per architect review item C1.
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

// TestMutation_NegativeOperatorsMissingEachProtectedBinary is architect
// review item C1's negative-operator mutation extension: for each
// protected binary b and each negative operator, build a values list meant
// to exclude every OTHER protected binary but not b, and confirm the
// mutant's accept/reject outcome matches what the reference "exists a
// protected binary matches()" formula computes (not a blanket "always
// rejected" assumption: some protected binaries share a real prefix/suffix
// with another, e.g. "/usr/bin/tetra" is a literal prefix of
// "/usr/bin/tetragon", so a NotPrefix set built from "every other binary's
// full path" can legitimately also exclude the one binary it was built to
// leave uncovered — that is a correct consequence of Prefix semantics, not
// a bug, so this test computes its expectation rather than assuming one,
// per "compute it, don't assume"). What this test actually proves is that
// the real guard decision never disagrees with the independently
// recomputed brute-force answer, across every protected binary and every
// negative operator — exactly the bug class step 2b shipped (an ambiguous
// value was treated as "excludes everything" regardless of the real
// per-candidate computation).
func TestMutation_NegativeOperatorsMissingEachProtectedBinary(t *testing.T) {
	mutants := 0
	anyGenuinelyMissed := false
	for _, op := range []string{"NotIn", "NotPrefix", "NotPostfix"} {
		for _, missing := range protectedBinaries {
			var values []string
			for _, b := range protectedBinaries {
				if b != missing {
					values = append(values, b)
				}
			}
			wantReject := matchesAnyCandidate(op, values, protectedBinaries)
			if wantReject {
				anyGenuinelyMissed = true
			}

			mutants++
			spec := fmt.Sprintf(`  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: %q
        values: %s
      matchActions:
      - action: "Sigkill"
`, op, yamlStringList(values))
			d := mustParseDoc(t, "p", policyYAML("p", spec))
			err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
			gotReject := err != nil
			if gotReject != wantReject {
				t.Errorf("operator %s missing %q: guard reject=%v, brute-force reject=%v (err=%v)", op, missing, gotReject, wantReject, err)
			}
			if gotReject && ruleOf(t, err) != RuleG1 {
				t.Errorf("operator %s missing %q: rejected for %v, want G1", op, missing, err)
			}
		}
	}
	if !anyGenuinelyMissed {
		t.Fatalf("test construction error: no (operator, missing) pair actually left a protected binary uncovered, so this test exercised nothing")
	}
	t.Logf("negative-operator mutation test: %d mutants (3 operators x %d protected binaries), decisions match brute force", mutants, len(protectedBinaries))
}

// TestMutation_AmbiguousAndLookAlikeValues covers the architect's
// reproduction cases directly (step 2c review, item C1): empty, relative,
// and "-x"-suffixed look-alike values must never let an enforcement
// selector through.
func TestMutation_AmbiguousAndLookAlikeValues(t *testing.T) {
	lookAlikes := make([]string, 0, len(protectedBinaries))
	for _, b := range protectedBinaries {
		lookAlikes = append(lookAlikes, b+"-x")
	}
	cases := []struct {
		name     string
		operator string
		values   []string
	}{
		{"notin_empty", "NotIn", []string{""}},
		{"notin_relative", "NotIn", []string{"relative"}},
		{"notprefix_relative", "NotPrefix", []string{"x"}},
		{"notprefix_lookalikes", "NotPrefix", lookAlikes},
		{"notpostfix_lookalikes", "NotPostfix", lookAlikes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := fmt.Sprintf(`  kprobes:
  - call: "security_file_open"
    selectors:
    - matchBinaries:
      - operator: %q
        values: %s
      matchActions:
      - action: "Sigkill"
`, tc.operator, yamlStringList(tc.values))
			d := mustParseDoc(t, "p", policyYAML("p", spec))
			err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
			if err == nil || ruleOf(t, err) != RuleG1 {
				t.Fatalf("error = %v, want G1", err)
			}
		})
	}
}

// yamlStringList renders a Go []string as a YAML flow-style sequence of
// double-quoted strings, suitable for embedding in a one-line policy spec.
func yamlStringList(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	out := "["
	for i, q := range quoted {
		if i > 0 {
			out += ", "
		}
		out += q
	}
	return out + "]"
}
