package guard

import (
	"fmt"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

// TestG1_NonCanonicalValuesFailOpenRepro reproduces architect review item
// D1's four exact probes against a kprobe on security_file_open with
// Sigkill: matchBinaries whose values are every protected binary written
// with a non-canonical spelling must now be rejected, since Tetragon
// compares raw strings and none of these spellings would ever actually
// exclude anything on a real host.
func TestG1_NonCanonicalValuesFailOpenRepro(t *testing.T) {
	cases := []struct {
		name     string
		operator string
		mutate   func(b string) string
	}{
		{"notin_trailing_slash", "NotIn", func(b string) string { return b + "/" }},
		{"notin_doubled_leading_slash", "NotIn", func(b string) string { return "/" + b }},
		{"notin_dot_segment", "NotIn", func(b string) string { return insertDotSegment(b, ".") }},
		{"notprefix_trailing_slash", "NotPrefix", func(b string) string { return b + "/" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := make([]string, len(protectedBinaries))
			for i, b := range protectedBinaries {
				values[i] = tc.mutate(b)
			}
			spec := fmt.Sprintf(`  kprobes:
  - call: "security_file_open"
    selectors:
    - matchBinaries:
      - operator: %q
        values: %s
      matchActions:
      - action: "Sigkill"
`, tc.operator, yamlStringList(values))
			d := mustParseDoc(t, "p", policyYAML("p", spec))
			err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
			if err == nil || ruleOf(t, err) != RuleG1 {
				t.Fatalf("error = %v, want G1", err)
			}
		})
	}
}

// TestG1_NonCanonicalValuesFailOpenRepro_SingleBinary applies each of the
// four non-canonical spellings to exactly ONE entry inside an otherwise
// exact, canonical NotIn list (every other protected binary spelled
// exactly); the mutant must still be rejected, since even one
// non-canonical value makes the whole selector impossible to trust.
func TestG1_NonCanonicalValuesFailOpenRepro_SingleBinary(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(b string) string
	}{
		{"trailing_slash", func(b string) string { return b + "/" }},
		{"doubled_leading_slash", func(b string) string { return "/" + b }},
		{"dot_segment", func(b string) string { return insertDotSegment(b, ".") }},
		{"dotdot_segment", func(b string) string { return insertDotSegment(b, "..") }},
	}
	for _, m := range mutations {
		for _, target := range protectedBinaries {
			t.Run(m.name+"_"+target, func(t *testing.T) {
				values := make([]string, 0, len(protectedBinaries))
				for _, b := range protectedBinaries {
					if b == target {
						values = append(values, m.mutate(b))
					} else {
						values = append(values, b)
					}
				}
				spec := fmt.Sprintf(`  kprobes:
  - call: "security_file_open"
    selectors:
    - matchBinaries:
      - operator: "NotIn"
        values: %s
      matchActions:
      - action: "Sigkill"
`, yamlStringList(values))
				d := mustParseDoc(t, "p", policyYAML("p", spec))
				err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
				if err == nil || ruleOf(t, err) != RuleG1 {
					t.Fatalf("error = %v, want G1", err)
				}
			})
		}
	}
}

// TestMutation_NonCanonicalSpellingInNegativeSweep extends architect
// review item D2's negative mutation sweep (TestMutation_
// NegativeOperatorsMissingEachProtectedBinary, step 2c) with the four
// non-canonical spellings: for NotIn, NotPrefix and NotPostfix, an
// otherwise-exact exclusion list with exactly one entry rewritten in a
// non-canonical spelling is checked against the guard's actual decision.
// The expected outcome is computed via the independent reference
// functions from property_test.go (referenceIsCanonicalValue,
// referenceAnyBinaryMatches), not assumed to always be "rejected": some
// protected binaries are literal prefixes/suffixes of others (e.g.
// "/usr/bin/tetra" of "/usr/bin/tetragon", or any dual-usrmerge-spelled
// binary's short form of its own long form via Postfix), so leaving every
// OTHER entry canonical can already exclude the mutated target by itself,
// independent of what its own entry says - the same real phenomenon step
// 2c's mutation test had to account for, not a test bug introduced here.
func TestMutation_NonCanonicalSpellingInNegativeSweep(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(b string) string
	}{
		{"trailing_slash", func(b string) string { return b + "/" }},
		{"doubled_leading_slash", func(b string) string { return "/" + b }},
		{"dot_segment", func(b string) string { return insertDotSegment(b, ".") }},
		{"dotdot_segment", func(b string) string { return insertDotSegment(b, "..") }},
	}
	mutants := 0
	anyGenuinelyNonCanonical := false
	for _, op := range []string{"NotIn", "NotPrefix", "NotPostfix"} {
		for _, m := range mutations {
			for _, target := range protectedBinaries {
				mutants++
				values := make([]string, 0, len(protectedBinaries))
				for _, b := range protectedBinaries {
					if b == target {
						values = append(values, m.mutate(b))
					} else {
						values = append(values, b)
					}
				}

				allCanonical := true
				for _, v := range values {
					if !referenceIsCanonicalValue(op, v) {
						allCanonical = false
						break
					}
				}
				if !allCanonical {
					anyGenuinelyNonCanonical = true
				}
				wantReject := !allCanonical || referenceAnyBinaryMatches(op, values)

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
					t.Errorf("operator=%s mutation=%s target=%q: guard reject=%v, reference reject=%v (err=%v)", op, m.name, target, gotReject, wantReject, err)
					continue
				}
				if gotReject && ruleOf(t, err) != RuleG1 {
					t.Errorf("operator=%s mutation=%s target=%q: rejected for %v, want G1", op, m.name, target, err)
				}
			}
		}
	}
	if !anyGenuinelyNonCanonical {
		t.Fatalf("test construction error: no mutation actually produced a non-canonical value, so this test exercised nothing")
	}
	t.Logf("non-canonical-spelling negative mutation sweep: %d mutants, decisions match reference", mutants)
}

// TestG1_ExactCanonicalListAccepted confirms the control case: NotIn with
// every protected binary spelled exactly (no mutation at all) is accepted,
// so the rejections above are specifically about non-canonical spelling,
// not about the list being broad.
func TestG1_ExactCanonicalListAccepted(t *testing.T) {
	spec := fmt.Sprintf(`  kprobes:
  - call: "security_file_open"
    selectors:
    - matchBinaries:
      - operator: "NotIn"
        values: %s
      matchActions:
      - action: "Sigkill"
`, yamlStringList(protectedBinaries))
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("exact canonical NotIn list was rejected: %v", err)
	}
}

// insertDotSegment inserts a "." or ".." path segment after the first path
// component of an absolute path, e.g. insertDotSegment("/usr/sbin/sshd",
// "..") = "/usr/../sbin/sshd".
func insertDotSegment(p, segment string) string {
	rest := p[1:]
	idx := 0
	for i, c := range rest {
		if c == '/' {
			idx = i + 1
			break
		}
	}
	return p[:idx] + "/" + segment + p[idx:]
}
