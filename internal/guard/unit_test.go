package guard

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

func TestViolation_Error(t *testing.T) {
	v := &Violation{Rule: RuleG1, Detail: "something"}
	if v.Error() != "guard: rule G1: something" {
		t.Fatalf("Error() = %q", v.Error())
	}
}

func TestSelectorUsesOverride_MatchReturnActions(t *testing.T) {
	s := policydoc.Selector{MatchReturnActions: []policydoc.ActionSelector{{Action: "Override"}}}
	if !selectorUsesOverride(s) {
		t.Fatalf("expected true for Override in MatchReturnActions")
	}
	none := policydoc.Selector{MatchActions: []policydoc.ActionSelector{{Action: "Post"}}}
	if selectorUsesOverride(none) {
		t.Fatalf("expected false")
	}
}

func TestIsExecHook_NonKProbeNonLsm(t *testing.T) {
	h := policydoc.Hook{Kind: policydoc.HookKindTracepoint, Identifier: "security_bprm_check"}
	if isExecHook(h) {
		t.Fatalf("a tracepoint must never be classified as an exec hook")
	}
	h2 := policydoc.Hook{Kind: policydoc.HookKindUProbe, Identifier: "bprm_check_security"}
	if isExecHook(h2) {
		t.Fatalf("a uprobe must never be classified as an exec hook")
	}
}

func TestCoversPrefix_NestedInsideProtectedDirectory(t *testing.T) {
	// A Prefix value naming something nested inside a protected directory
	// (rather than an ancestor of it) must also be covered.
	if !coversPrefix("/run/tetragon/sub/", "/run/tetragon/") {
		t.Fatalf("expected coverage for a prefix nested inside a protected directory")
	}
	if coversPrefix("/completely/unrelated/", "/run/tetragon/") {
		t.Fatalf("expected no coverage for an unrelated prefix")
	}
}

func TestCoversPostfix_DirectoryTarget(t *testing.T) {
	if !coversPostfix("tetragon/", "/run/tetragon/") {
		t.Fatalf("expected coverage: postfix names the protected directory's own trailing segment")
	}
	if coversPostfix("unrelated-suffix", "/run/tetragon/") {
		t.Fatalf("expected no coverage for an unrelated postfix")
	}
}

func TestExcludesAllBinaries_NotPrefix(t *testing.T) {
	if !excludesAllBinaries("NotPrefix", []string{"/"}, nil) {
		t.Fatalf("expected broad NotPrefix values to exclude every protected binary")
	}
	if excludesAllBinaries("NotPrefix", []string{"/usr/sbin/"}, nil) {
		t.Fatalf("expected a narrow NotPrefix to leave some protected binaries uncovered")
	}
}

func TestSelectorValueCount_AllFields(t *testing.T) {
	s := policydoc.Selector{
		MatchPIDs:           []policydoc.PIDSelector{{Values: []uint32{1, 2}}},
		MatchArgs:           []policydoc.ArgSelector{{Values: []string{"a"}}},
		MatchReturnArgs:     []policydoc.ArgSelector{{Values: []string{"b", "c"}}},
		MatchBinaries:       []policydoc.BinarySelector{{Values: []string{"d"}}},
		MatchParentBinaries: []policydoc.BinarySelector{{Values: []string{"e", "f"}}},
	}
	if got := selectorValueCount(s); got != 8 {
		t.Fatalf("selectorValueCount = %d, want 8", got)
	}
}

func TestCheckG5_SkipsPoliciesWithoutEnforcement(t *testing.T) {
	spec := `  kprobes:
  - call: "x"
    selectors:
    - matchActions:
      - action: "Post"
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	// History would error if ever consulted; it must not be, since this
	// policy has no enforcement action.
	g := &Guardrails{Capabilities: allowAllCapabilities, History: fakeHistory{err: errBoom}}
	if err := g.Check(GuardContext{Scope: "s", Mode: "enforce"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtraPaths_NilAndSet(t *testing.T) {
	g := &Guardrails{}
	if got := g.extraPaths(); got != nil {
		t.Fatalf("extraPaths() = %v, want nil", got)
	}
	g2 := &Guardrails{ExtraProtected: fakeProtectedSetSource{paths: []string{"/opt/extra/"}}}
	if got := g2.extraPaths(); len(got) != 1 || got[0] != "/opt/extra/" {
		t.Fatalf("extraPaths() = %v", got)
	}
}

func TestSelectorHasEnforcement_ViaMatchReturnActions(t *testing.T) {
	s := policydoc.Selector{MatchReturnActions: []policydoc.ActionSelector{{Action: "Signal"}}}
	if !selectorHasEnforcement(s) {
		t.Fatalf("expected true via MatchReturnActions")
	}
}

func TestCheck_G4_SelectorValueLimit(t *testing.T) {
	var sb []byte
	sb = append(sb, []byte(`  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
`)...)
	for i := 0; i < 4100; i++ {
		sb = append(sb, []byte(fmt.Sprintf("        - \"/usr/bin/app%d\"\n", i))...)
	}
	d := mustParseDoc(t, "p", policyYAML("p", string(sb)))
	err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG4 {
		t.Fatalf("error = %v, want G4", err)
	}
}

func TestCheck_G8_LsmHookRequiresLSMBPF(t *testing.T) {
	spec := `  lsmhooks:
  - hook: "bprm_check_security"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      matchActions:
      - action: "Override"
        argError: -1
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	g := &Guardrails{Capabilities: fakeCapabilities{kprobeOverride: true, lsmBPF: false}, History: fakeHistory{}}
	err := g.Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG8 {
		t.Fatalf("error = %v, want G8", err)
	}
}

func TestCheck_G8_NoCapabilitiesConfigured(t *testing.T) {
	spec := overrideKprobeSpec(`matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      `)
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	g := &Guardrails{History: fakeHistory{}}
	err := g.Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG8 {
		t.Fatalf("error = %v, want G8", err)
	}
}

func TestCheck_G1_PostfixAndNotPostfix(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		wantErr bool
	}{
		{"postfix_covers_sshd", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "Postfix"
        values: ["sshd"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"notpostfix_leaves_some_uncovered", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "NotPostfix"
        values: ["sshd"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"notpostfix_covers_all", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "NotPostfix"
        values: [""]
      matchActions:
      - action: "Sigkill"
`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParseDoc(t, "p", policyYAML("p", tc.spec))
			err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
			if tc.wantErr && (err == nil || ruleOf(t, err) != RuleG1) {
				t.Fatalf("error = %v, want G1", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCheckSelectorG1_UnrecognizedOperator(t *testing.T) {
	s := policydoc.Selector{
		MatchBinaries: []policydoc.BinarySelector{{Operator: "Bogus", Values: []string{"x"}}},
		MatchActions:  []policydoc.ActionSelector{{Action: "Sigkill"}},
	}
	err := checkSelectorG1("p", "h", s, nil)
	var v *Violation
	if err == nil || !errors.As(err, &v) || v.Rule != RuleG1 {
		t.Fatalf("error = %v, want G1", err)
	}
}

func TestG9_ExtraProtectedExtendsPaths(t *testing.T) {
	spec := `  kprobes:
  - call: "x"
    args:
    - index: 0
      type: "path"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      matchArgs:
      - index: 0
        operator: "Equal"
        values: ["/opt/extra/secret"]
      matchActions:
      - action: "Sigkill"
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	g := &Guardrails{
		Capabilities:   allowAllCapabilities,
		History:        fakeHistory{},
		ExtraProtected: fakeProtectedSetSource{paths: []string{"/opt/extra/"}},
	}
	err := g.Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG2 {
		t.Fatalf("error = %v, want G2 (extended protected path set)", err)
	}
}
