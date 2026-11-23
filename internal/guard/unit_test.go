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

// TestIsExecHook_AnyKindWithMatchingIdentifier is architect review item
// C3: exec-hook classification is identifier-substring based ("exec" or
// "bprm", case-insensitive) across every hook kind, not just kprobe/lsmhook
// — a tracepoint or uprobe naming an exec-related symbol must also count.
func TestIsExecHook_AnyKindWithMatchingIdentifier(t *testing.T) {
	cases := []struct {
		kind       policydoc.HookKind
		identifier string
		want       bool
	}{
		{policydoc.HookKindKProbe, "security_bprm_check", true},
		{policydoc.HookKindLsmHook, "bprm_check_security", true},
		{policydoc.HookKindKProbe, "sys_execve", true},
		{policydoc.HookKindKProbe, "sys_execveat", true},
		{policydoc.HookKindTracepoint, "syscalls/sys_enter_execve", true},
		{policydoc.HookKindUProbe, "bprm_execve", true},
		{policydoc.HookKindKProbe, "EXECVE_UPPERCASE", true},
		{policydoc.HookKindKProbe, "tcp_connect", false},
		{policydoc.HookKindTracepoint, "skb/kfree_skb", false},
	}
	for _, tc := range cases {
		h := policydoc.Hook{Kind: tc.kind, Identifier: tc.identifier}
		if got := isExecHook(h); got != tc.want {
			t.Errorf("isExecHook(kind=%v, identifier=%q) = %v, want %v", tc.kind, tc.identifier, got, tc.want)
		}
	}
}

func TestPathCoversPositive_PrefixNestedInsideProtectedDirectory(t *testing.T) {
	// A Prefix value naming something nested inside a protected directory
	// (rather than an ancestor of it) must also be covered.
	if !pathCoversPositive("Prefix", []string{"/run/tetragon/sub/"}, "/run/tetragon/") {
		t.Fatalf("expected coverage for a prefix nested inside a protected directory")
	}
	if pathCoversPositive("Prefix", []string{"/completely/unrelated/"}, "/run/tetragon/") {
		t.Fatalf("expected no coverage for an unrelated prefix")
	}
}

func TestPathCoversPositive_PostfixAlwaysCoversDirectory(t *testing.T) {
	// Architect review item C2: Postfix on a directory target always
	// covers, since some hypothetical file inside it could end with any
	// given suffix.
	if !pathCoversPositive("Postfix", []string{"unrelated-suffix"}, "/run/tetragon/") {
		t.Fatalf("expected Postfix to always cover a directory target")
	}
}

func TestPathCoversPositive_ExactFileTarget(t *testing.T) {
	if !pathCoversPositive("Postfix", []string{"tetragon.sock"}, "/run/tetragon/tetragon.sock") {
		t.Fatalf("expected coverage: postfix names the protected file's own trailing segment")
	}
	if pathCoversPositive("Postfix", []string{"unrelated-suffix"}, "/run/tetragon/tetragon.sock") {
		t.Fatalf("expected no coverage for an unrelated postfix against an exact file target")
	}
}

func TestMatches_NegativeOperatorsExcludeCorrectly(t *testing.T) {
	// NotPrefix "/" means "does not start with /", which is false for
	// every absolute candidate (every candidate here starts with "/"), so
	// matches() (the negation of the positive form) is false: a broad "/"
	// value excludes everything, i.e. "/" is a universal NotPrefix.
	if matches("NotPrefix", []string{"/"}, "/usr/sbin/sshd") {
		t.Fatalf("NotPrefix '/' must exclude every absolute candidate")
	}
	if matches("NotPrefix", []string{"/usr/sbin/"}, "/usr/sbin/sshd") {
		t.Fatalf("NotPrefix '/usr/sbin/' must exclude /usr/sbin/sshd")
	}
	if !matches("NotPrefix", []string{"/usr/sbin/"}, "/sbin/init") {
		t.Fatalf("NotPrefix '/usr/sbin/' must NOT exclude /sbin/init (different prefix)")
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
		{"notpostfix_empty_value_is_unsafe", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "NotPostfix"
        values: [""]
      matchActions:
      - action: "Sigkill"
`, true}, // empty value is unsafe (C1), rejected outright regardless of what it would "exclude"
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

// TestCheck_G1_NotPostfixCoveringAllLastCharacters computes (rather than
// assumes, per the architect's "compute it, don't assume" instruction) the
// set of every protected binary's final character and uses exactly that
// set as NotPostfix values: since every protected binary ends with one of
// these single characters, this selector must be accepted (it genuinely
// excludes all of them), proving the check isn't simply "NotPostfix always
// rejects."
func TestCheck_G1_NotPostfixCoveringAllLastCharacters(t *testing.T) {
	seen := map[string]bool{}
	var values []string
	for _, b := range protectedBinaries {
		last := string(b[len(b)-1])
		if !seen[last] {
			seen[last] = true
			values = append(values, last)
		}
	}
	spec := fmt.Sprintf(`  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "NotPostfix"
        values: %s
      matchActions:
      - action: "Sigkill"
`, yamlStringList(values))
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("NotPostfix covering every protected binary's last character was rejected: %v", err)
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

func TestCheck_G10_OverrideOnUprobeRejected(t *testing.T) {
	spec := `  uprobes:
  - path: "/usr/bin/myapp"
    symbols: ["do_thing"]
    selectors:
    - matchActions:
      - action: "Override"
        argError: -1
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG10 {
		t.Fatalf("error = %v, want G10", err)
	}
}

func TestCheck_G10_OverrideOnTracepointRejected(t *testing.T) {
	spec := `  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_open"
    selectors:
    - matchActions:
      - action: "Override"
        argError: -1
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG10 {
		t.Fatalf("error = %v, want G10", err)
	}
}

func TestCheck_G10_ViaMatchReturnActions(t *testing.T) {
	spec := `  uprobes:
  - path: "/usr/bin/myapp"
    symbols: ["do_thing"]
    return: true
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchReturnActions:
      - action: "Override"
        argError: -1
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG10 {
		t.Fatalf("error = %v, want G10", err)
	}
}

func TestCheckSelectorG2_UnrecognizedOperator(t *testing.T) {
	h := policydoc.Hook{PathArgIndices: map[uint32]bool{0: true}}
	s := policydoc.Selector{
		MatchArgs:    []policydoc.ArgSelector{{Index: 0, Operator: "Bogus", Values: []string{"/tmp/x"}}},
		MatchActions: []policydoc.ActionSelector{{Action: "Sigkill"}},
	}
	err := checkSelectorG2("p", h, s, nil)
	if err == nil || ruleOf(t, err) != RuleG2 {
		t.Fatalf("error = %v, want G2", err)
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
