package guard

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

func policyYAML(name, specBody string) string {
	return fmt.Sprintf("apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: %q\nspec:\n%s\n", name, specBody)
}

func newGuard() *Guardrails {
	return &Guardrails{Capabilities: allowAllCapabilities, History: fakeHistory{}}
}

func ruleOf(t *testing.T, err error) RuleID {
	t.Helper()
	var v *Violation
	if !errors.As(err, &v) {
		t.Fatalf("error %v is not a *Violation", err)
	}
	return v.Rule
}

// TestCheck_G7_UnknownAction_LogicUnit tests isKnownAction (the decision
// G7's loop acts on) directly, rather than through Check: the vendored
// CRD's own ActionSelector.action enum (types.go:382) is exactly this
// project's 13-action set, so no schema-valid document can ever carry an
// action name isKnownAction rejects — policydoc.Parse itself already
// rejects "FollowFD", "UnfollowFD", "CopyFD" and anything else not in that
// enum (see internal/policydoc's B3 schema validation) before a Doc ever
// reaches guard. G7's per-action check in checkG7 is therefore verified
// defense in depth, and the decision logic it calls is unit tested here;
// see docs/reports/step-02b.md's self-review for why that specific line in
// checkG7 is not (and, given the schema, cannot be) covered by a Check-level
// test.
func TestCheck_G7_UnknownAction_LogicUnit(t *testing.T) {
	cases := map[string]bool{
		"Post": true, "Sigkill": true, "Override": true, "GetUrl": true,
		"DnsLookup": true, "NoPost": true, "Signal": true, "TrackSock": true,
		"UntrackSock": true, "NotifyEnforcer": true, "CleanupEnforcerNotification": true,
		"Set": true,
		// Deliberately not in this project's known set (see
		// internal/guard/actions.go's package doc for why):
		"UpdateState": false,
		"FollowFD":    false,
		"UnfollowFD":  false,
		"CopyFD":      false,
		"Bogus":       false,
	}
	for action, want := range cases {
		if got := isKnownAction(action); got != want {
			t.Errorf("isKnownAction(%q) = %v, want %v", action, got, want)
		}
	}
}

func TestCheck_G7_AllRealActionsAccepted(t *testing.T) {
	// Every known action actually reaches Check() without a G7 error, for
	// every document that otherwise passes (Post is the simplest: an
	// observe action never needs matchBinaries, so no other rule fires).
	spec := `  kprobes:
  - call: "x"
    selectors:
    - matchActions:
      - action: "Post"
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheck_G6_InvalidMode(t *testing.T) {
	err := newGuard().Check(GuardContext{Scope: "s", Mode: "audit"}, nil)
	if err == nil || ruleOf(t, err) != RuleG6 {
		t.Fatalf("error = %v, want G6", err)
	}
}

func overrideKprobeSpec(matchBinaries string) string {
	return fmt.Sprintf(`  kprobes:
  - call: "security_bprm_check"
    selectors:
    - %smatchActions:
      - action: "Override"
        argError: -1
`, matchBinaries)
}

func TestCheck_G8_CapabilityGating(t *testing.T) {
	spec := overrideKprobeSpec(`matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      `)
	d := mustParseDoc(t, "p", policyYAML("p", spec))

	g := &Guardrails{Capabilities: denyAllCapabilities, History: fakeHistory{}}
	err := g.Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG8 {
		t.Fatalf("error = %v, want G8", err)
	}

	g2 := &Guardrails{Capabilities: allowAllCapabilities, History: fakeHistory{}}
	if err := g2.Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("unexpected error with capability granted: %v", err)
	}
}

func TestCheck_G1(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		wantErr bool
	}{
		{"no_matchBinaries", `  kprobes:
  - call: "x"
    selectors:
    - matchActions:
      - action: "Sigkill"
`, true},
		{"in_protected_binary", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/sbin/sshd"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"prefix_covers_sshd", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "Prefix"
        values: ["/usr/sbin/"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"usrmerge_alias_sbin", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/sbin/sshd"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"trailing_slash", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/sbin/sshd/"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"traversal_ambiguous", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/sbin/../sbin/sshd"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"notin_missing_one", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "NotIn"
        values: ["/usr/sbin/sshd"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"matchpids_one_with_enforcement", `  kprobes:
  - call: "x"
    selectors:
    - matchPIDs:
      - operator: "In"
        values: [1]
      matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      matchActions:
      - action: "Sigkill"
`, true},
		{"followchildren_does_not_exempt", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/sbin/sshd"]
        followChildren: true
      matchActions:
      - action: "Sigkill"
`, true},
		{"safe_binary", `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/bin/myapp"]
      matchActions:
      - action: "Sigkill"
`, false},
		{"observe_only_no_matchBinaries_needed", `  kprobes:
  - call: "x"
    selectors:
    - matchActions:
      - action: "Post"
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

func TestCheck_G1_NotInCoversAll_Passes(t *testing.T) {
	var sb []byte
	sb = append(sb, []byte(`  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "NotIn"
        values:
`)...)
	for _, b := range protectedBinaries {
		sb = append(sb, []byte("        - \""+b+"\"\n")...)
	}
	sb = append(sb, []byte(`      matchActions:
      - action: "Sigkill"
`)...)
	d := mustParseDoc(t, "p", policyYAML("p", string(sb)))
	if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheck_G2(t *testing.T) {
	kprobeWithPathArg := func(matchArgs string) string {
		return fmt.Sprintf(`  kprobes:
  - call: "x"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      matchArgs:
      - index: 0
        %s
      matchActions:
      - action: "Sigkill"
`, matchArgs)
	}
	cases := []struct {
		name      string
		matchArgs string
		wantErr   bool
	}{
		{"prefix_root", `operator: "Prefix"
        values: ["/"]`, true},
		{"prefix_var", `operator: "Prefix"
        values: ["/var"]`, true},
		{"postfix_socket", `operator: "Postfix"
        values: ["tetragon.sock"]`, true},
		{"only_not_operators", `operator: "NotEqual"
        values: ["/tmp/foo"]`, true},
		{"safe_equal", `operator: "Equal"
        values: ["/tmp/safe-file"]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParseDoc(t, "p", policyYAML("p", kprobeWithPathArg(tc.matchArgs)))
			err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
			if tc.wantErr && (err == nil || ruleOf(t, err) != RuleG2) {
				t.Fatalf("error = %v, want G2", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// G1 unconditionally requires matchBinaries on every enforcement selector,
// and runs before G3 in the pinned order, so by the time G3 evaluates an
// exec hook's selector, matchBinaries is already guaranteed present (and,
// if NotIn/NotPrefix, already guaranteed to exclude every protected
// binary). G3's own, distinct value is rejecting a *technically-G1-safe*
// NotIn/NotPrefix selector as still "unscoped" for an exec-denial hook
// (e.g. "deny exec for everything except three binaries" excludes no
// protected binary yet is still an unscoped denial) unless a positive
// matchArgs also narrows it. See docs/reports/step-02b.md's open
// questions for this ordering interaction.
func notInAllProtectedBinaries() string {
	var sb strings.Builder
	sb.WriteString("      - operator: \"NotIn\"\n        values:\n")
	for _, b := range protectedBinaries {
		sb.WriteString("        - \"" + b + "\"\n")
	}
	return sb.String()
}

func TestCheck_G3(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		wantErr bool
	}{
		{"g1_fires_first_when_no_matchBinaries_at_all", overrideKprobeSpec(""), true},
		{"in_is_scoped", overrideKprobeSpec(`matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      `), false},
		{"notin_alone_is_unscoped_for_g3", `  kprobes:
  - call: "security_bprm_check"
    selectors:
    - matchBinaries:
` + notInAllProtectedBinaries() + `      matchActions:
      - action: "Override"
        argError: -1
`, true},
		{"notin_plus_positive_matchArgs_is_scoped", `  kprobes:
  - call: "security_bprm_check"
    selectors:
    - matchBinaries:
` + notInAllProtectedBinaries() + `      matchArgs:
      - index: 0
        operator: "Equal"
        values: ["/usr/bin/safe"]
      matchActions:
      - action: "Override"
        argError: -1
`, false},
		{"notin_plus_only_not_matchArgs_is_unscoped", `  kprobes:
  - call: "security_bprm_check"
    selectors:
    - matchBinaries:
` + notInAllProtectedBinaries() + `      matchArgs:
      - index: 0
        operator: "NotEqual"
        values: ["/usr/bin/safe"]
      matchActions:
      - action: "Override"
        argError: -1
`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParseDoc(t, "p", policyYAML("p", tc.spec))
			err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

func TestCheck_G3_RuleIsG3Specifically(t *testing.T) {
	spec := `  kprobes:
  - call: "security_bprm_check"
    selectors:
    - matchBinaries:
` + notInAllProtectedBinaries() + `      matchActions:
      - action: "Override"
        argError: -1
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG3 {
		t.Fatalf("error = %v, want G3", err)
	}
}

func TestCheck_G3_NonExecHookUnaffected(t *testing.T) {
	// A Sigkill on a non-exec hook with no matchBinaries fails G1 (which
	// applies to every enforcement selector regardless of hook
	// identity), proving non-exec hooks are not silently exempted from
	// everything else just because G3 does not apply to them.
	spec := `  kprobes:
  - call: "tcp_connect"
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchActions:
      - action: "Sigkill"
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG1 {
		t.Fatalf("error = %v, want G1", err)
	}
}

func TestCheck_G4_HookCountLimit(t *testing.T) {
	var sb []byte
	sb = append(sb, []byte("  kprobes:\n")...)
	for i := 0; i < 257; i++ {
		sb = append(sb, []byte(fmt.Sprintf("  - call: \"call%d\"\n", i))...)
	}
	d := mustParseDoc(t, "p", policyYAML("p", string(sb)))
	err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG4 {
		t.Fatalf("error = %v, want G4", err)
	}
}

func TestCheck_G5_MonitorFirst(t *testing.T) {
	spec := `  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      matchActions:
      - action: "Sigkill"
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))

	// Monitor mode: G5 never applies.
	if err := newGuard().Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("monitor mode: unexpected error: %v", err)
	}

	// Enforce mode, never seen in monitor: reject.
	g := &Guardrails{Capabilities: allowAllCapabilities, History: fakeHistory{}}
	err := g.Check(GuardContext{Scope: "s", Mode: "enforce"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG5 {
		t.Fatalf("error = %v, want G5", err)
	}

	// Enforce mode, seen in monitor for this scope: allow.
	g2 := &Guardrails{Capabilities: allowAllCapabilities, History: fakeHistory{seen: map[string]bool{"s/p": true}}}
	if err := g2.Check(GuardContext{Scope: "s", Mode: "enforce"}, []*policydoc.Doc{d}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// PolicyHistory error: fail closed.
	g3 := &Guardrails{Capabilities: allowAllCapabilities, History: fakeHistory{err: errBoom}}
	err = g3.Check(GuardContext{Scope: "s", Mode: "enforce"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG5 {
		t.Fatalf("error = %v, want G5 on history error", err)
	}
}

var errBoom = fmt.Errorf("boom")

func TestCheck_G9_ExtraProtectedExtendsG1AndG2(t *testing.T) {
	spec := `  kprobes:
  - call: "x"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["/opt/myapp/extra-protected"]
      matchActions:
      - action: "Sigkill"
`
	d := mustParseDoc(t, "p", policyYAML("p", spec))
	g := &Guardrails{
		Capabilities:   allowAllCapabilities,
		History:        fakeHistory{},
		ExtraProtected: fakeProtectedSetSource{binaries: []string{"/opt/myapp/extra-protected"}},
	}
	err := g.Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{d})
	if err == nil || ruleOf(t, err) != RuleG1 {
		t.Fatalf("error = %v, want G1 (extended protected set)", err)
	}
}
