package guard

import (
	"strings"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

// execHookIdentifiers are the exec-related hooks G3 applies to, from the
// pinned source and the vendored example corpus:
//   - kprobe "security_bprm_check": testdata/upstream/security_bprm_check.yaml:7
//   - lsmhook "bprm_check_security": testdata/upstream/lsm_bprm_check.yaml:8
//   - "security_bprm_creds_for_exec" / "bprm_creds_for_exec" are named by
//     the step 2 prompt itself; this project found no example or other
//     pinned-source occurrence of either spelling to confirm the exact
//     hook/call name Tetragon v1.8.0 uses for it, so both the kprobe-call
//     and lsmhook-hook forms are included defensively (see
//     docs/reports/step-02b.md open questions: this is a judgment call,
//     not a confirmed fact, and is flagged there rather than silently
//     assumed).
//   - No execve-syscall or execve-tracepoint hook name usable from a
//     TracingPolicy was found anywhere in the pinned source or corpus:
//     the only "sys_execve" occurrence (pkg/sensors/base/base.go:36) is a
//     raw_tracepoint wired into Tetragon's always-on base sensor, not a
//     user-addressable TracingPolicy hook. That category of G3 is
//     therefore not enforced here; see the open questions in the report.
var execKProbeCalls = map[string]bool{
	"security_bprm_check":          true,
	"security_bprm_creds_for_exec": true,
}

var execLsmHooks = map[string]bool{
	"bprm_check_security": true,
	"bprm_creds_for_exec": true,
}

// Guardrails implements internal/verify.Guardrails (step 2 prompt Part C0):
// Check(ctx, docs) runs G7, G6, G8, G1, G2, G3, G4, G5 in that fixed order,
// first failure wins.
type Guardrails struct {
	Capabilities HostCapabilities
	History      PolicyHistory
	// ExtraProtected is optional (G9); nil means no trust-root extension
	// of the compiled-in protected sets.
	ExtraProtected ProtectedSetSource
}

func (g *Guardrails) extraBinaries() []string {
	if g.ExtraProtected == nil {
		return nil
	}
	return g.ExtraProtected.ExtraBinaries()
}

func (g *Guardrails) extraPaths() []string {
	if g.ExtraProtected == nil {
		return nil
	}
	return g.ExtraProtected.ExtraPaths()
}

// Check implements the fixed G7/G6/G8/G1/G2/G3/G4/G5 ordering.
func (g *Guardrails) Check(ctx GuardContext, docs []*policydoc.Doc) error {
	if err := checkG7(docs); err != nil {
		return err
	}
	if err := checkG6(ctx); err != nil {
		return err
	}
	if err := g.checkG8(docs); err != nil {
		return err
	}
	if err := g.checkG1(docs); err != nil {
		return err
	}
	if err := g.checkG2(docs); err != nil {
		return err
	}
	if err := checkG3(docs); err != nil {
		return err
	}
	if err := checkG4(docs); err != nil {
		return err
	}
	if err := g.checkG5(ctx, docs); err != nil {
		return err
	}
	return nil
}

// selectorHasEnforcement reports whether s carries any enforcement action
// in MatchActions or MatchReturnActions.
func selectorHasEnforcement(s policydoc.Selector) bool {
	for _, a := range s.MatchActions {
		if isEnforcementAction(a.Action) {
			return true
		}
	}
	for _, a := range s.MatchReturnActions {
		if isEnforcementAction(a.Action) {
			return true
		}
	}
	return false
}

// --- G7: unknown action or hook type ---

func checkG7(docs []*policydoc.Doc) error {
	for _, d := range docs {
		for _, h := range d.Hooks() {
			switch h.Kind { //nolint:exhaustive // the default case below handles every other value
			case policydoc.HookKindKProbe, policydoc.HookKindTracepoint, policydoc.HookKindUProbe, policydoc.HookKindLsmHook:
			default:
				return violation(RuleG7, "policy %q: unknown hook type (kind=%v)", d.Name(), h.Kind)
			}
			for _, s := range h.Selectors {
				for _, a := range s.MatchActions {
					if !isKnownAction(a.Action) {
						return violation(RuleG7, "policy %q hook %q: unknown action %q", d.Name(), h.Identifier, a.Action)
					}
				}
				for _, a := range s.MatchReturnActions {
					if !isKnownAction(a.Action) {
						return violation(RuleG7, "policy %q hook %q: unknown return action %q", d.Name(), h.Identifier, a.Action)
					}
				}
			}
		}
	}
	return nil
}

// --- G6: mode coherence ---

func checkG6(ctx GuardContext) error {
	if ctx.Mode != "monitor" && ctx.Mode != "enforce" {
		return violation(RuleG6, "invalid mode %q", ctx.Mode)
	}
	return nil
}

// --- G8: capability check ---

func (g *Guardrails) checkG8(docs []*policydoc.Doc) error {
	if g.Capabilities == nil {
		return violation(RuleG8, "no HostCapabilities configured")
	}
	for _, d := range docs {
		for _, h := range d.Hooks() {
			for _, s := range h.Selectors {
				if !selectorUsesOverride(s) {
					continue
				}
				switch h.Kind { //nolint:exhaustive // G8 only names kprobes/lsmhooks (step 2 prompt Part C); Override on tracepoints/uprobes is not gated here, see docs/reports/step-02b.md open questions
				case policydoc.HookKindKProbe:
					if !g.Capabilities.KprobeOverride() {
						return violation(RuleG8, "policy %q hook %q: Override on a kprobe requires KprobeOverride capability", d.Name(), h.Identifier)
					}
				case policydoc.HookKindLsmHook:
					if !g.Capabilities.LSMBPF() {
						return violation(RuleG8, "policy %q hook %q: Override on an lsmhook requires LSMBPF capability", d.Name(), h.Identifier)
					}
				}
			}
		}
	}
	return nil
}

func selectorUsesOverride(s policydoc.Selector) bool {
	for _, a := range s.MatchActions {
		if a.Action == "Override" {
			return true
		}
	}
	for _, a := range s.MatchReturnActions {
		if a.Action == "Override" {
			return true
		}
	}
	return false
}

// --- G1: protected processes ---

func (g *Guardrails) checkG1(docs []*policydoc.Doc) error {
	extraBinaries := g.extraBinaries()
	for _, d := range docs {
		for _, h := range d.Hooks() {
			for _, s := range h.Selectors {
				if !selectorHasEnforcement(s) {
					continue
				}
				if err := checkSelectorG1(d.Name(), h.Identifier, s, extraBinaries); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkSelectorG1(policyName, hookID string, s policydoc.Selector, extraBinaries []string) error {
	for _, p := range s.MatchPIDs {
		if p.Operator == "In" {
			for _, v := range p.Values {
				if v == 1 {
					return violation(RuleG1, "policy %q hook %q: matchPIDs In containing 1 with enforcement", policyName, hookID)
				}
			}
		}
	}
	if len(s.MatchBinaries) == 0 {
		return violation(RuleG1, "policy %q hook %q: enforcement selector has no matchBinaries", policyName, hookID)
	}
	b := s.MatchBinaries[0]
	switch b.Operator {
	case "In", "Prefix", "Postfix":
		if anyBinaryCovered(b.Operator, b.Values, extraBinaries) {
			return violation(RuleG1, "policy %q hook %q: matchBinaries %s covers a protected binary", policyName, hookID, b.Operator)
		}
	case "NotIn", "NotPrefix", "NotPostfix":
		if !excludesAllBinaries(b.Operator, b.Values, extraBinaries) {
			return violation(RuleG1, "policy %q hook %q: matchBinaries %s does not exclude every protected binary", policyName, hookID, b.Operator)
		}
	default:
		return violation(RuleG1, "policy %q hook %q: unrecognized matchBinaries operator %q", policyName, hookID, b.Operator)
	}
	return nil
}

// --- G2: protected paths ---

func (g *Guardrails) checkG2(docs []*policydoc.Doc) error {
	extraPaths := g.extraPaths()
	for _, d := range docs {
		for _, h := range d.Hooks() {
			for _, s := range h.Selectors {
				if !selectorHasEnforcement(s) {
					continue
				}
				if err := checkSelectorG2(d.Name(), h, s, extraPaths); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkSelectorG2(policyName string, h policydoc.Hook, s policydoc.Selector, extraPaths []string) error {
	var pathArgs []policydoc.ArgSelector
	for _, a := range s.MatchArgs {
		if h.PathArgIndices[a.Index] {
			pathArgs = append(pathArgs, a)
		}
	}
	if len(pathArgs) == 0 {
		return nil
	}

	hasPositive := false
	for _, a := range pathArgs {
		switch a.Operator {
		case "Equal", "Prefix", "Postfix":
			hasPositive = true
			if anyPathCovered(a.Operator, a.Values, extraPaths) {
				return violation(RuleG2, "policy %q hook %q: matchArgs %s on a path arg covers a protected path", policyName, h.Identifier, a.Operator)
			}
		case "NotEqual", "NotPrefix", "NotPostfix":
			// handled by the hasPositive check below
		}
	}
	if !hasPositive {
		return violation(RuleG2, "policy %q hook %q: enforcement selector uses only Not* operators on path args", policyName, h.Identifier)
	}
	return nil
}

// --- G3: exec hooks ---

func checkG3(docs []*policydoc.Doc) error {
	for _, d := range docs {
		for _, h := range d.Hooks() {
			if !isExecHook(h) {
				continue
			}
			for _, s := range h.Selectors {
				if !selectorHasEnforcement(s) {
					continue
				}
				if !execSelectorScoped(s) {
					return violation(RuleG3, "policy %q hook %q: unscoped exec denial (no matchBinaries In/Prefix or positive matchArgs)", d.Name(), h.Identifier)
				}
			}
		}
	}
	return nil
}

func isExecHook(h policydoc.Hook) bool {
	switch h.Kind { //nolint:exhaustive // only kprobes/lsmhooks can name an exec-related hook identifier in execKProbeCalls/execLsmHooks; tracepoints/uprobes always fall to the default
	case policydoc.HookKindKProbe:
		return execKProbeCalls[h.Identifier]
	case policydoc.HookKindLsmHook:
		return execLsmHooks[h.Identifier]
	default:
		return false
	}
}

func execSelectorScoped(s policydoc.Selector) bool {
	if len(s.MatchBinaries) > 0 {
		op := s.MatchBinaries[0].Operator
		if op == "In" || op == "Prefix" {
			return true
		}
	}
	for _, a := range s.MatchArgs {
		if !strings.HasPrefix(a.Operator, "Not") {
			return true
		}
	}
	return false
}

// --- G4: size limits ---

func checkG4(docs []*policydoc.Doc) error {
	totalHooks := 0
	totalValues := 0
	for _, d := range docs {
		for _, h := range d.Hooks() {
			totalHooks++
			for _, s := range h.Selectors {
				totalValues += selectorValueCount(s)
			}
		}
	}
	if totalHooks > limits.MaxHooksPerBundle {
		return violation(RuleG4, "bundle has %d hooks, max %d", totalHooks, limits.MaxHooksPerBundle)
	}
	if totalValues > limits.MaxSelectorValuesPerBundle {
		return violation(RuleG4, "bundle has %d selector values, max %d", totalValues, limits.MaxSelectorValuesPerBundle)
	}
	return nil
}

func selectorValueCount(s policydoc.Selector) int {
	n := 0
	for _, p := range s.MatchPIDs {
		n += len(p.Values)
	}
	for _, a := range s.MatchArgs {
		n += len(a.Values)
	}
	for _, a := range s.MatchReturnArgs {
		n += len(a.Values)
	}
	for _, b := range s.MatchBinaries {
		n += len(b.Values)
	}
	for _, b := range s.MatchParentBinaries {
		n += len(b.Values)
	}
	return n
}

// --- G5: monitor first ---

func (g *Guardrails) checkG5(ctx GuardContext, docs []*policydoc.Doc) error {
	if ctx.Mode != "enforce" {
		return nil
	}
	if g.History == nil {
		return violation(RuleG5, "no PolicyHistory configured")
	}
	for _, d := range docs {
		if !docHasEnforcement(d) {
			continue
		}
		seen, err := g.History.SeenInMonitor(ctx.Scope, d.Name())
		if err != nil {
			return violation(RuleG5, "policy %q: PolicyHistory error: %v", d.Name(), err)
		}
		if !seen {
			return violation(RuleG5, "policy %q: enforcement actions not previously seen in a monitor-mode bundle for scope %q", d.Name(), ctx.Scope)
		}
	}
	return nil
}

func docHasEnforcement(d *policydoc.Doc) bool {
	for _, h := range d.Hooks() {
		for _, s := range h.Selectors {
			if selectorHasEnforcement(s) {
				return true
			}
		}
	}
	return false
}
