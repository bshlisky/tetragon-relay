package guard

import (
	"strings"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

// isExecIdentifier implements architect review item C3: a hook is
// exec-related iff its identifier contains "exec" or "bprm",
// case-insensitive, regardless of hook kind. This replaces a fixed list
// that missed, among others, any execve syscall/tracepoint hook.
func isExecIdentifier(identifier string) bool {
	lower := strings.ToLower(identifier)
	return strings.Contains(lower, "exec") || strings.Contains(lower, "bprm")
}

// Guardrails implements internal/verify.Guardrails (step 2 prompt Part C0):
// Check(ctx, docs) runs G7, G6, G8, G10, G1, G2, G3, G4, G5 in that fixed
// order, first failure wins. G10 (architect review item C5, Override hook
// placement) is new in this review pass and runs immediately after G8
// since both gate the Override action.
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
	if err := checkG10(docs); err != nil {
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
				switch h.Kind { //nolint:exhaustive // G10 (checked separately, right after this rule) rejects Override on every other hook kind outright
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

// --- G10: Override hook placement (architect review item C5) ---

// checkG10 rejects Override on any hook kind other than kprobes and
// lsmhooks: those two are the only kinds G8 has a capability check for,
// and the CRD's own ActionSelector doc comment
// (pkg/k8s/apis/cilium.io/v1alpha1/types.go:384-396) states Override's
// three variants are supported on "kprobes, uprobes, lsm" — uprobe
// override is a different mechanism (symbol/address/offset substitution,
// not kernel ALLOW_ERROR_INJECTION) that this project has no capability
// detection for, and tracepoints are not listed as supporting Override at
// all. Loading Override on either would either fail open (no capability
// gate exists to say no) or rely on an unconfirmed assumption about
// tracepoint support; both are rejected outright instead.
func checkG10(docs []*policydoc.Doc) error {
	for _, d := range docs {
		for _, h := range d.Hooks() {
			if h.Kind == policydoc.HookKindKProbe || h.Kind == policydoc.HookKindLsmHook {
				continue
			}
			for _, s := range h.Selectors {
				if selectorUsesOverride(s) {
					return violation(RuleG10, "policy %q hook %q: Override is only allowed on kprobes and lsmhooks, not %v", d.Name(), h.Identifier, h.Kind)
				}
			}
		}
	}
	return nil
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
	// The pinned CRD caps matchBinaries at one entry
	// (TestCRD_MatchBinariesMaxItemsOne verifies this directly against the
	// vendored schema); inspecting only [0] would silently ignore any
	// later entries if that ever changed, so reject outright instead of
	// assuming the cap still holds.
	if len(s.MatchBinaries) > 1 {
		return violation(RuleG1, "policy %q hook %q: enforcement selector has more than one matchBinaries entry", policyName, hookID)
	}
	b := s.MatchBinaries[0]
	if !recognizedMatchOperators[b.Operator] {
		return violation(RuleG1, "policy %q hook %q: unrecognized matchBinaries operator %q", policyName, hookID, b.Operator)
	}
	if v, bad := firstNonCanonicalValue(b.Operator, b.Values); bad {
		return violation(RuleG1, "policy %q hook %q: matchBinaries %s has a non-canonical value %q", policyName, hookID, b.Operator, truncateValue(v))
	}
	candidates := append(append([]string(nil), protectedBinaries...), extraBinaries...)
	if matchesAnyCandidate(b.Operator, b.Values, candidates) {
		return violation(RuleG1, "policy %q hook %q: matchBinaries %s matches a protected binary", policyName, hookID, b.Operator)
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
		if !recognizedMatchOperators[a.Operator] {
			return violation(RuleG2, "policy %q hook %q: unrecognized matchArgs operator %q", policyName, h.Identifier, a.Operator)
		}
		// Architect review item D1: every anchored value on a path-typed
		// arg must be canonical, for every operator - not just the
		// positive ones this function goes on to evaluate for coverage -
		// since a non-canonical value is unsafe to reason about either
		// way and "no special cases" applies here exactly as it does to
		// G1's matchBinaries check.
		if v, bad := firstNonCanonicalValue(a.Operator, a.Values); bad {
			return violation(RuleG2, "policy %q hook %q: matchArgs %s on a path arg has a non-canonical value %q", policyName, h.Identifier, a.Operator, truncateValue(v))
		}
		switch a.Operator {
		case "Equal", "In", "Prefix", "Postfix":
			hasPositive = true
			if anyPathCoveredPositive(a.Operator, a.Values, extraPaths) {
				return violation(RuleG2, "policy %q hook %q: matchArgs %s on a path arg covers a protected path", policyName, h.Identifier, a.Operator)
			}
		case "NotEqual", "NotIn", "NotPrefix", "NotPostfix":
			// A Not*-only selector on a path arg is rejected below
			// regardless of these values (architect review: "Negative-only
			// path selectors with enforcement remain rejected"); G2 does
			// not need a G1-style "excludes every protected path" check
			// for the negative case.
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
				if !execSelectorScoped(h, s) {
					return violation(RuleG3, "policy %q hook %q: unscoped exec denial (no matchBinaries In/Prefix or positive matchArgs on a path-typed arg)", d.Name(), h.Identifier)
				}
			}
		}
	}
	return nil
}

// isExecHook implements architect review item C3: identifier-substring
// based, across every hook kind (not just kprobe/lsmhook), so it also
// catches tracepoint/uprobe identifiers naming an exec-related symbol
// (e.g. a "syscalls/sys_enter_execve" tracepoint's Identifier is
// "syscalls/sys_enter_execve", or a uprobe traced symbol named
// "bprm_execve").
func isExecHook(h policydoc.Hook) bool {
	return isExecIdentifier(h.Identifier)
}

// execSelectorScoped reports whether s is scoped enough for G3: a single
// matchBinaries entry using In/Prefix, or at least one positive-operator
// matchArgs entry on a path-typed arg (architect review item C4: "positive
// matchArgs" means specifically a path-typed arg, not any arg).
func execSelectorScoped(h policydoc.Hook, s policydoc.Selector) bool {
	if len(s.MatchBinaries) == 1 {
		op := s.MatchBinaries[0].Operator
		if op == "In" || op == "Prefix" {
			return true
		}
	}
	for _, a := range s.MatchArgs {
		if !h.PathArgIndices[a.Index] {
			continue
		}
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
