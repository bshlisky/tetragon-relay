package policydoc

import "fmt"

// ErrUnknownMacro is returned when a selector's `macros` field names an
// entry not present in spec.selectorsMacros.
var ErrUnknownMacro = fmt.Errorf("%w: unknown macro name", ErrModelDecode)

// buildHooks converts the typed model's per-hook-type specs into the
// exported, uniform Hook/Selector shape internal/guard consumes, resolving
// every selector's macro references along the way.
func buildHooks(d *rawDoc) ([]Hook, error) {
	var hooks []Hook

	for _, k := range d.Spec.KProbes {
		sels, err := resolveSelectors(k.Selectors, d.Spec.SelectorsMacros)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, Hook{Kind: HookKindKProbe, Identifier: k.Call, Selectors: sels})
	}
	for _, t := range d.Spec.Tracepoints {
		sels, err := resolveSelectors(t.Selectors, d.Spec.SelectorsMacros)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, Hook{Kind: HookKindTracepoint, Identifier: t.Subsystem + "/" + t.Event, Selectors: sels})
	}
	for _, u := range d.Spec.UProbes {
		sels, err := resolveSelectors(u.Selectors, d.Spec.SelectorsMacros)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, Hook{Kind: HookKindUProbe, Identifier: u.Path, Selectors: sels})
	}
	for _, l := range d.Spec.LsmHooks {
		sels, err := resolveSelectors(l.Selectors, d.Spec.SelectorsMacros)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, Hook{Kind: HookKindLsmHook, Identifier: l.Hook, Selectors: sels})
	}
	return hooks, nil
}

// resolveSelectors converts a slice of raw selectors, resolving each one's
// macro references.
func resolveSelectors(raws []rawSelector, macros map[string]rawSelector) ([]Selector, error) {
	out := make([]Selector, 0, len(raws))
	for _, r := range raws {
		s, err := resolveSelector(r, macros)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// resolveSelector converts one raw selector, merging in every macro it
// references (types.go: "Filters specified in macros will be appended to
// corresponding filters of the selector."). This is security-relevant: a
// selector can carry zero matchActions of its own while a referenced macro
// supplies the actual enforcement action, so guard rules must see the
// merged result, not the raw selector, or G1-G3 could be bypassed by
// hiding an enforcement action inside a macro. Macro chaining (a macro
// referencing another macro) is not resolved recursively: the pinned CRD
// models selectorsMacros as map[string]KProbeSelector with its own Macros
// field, but this project found no documented support for macro-of-macro
// expansion in the pinned source and, per "never guess a fact", treats a
// macro that itself names other macros as using only its own direct
// filters (see docs/reports/step-02b.md open questions).
func resolveSelector(r rawSelector, macros map[string]rawSelector) (Selector, error) {
	s := Selector{
		MatchPIDs:           convertPIDSelectors(r.MatchPIDs),
		MatchArgs:           convertArgSelectors(r.MatchArgs),
		MatchActions:        convertActionSelectors(r.MatchActions),
		MatchReturnArgs:     convertArgSelectors(r.MatchReturnArgs),
		MatchReturnActions:  convertActionSelectors(r.MatchReturnActions),
		MatchBinaries:       convertBinarySelectors(r.MatchBinaries),
		MatchParentBinaries: convertBinarySelectors(r.MatchParentBinaries),
	}
	for _, name := range r.Macros {
		m, ok := macros[name]
		if !ok {
			return Selector{}, fmt.Errorf("%w: %q", ErrUnknownMacro, name)
		}
		s.MatchPIDs = append(s.MatchPIDs, convertPIDSelectors(m.MatchPIDs)...)
		s.MatchArgs = append(s.MatchArgs, convertArgSelectors(m.MatchArgs)...)
		s.MatchActions = append(s.MatchActions, convertActionSelectors(m.MatchActions)...)
		s.MatchReturnArgs = append(s.MatchReturnArgs, convertArgSelectors(m.MatchReturnArgs)...)
		s.MatchReturnActions = append(s.MatchReturnActions, convertActionSelectors(m.MatchReturnActions)...)
		s.MatchBinaries = append(s.MatchBinaries, convertBinarySelectors(m.MatchBinaries)...)
		s.MatchParentBinaries = append(s.MatchParentBinaries, convertBinarySelectors(m.MatchParentBinaries)...)
	}
	return s, nil
}

func convertPIDSelectors(in []rawPIDSelector) []PIDSelector {
	if in == nil {
		return nil
	}
	out := make([]PIDSelector, len(in))
	for i, p := range in {
		out[i] = PIDSelector{Operator: p.Operator, Values: p.Values}
	}
	return out
}

func convertArgSelectors(in []rawArgSelector) []ArgSelector {
	if in == nil {
		return nil
	}
	out := make([]ArgSelector, len(in))
	for i, a := range in {
		out[i] = ArgSelector{Index: a.Index, Operator: a.Operator, Values: a.Values}
	}
	return out
}

func convertBinarySelectors(in []rawBinarySelector) []BinarySelector {
	if in == nil {
		return nil
	}
	out := make([]BinarySelector, len(in))
	for i, b := range in {
		out[i] = BinarySelector(b)
	}
	return out
}

func convertActionSelectors(in []rawActionSelector) []ActionSelector {
	if in == nil {
		return nil
	}
	out := make([]ActionSelector, len(in))
	for i, a := range in {
		out[i] = ActionSelector{Action: a.Action}
	}
	return out
}
