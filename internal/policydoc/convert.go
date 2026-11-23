package policydoc

import (
	"fmt"
	"strings"
)

// ErrUnknownMacro is returned when a selector's `macros` field names an
// entry not present in spec.selectorsMacros.
var ErrUnknownMacro = fmt.Errorf("%w: unknown macro name", ErrModelDecode)

// containsLineWhitespace reports whether s contains a tab, newline, or
// carriage return: step 3 prompt Part A1's additional rule for selector
// values and hook identifiers, on top of the generic scalar check in
// yamlharden.go (which deliberately allows these three characters
// elsewhere, e.g. in a free-form message string).
func containsLineWhitespace(s string) bool {
	return strings.ContainsAny(s, "\t\n\r")
}

// checkIdentifierWhitespace enforces Part A1 on a hook identifier field
// (call, symbols, path, subsystem, event, hook).
func checkIdentifierWhitespace(s string) error {
	if containsLineWhitespace(s) {
		return fmt.Errorf("%w: %q", ErrHookIdentifierWhitespace, s)
	}
	return nil
}

// buildHooks converts the typed model's per-hook-type specs into the
// exported, uniform Hook/Selector shape internal/guard consumes, resolving
// every selector's macro references along the way.
func buildHooks(d *rawDoc) ([]Hook, error) {
	var hooks []Hook

	for _, k := range d.Spec.KProbes {
		if err := checkIdentifierWhitespace(k.Call); err != nil {
			return nil, err
		}
		sels, err := resolveSelectors(k.Selectors, d.Spec.SelectorsMacros)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, Hook{Kind: HookKindKProbe, Identifier: k.Call, Selectors: sels, PathArgIndices: pathArgIndices(k.Args)})
	}
	for _, t := range d.Spec.Tracepoints {
		if err := checkIdentifierWhitespace(t.Subsystem); err != nil {
			return nil, err
		}
		if err := checkIdentifierWhitespace(t.Event); err != nil {
			return nil, err
		}
		sels, err := resolveSelectors(t.Selectors, d.Spec.SelectorsMacros)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, Hook{Kind: HookKindTracepoint, Identifier: t.Subsystem + "/" + t.Event, Selectors: sels, PathArgIndices: pathArgIndices(t.Args)})
	}
	for _, u := range d.Spec.UProbes {
		if err := checkIdentifierWhitespace(u.Path); err != nil {
			return nil, err
		}
		for _, sym := range u.Symbols {
			if err := checkIdentifierWhitespace(sym); err != nil {
				return nil, err
			}
		}
		sels, err := resolveSelectors(u.Selectors, d.Spec.SelectorsMacros)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, Hook{Kind: HookKindUProbe, Identifier: u.Path, Selectors: sels, PathArgIndices: pathArgIndices(u.Args)})
	}
	for _, l := range d.Spec.LsmHooks {
		if err := checkIdentifierWhitespace(l.Hook); err != nil {
			return nil, err
		}
		sels, err := resolveSelectors(l.Selectors, d.Spec.SelectorsMacros)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, Hook{Kind: HookKindLsmHook, Identifier: l.Hook, Selectors: sels, PathArgIndices: pathArgIndices(l.Args)})
	}
	return hooks, nil
}

// pathArgTypes are the KProbeArg.Type values (types.go:79's Type enum)
// internal/guard's G2/G3 treat as path-typed, per architect review (step
// 2c) item C2. Two sources, both cited:
//
//   - Tetragon's own path-type classifier,
//     pkg/generictypes/generictypes.go:277-283 (func PathType), used by
//     the sensor itself to decide which arg types need path resolution
//     (pkg/sensors/tracing/generic.go:297:
//     "generictypes.PathType(ty) && selectors.HasFilter(s, index)"):
//     path, file, dentry, linux_binprm, kiocb.
//   - Every remaining string/byte-buffer-shaped type from that same
//     file's genericStringToType table (generictypes.go:84-136), which
//     PathType() does not itself classify as "path" but which this
//     project treats as path-typed defensively for guardrail purposes
//     (architect review: "every string-like arg type ... and any other
//     textual type"), since a policy author can put a filesystem path in
//     any of these: string, char_buf, char_iovec, filename, const_buf,
//     data_loc.
//
// linux_binprm specifically: pkg/selectors/kernel.go:1287-1293 confirms
// Equal/NotEqual on a linux_binprm-typed arg goes through
// writeMatchStrings, the same exact-string comparison path used for
// file/path/string types (not a numeric or struct comparison), and
// pkg/sensors/tracing/kprobe_test.go:5550's TestLinuxBinprmExtractPath /
// lsm_test.go:264's WithLinuxBinprmArg(...).WithPath(testBin) confirm the
// compared value is the binary's path: pinned-source confirmation that
// architect review item C4 required before G3 could count linux_binprm
// matchArgs as scoping.
var pathArgTypes = map[string]bool{
	"path":         true,
	"file":         true,
	"dentry":       true,
	"linux_binprm": true,
	"kiocb":        true,
	"string":       true,
	"char_buf":     true,
	"char_iovec":   true,
	"filename":     true,
	"const_buf":    true,
	"data_loc":     true,
}

// pathArgIndices returns the set of Index values among args whose Type is
// path-typed.
func pathArgIndices(args []rawKProbeArg) map[uint32]bool {
	out := make(map[uint32]bool)
	for _, a := range args {
		if pathArgTypes[a.Type] {
			out[a.Index] = true
		}
	}
	return out
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
	matchArgs, err := convertArgSelectors(r.MatchArgs)
	if err != nil {
		return Selector{}, err
	}
	matchReturnArgs, err := convertArgSelectors(r.MatchReturnArgs)
	if err != nil {
		return Selector{}, err
	}
	matchBinaries, err := convertBinarySelectors(r.MatchBinaries)
	if err != nil {
		return Selector{}, err
	}
	matchParentBinaries, err := convertBinarySelectors(r.MatchParentBinaries)
	if err != nil {
		return Selector{}, err
	}
	s := Selector{
		MatchPIDs:           convertPIDSelectors(r.MatchPIDs),
		MatchArgs:           matchArgs,
		MatchActions:        convertActionSelectors(r.MatchActions),
		MatchReturnArgs:     matchReturnArgs,
		MatchReturnActions:  convertActionSelectors(r.MatchReturnActions),
		MatchBinaries:       matchBinaries,
		MatchParentBinaries: matchParentBinaries,
	}
	for _, name := range r.Macros {
		m, ok := macros[name]
		if !ok {
			return Selector{}, fmt.Errorf("%w: %q", ErrUnknownMacro, name)
		}
		mArgs, err := convertArgSelectors(m.MatchArgs)
		if err != nil {
			return Selector{}, err
		}
		mReturnArgs, err := convertArgSelectors(m.MatchReturnArgs)
		if err != nil {
			return Selector{}, err
		}
		mBinaries, err := convertBinarySelectors(m.MatchBinaries)
		if err != nil {
			return Selector{}, err
		}
		mParentBinaries, err := convertBinarySelectors(m.MatchParentBinaries)
		if err != nil {
			return Selector{}, err
		}
		s.MatchPIDs = append(s.MatchPIDs, convertPIDSelectors(m.MatchPIDs)...)
		s.MatchArgs = append(s.MatchArgs, mArgs...)
		s.MatchActions = append(s.MatchActions, convertActionSelectors(m.MatchActions)...)
		s.MatchReturnArgs = append(s.MatchReturnArgs, mReturnArgs...)
		s.MatchReturnActions = append(s.MatchReturnActions, convertActionSelectors(m.MatchReturnActions)...)
		s.MatchBinaries = append(s.MatchBinaries, mBinaries...)
		s.MatchParentBinaries = append(s.MatchParentBinaries, mParentBinaries...)
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

// checkSelectorValueWhitespace enforces Part A1 on a matchArgs/matchData/
// matchReturnArgs/matchBinaries/matchParentBinaries value. The step 3
// prompt names "matchArgs values" explicitly; this project applies the
// same rule to matchData and matchReturnArgs (which share ArgSelector's
// shape and are compared the same way) and to matchParentBinaries (which
// shares matchBinaries' shape and purpose) as a reject-more interpretation
// (see docs/reports/step-03.md section 14).
func checkSelectorValueWhitespace(v string) error {
	if containsLineWhitespace(v) {
		return fmt.Errorf("%w: %q", ErrSelectorValueWhitespace, v)
	}
	return nil
}

func convertArgSelectors(in []rawArgSelector) ([]ArgSelector, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]ArgSelector, len(in))
	for i, a := range in {
		for _, v := range a.Values {
			if err := checkSelectorValueWhitespace(v); err != nil {
				return nil, err
			}
		}
		out[i] = ArgSelector{Index: a.Index, Operator: a.Operator, Values: a.Values}
	}
	return out, nil
}

func convertBinarySelectors(in []rawBinarySelector) ([]BinarySelector, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]BinarySelector, len(in))
	for i, b := range in {
		for _, v := range b.Values {
			if err := checkSelectorValueWhitespace(v); err != nil {
				return nil, err
			}
		}
		out[i] = BinarySelector(b)
	}
	return out, nil
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
