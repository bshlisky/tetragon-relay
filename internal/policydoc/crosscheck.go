package policydoc

import (
	"fmt"
	"sort"
)

// genericActionWalk independently walks a generically-decoded JSON value
// (step 2 prompt Part B7) and collects every string found under an
// "action" key inside any element of an array named "matchActions" or
// "matchReturnActions", anywhere in the document, regardless of nesting
// position. This does not use the typed model at all: it is the
// independent check B7 requires, so a bug or omission in model.go's field
// coverage cannot also hide the mismatch it is meant to catch.
func genericActionWalk(v interface{}) []string {
	var out []string
	var walk func(key string, v interface{})
	walk = func(key string, v interface{}) {
		switch t := v.(type) {
		case map[string]interface{}:
			for k, child := range t {
				walk(k, child)
			}
		case []interface{}:
			if key == "matchActions" || key == "matchReturnActions" {
				for _, elem := range t {
					if m, ok := elem.(map[string]interface{}); ok {
						if action, ok := m["action"].(string); ok {
							out = append(out, action)
						}
					}
				}
			}
			for _, child := range t {
				walk("", child)
			}
		}
	}
	walk("", v)
	return out
}

// typedModelActionWalk collects every action string the typed model (B6)
// knows about, from the same positions a real policy load would evaluate:
// every hook type's selectors, and every selectorsMacros entry (since a
// selector can pull a macro's filters, including its actions, in by
// reference; see resolveSelector).
func (d *rawDoc) typedModelActionWalk() []string {
	var out []string
	collect := func(sels []rawSelector) {
		for _, s := range sels {
			for _, a := range s.MatchActions {
				out = append(out, a.Action)
			}
			for _, a := range s.MatchReturnActions {
				out = append(out, a.Action)
			}
		}
	}
	for _, k := range d.Spec.KProbes {
		collect(k.Selectors)
	}
	for _, t := range d.Spec.Tracepoints {
		collect(t.Selectors)
	}
	for _, u := range d.Spec.UProbes {
		collect(u.Selectors)
	}
	for _, l := range d.Spec.LsmHooks {
		collect(l.Selectors)
	}
	for _, m := range d.Spec.SelectorsMacros {
		collect([]rawSelector{m})
	}
	return out
}

// checkActionCompleteness implements B7: the multiset of actions found by
// the independent generic walk must equal the multiset the typed model
// knows about. Any difference means some part of the document structure
// can carry a matchActions/matchReturnActions entry that model.go's
// field-by-field coverage does not visit, which would let an action (e.g.
// Sigkill) hide from internal/guard entirely.
func checkActionCompleteness(generic interface{}, typed *rawDoc) error {
	genericActions := sortedCopy(genericActionWalk(generic))
	typedActions := sortedCopy(typed.typedModelActionWalk())

	if len(genericActions) != len(typedActions) {
		return fmt.Errorf("%w: generic walk found %d action(s), typed model found %d", ErrUnmodeledAction, len(genericActions), len(typedActions))
	}
	for i := range genericActions {
		if genericActions[i] != typedActions[i] {
			return fmt.Errorf("%w: action multisets differ (generic has %q where typed model has %q)", ErrUnmodeledAction, genericActions[i], typedActions[i])
		}
	}
	return nil
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
