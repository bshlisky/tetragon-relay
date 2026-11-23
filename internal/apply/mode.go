package apply

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// enforcementActionNames mirrors internal/guard/actions.go's
// enforcementActions exactly (Sigkill, Signal, NotifyEnforcer, Override,
// Set; pkg/selectors/kernel.go:2339-2349's HasEnforcementAction in the
// pinned v1.8.0 source). Duplicated rather than imported because
// internal/guard does not export it; TestEnforcementActionNamesMatchGuard
// keeps the two lists from silently drifting apart. By the time Apply ever
// sees a bundle, G7 has already rejected every action name not in
// internal/guard's enforcementActions/observeActions union, so this is an
// exhaustive, not merely best-effort, rewrite target.
var enforcementActionNames = map[string]bool{
	"Sigkill":        true,
	"Signal":         true,
	"NotifyEnforcer": true,
	"Override":       true,
	"Set":            true,
}

// rewriteActionsToPost implements step 3 prompt Part D2's fallback
// mechanism (ADR 0016: the only mechanism this project ever uses, since
// native TracingPolicyMode requires ConfigureTracingPolicy, outside Part
// B1's allowlist). It walks canonicalJSON generically (no assumption about
// which hook/selector shape an "action" field appears under — reject-more:
// this also catches an action hidden somewhere this project's typed model
// does not explicitly walk, docs/reports/step-03.md section 14) and
// rewrites every object field literally named "action" whose string value
// is in enforcementActionNames to "Post".
//
// The result is re-encoded with sorted object keys and no insignificant
// whitespace; see marshalCanonical's doc comment for why that is a valid
// re-canonicalization.
func rewriteActionsToPost(canonicalJSON []byte) ([]byte, error) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(canonicalJSON))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("apply: decode canonical JSON: %w", err)
	}
	rewriteActionsInPlace(v)
	return marshalCanonical(v)
}

func rewriteActionsInPlace(v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		if action, ok := t["action"].(string); ok && enforcementActionNames[action] {
			t["action"] = "Post"
		}
		for _, child := range t {
			rewriteActionsInPlace(child)
		}
	case []interface{}:
		for _, child := range t {
			rewriteActionsInPlace(child)
		}
	}
}

// setMetadataName implements the metadata.name half of step 3 prompt Part
// D1: "The rewrite is applied to metadata.name in the canonical JSON and
// the doc is re-canonicalized."
func setMetadataName(canonicalJSON []byte, loadedName string) ([]byte, error) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(canonicalJSON))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("apply: decode canonical JSON: %w", err)
	}
	root, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("apply: canonical JSON root is not an object")
	}
	metadata, ok := root["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("apply: canonical JSON has no metadata object")
	}
	metadata["name"] = loadedName
	return marshalCanonical(v)
}

// marshalCanonical re-encodes a value decoded via UseNumber(), relying on
// encoding/json.Marshal's documented guarantee that map[string]interface{}
// keys are emitted in sorted order and that json.Number marshals back as
// its original textual digits (no float64 round-trip): together these
// reproduce this project's "deterministic JSON, sorted keys, no
// insignificant whitespace, numbers preserved exactly as parsed"
// definition of canonical JSON (internal/policydoc's own Part B5) without
// needing to depend on internal/policydoc's YAML-node-based canonicalizer.
func marshalCanonical(v interface{}) ([]byte, error) {
	out, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("apply: re-marshal canonical JSON: %w", err)
	}
	return out, nil
}
