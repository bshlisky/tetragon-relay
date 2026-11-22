// Package policydoc implements step 2 prompt Part B: safe ingestion of a
// single TracingPolicy YAML document whose SHA-256 has already been
// verified by internal/verify (architecture doc section 7.4 step 11).
// Parse turns that YAML into an immutable, typed *Doc that internal/guard
// can analyze, after YAML hardening (B1), duplicate-key and CRD schema
// validation (B2/B3), a policy-level allowlist (B4), deterministic
// canonicalization (B5), a typed decode (B6), an independent
// action-completeness cross-check (B7), and bundle-name binding (B8).
package policydoc

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// HookKind identifies which of the four allowed hook types (step 2 prompt
// Part B4) a Hook represents.
type HookKind int

// The four hook kinds the step 2 prompt's B4 allowlist permits.
const (
	HookKindKProbe HookKind = iota
	HookKindTracepoint
	HookKindUProbe
	HookKindLsmHook
)

func (k HookKind) String() string {
	switch k {
	case HookKindKProbe:
		return "kprobe"
	case HookKindTracepoint:
		return "tracepoint"
	case HookKindUProbe:
		return "uprobe"
	case HookKindLsmHook:
		return "lsmhook"
	default:
		return "unknown"
	}
}

// Hook is one kprobe/tracepoint/uprobe/lsmhook spec, exposed to
// internal/guard in a shape uniform across hook kinds.
type Hook struct {
	Kind HookKind
	// Identifier is the hook's primary name used for guard rule matching:
	// the kprobe/fentry function name (Call), the LSM hook name (Hook),
	// "<subsystem>/<event>" for a tracepoint, or the traced binary's path
	// for a uprobe.
	Identifier string
	Selectors  []Selector
}

// Selector is a resolved KProbeSelector: any selectorsMacros reference
// (types.go's Macros field) has already been merged in by resolveSelector,
// so guard rules never need to know macros exist.
type Selector struct {
	MatchPIDs           []PIDSelector
	MatchArgs           []ArgSelector
	MatchActions        []ActionSelector
	MatchReturnArgs     []ArgSelector
	MatchReturnActions  []ActionSelector
	MatchBinaries       []BinarySelector
	MatchParentBinaries []BinarySelector
}

// PIDSelector is a resolved matchPIDs entry (types.go:318-333).
type PIDSelector struct {
	Operator string
	Values   []uint32
}

// ArgSelector is a resolved matchArgs/matchReturnArgs entry (types.go:335-351).
type ArgSelector struct {
	Index    uint32
	Operator string
	Values   []string
}

// BinarySelector is a resolved matchBinaries/matchParentBinaries entry
// (types.go:140-150).
type BinarySelector struct {
	Operator       string
	Values         []string
	FollowChildren bool
}

// ActionSelector is a resolved matchActions/matchReturnActions entry
// (types.go:366-481); only the Action name itself is exposed, since that is
// all internal/guard's rules need.
type ActionSelector struct {
	Action string
}

// Doc is the immutable result of a successful Parse.
type Doc struct {
	name          string
	hooks         []Hook
	canonicalJSON []byte
}

// Name is the policy's metadata.name, already checked against the bundle's
// declared name (B8).
func (d *Doc) Name() string { return d.name }

// Hooks returns every kprobe/tracepoint/uprobe/lsmhook in the document,
// each with its selectors fully resolved (macros merged in).
func (d *Doc) Hooks() []Hook { return d.hooks }

// CanonicalJSON returns a copy of the deterministic JSON form (B5) that
// Step 3 sends to Tetragon: sorted keys, no insignificant whitespace,
// numbers preserved exactly as parsed.
func (d *Doc) CanonicalJSON() []byte { return append([]byte(nil), d.canonicalJSON...) }

// CanonicalSHA256 returns sha256(CanonicalJSON()), which feeds the
// loaded-policy digest (architecture doc section 6.4).
func (d *Doc) CanonicalSHA256() [32]byte { return sha256.Sum256(d.canonicalJSON) }

// Parse implements internal/verify.PolicyParser for a single policy: name
// is the bundle's declared policies[].name (already schema-checked by
// internal/verify before Parse is called); yamlDoc is that policy's YAML
// text, whose SHA-256 internal/verify has already matched against the
// signed bundle's declared digest.
func Parse(name, yamlDoc string) (*Doc, error) {
	raw := []byte(yamlDoc)

	// B1: YAML hardening.
	root, err := parseHardenedYAML(raw)
	if err != nil {
		return nil, err
	}

	// B5 (computed here because B2/B3 both need JSON bytes; still
	// "deterministic JSON, sorted keys, no insignificant whitespace,
	// numbers preserved exactly as parsed").
	canonical, err := canonicalJSON(root)
	if err != nil {
		return nil, err
	}

	// B2: re-check for duplicate keys on the converted JSON using
	// internal/strictjson directly, as the prompt specifies, as a second,
	// independent check on top of B1's own duplicate-key detection.
	if err := strictjson.CheckNoDuplicateKeys(canonical, limits.MaxJSONDepth); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDuplicateJSONKey, err)
	}

	// Decode once generically (json.Number-preserving) for B3 schema
	// validation, B4's allowlist, and B7's independent cross-check walk.
	generic, err := decodeGeneric(canonical)
	if err != nil {
		return nil, err
	}

	// B3: CRD schema validation (closed schema).
	if err := validateAgainstSchema(generic); err != nil {
		return nil, err
	}

	// B4: policy-level allowlist.
	genericMap, ok := generic.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: document is not a JSON object", ErrSchemaValidation)
	}
	if err := checkAllowlist(genericMap); err != nil {
		return nil, err
	}

	// B6: typed model decode.
	var typed rawDoc
	if err := strictjson.DecodeStrict(canonical, limits.MaxJSONDepth, &typed); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrModelDecode, err)
	}

	// B7: independent action-completeness cross-check.
	if err := checkActionCompleteness(generic, &typed); err != nil {
		return nil, err
	}

	// B8: name binding.
	metaName, _ := typed.Metadata["name"].(string)
	if metaName == "" {
		return nil, ErrMissingName
	}
	if !limits.PolicyNamePattern.MatchString(metaName) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidName, metaName)
	}
	if metaName != name {
		return nil, fmt.Errorf("%w: metadata.name=%q, bundle policy name=%q", ErrNameMismatch, metaName, name)
	}

	hooks, err := buildHooks(&typed)
	if err != nil {
		return nil, err
	}

	return &Doc{
		name:          metaName,
		hooks:         hooks,
		canonicalJSON: canonical,
	}, nil
}

// decodeGeneric decodes canonical JSON bytes into interface{} using
// json.Number for numeric values, so schema validation and B4's allowlist
// checks see exactly what B5 canonicalized, without float64 precision loss
// for large integers.
func decodeGeneric(canonical []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJSONConvert, err)
	}
	return v, nil
}
