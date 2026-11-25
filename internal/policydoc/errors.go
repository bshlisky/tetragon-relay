package policydoc

import (
	"errors"

	"github.com/bshlisky/tetragon-relay/internal/yamlharden"
)

// Every rejection this package can produce has a distinct sentinel (or
// wraps one with %w), per the project's "typed errors for every rejection"
// rule. Callers (internal/verify) only need to know that any non-nil error
// means REJECTED_SCHEMA; tests assert on these sentinels directly with
// errors.Is.
var (
	// --- B1: YAML hardening ---
	//
	// docs/prompts/step-06a.md Part B2: these are now aliases of
	// internal/yamlharden's own sentinels (the hardening rules were
	// extracted there, shared with internal/config). Aliasing keeps
	// every existing errors.Is(err, policydoc.ErrYAMLXxx) call in this
	// package's own tests (and any external caller) working unchanged:
	// an alias is the identical error value, not a new one.

	ErrMultipleYAMLDocuments      = yamlharden.ErrMultipleYAMLDocuments
	ErrEmptyYAMLDocument          = yamlharden.ErrEmptyYAMLDocument
	ErrYAMLAlias                  = yamlharden.ErrYAMLAlias
	ErrYAMLAnchor                 = yamlharden.ErrYAMLAnchor
	ErrYAMLMergeKey               = yamlharden.ErrYAMLMergeKey
	ErrYAMLExplicitTag            = yamlharden.ErrYAMLExplicitTag
	ErrYAMLDuplicateKey           = yamlharden.ErrYAMLDuplicateKey
	ErrYAMLNonStringKey           = yamlharden.ErrYAMLNonStringKey
	ErrYAMLMaxDepth               = yamlharden.ErrYAMLMaxDepth
	ErrYAMLTooManyNodes           = yamlharden.ErrYAMLTooManyNodes
	ErrYAMLScalarTooLarge         = yamlharden.ErrYAMLScalarTooLarge
	ErrYAMLTooManyKeys            = yamlharden.ErrYAMLTooManyKeys
	ErrYAMLInvalidUTF8            = yamlharden.ErrYAMLInvalidUTF8
	ErrYAMLByteOrderMark          = yamlharden.ErrYAMLByteOrderMark
	ErrYAMLNULByte                = yamlharden.ErrYAMLNULByte
	ErrYAMLControlChar            = yamlharden.ErrYAMLControlChar
	ErrYAMLAmbiguousScalar        = yamlharden.ErrYAMLAmbiguousScalar
	ErrYAMLParse                  = yamlharden.ErrYAMLParse
	ErrYAMLInvisibleOrControlChar = yamlharden.ErrYAMLInvisibleOrControlChar

	// --- B2/B3: JSON conversion, duplicate keys, schema ---

	ErrJSONConvert      = errors.New("policydoc: could not convert YAML to JSON")
	ErrDuplicateJSONKey = errors.New("policydoc: duplicate JSON key after conversion")
	ErrSchemaValidation = errors.New("policydoc: document does not conform to the TracingPolicy schema")

	// --- B4: policy-level allowlist ---

	ErrUnsupportedAPIVersion = errors.New("policydoc: unsupported apiVersion")
	ErrUnsupportedKind       = errors.New("policydoc: unsupported kind (TracingPolicyNamespaced is not supported; there is no Kubernetes here)")
	ErrKubernetesSelector    = errors.New("policydoc: Kubernetes-only selector is not supported on bare RHEL")
	ErrUnsupportedHookType   = errors.New("policydoc: unsupported hook type")
	ErrMissingName           = errors.New("policydoc: metadata.name is missing or empty")
	ErrInvalidName           = errors.New("policydoc: metadata.name is not a valid policy name")

	// --- B6: typed model decode ---

	ErrModelDecode = errors.New("policydoc: canonical JSON does not decode into the typed model")

	// --- B7: completeness cross-check ---

	ErrUnmodeledAction = errors.New("policydoc: unmodeled action location (generic and typed-model action counts differ)")

	// --- B8: name binding ---

	ErrNameMismatch = errors.New("policydoc: metadata.name does not match the bundle's policy name")

	// --- A1 (step 3 prompt, architect review R2D-1): escape-decoded
	// control and invisible characters ---
	//
	// ErrYAMLInvisibleOrControlChar is aliased above, in the B1 group
	// (it is now internal/yamlharden's sentinel); kept documented here
	// since ErrHookIdentifierWhitespace/ErrSelectorValueWhitespace
	// below are its narrower, field-specific siblings from the same
	// architect review.

	// ErrHookIdentifierWhitespace is returned when a hook identifier
	// (kprobe call, tracepoint subsystem/event, uprobe path/symbols,
	// lsmhook hook) contains a tab, newline, or carriage return. These
	// are otherwise-legal scalar characters (ErrYAMLInvisibleOrControlChar
	// exempts them) but have no legitimate meaning inside an identifier
	// Tetragon matches as an opaque string, and a tab/newline embedded in
	// one can make an approver's rendering of the policy differ from
	// what is actually loaded (architect review R2D-1).
	ErrHookIdentifierWhitespace = errors.New("policydoc: hook identifier contains a tab, newline, or carriage return")

	// ErrSelectorValueWhitespace is the matchBinaries/matchParentBinaries
	// and matchArgs/matchData/matchReturnArgs analog of
	// ErrHookIdentifierWhitespace: a tab/newline/CR inside a selector
	// value has no legitimate use and the same spoofing risk.
	ErrSelectorValueWhitespace = errors.New("policydoc: selector value contains a tab, newline, or carriage return")
)
