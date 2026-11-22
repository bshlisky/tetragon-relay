package policydoc

import "errors"

// Every rejection this package can produce has a distinct sentinel (or
// wraps one with %w), per the project's "typed errors for every rejection"
// rule. Callers (internal/verify) only need to know that any non-nil error
// means REJECTED_SCHEMA; tests assert on these sentinels directly with
// errors.Is.
var (
	// --- B1: YAML hardening ---

	ErrMultipleYAMLDocuments = errors.New("policydoc: more than one YAML document")
	ErrEmptyYAMLDocument     = errors.New("policydoc: empty YAML document")
	ErrYAMLAlias             = errors.New("policydoc: YAML aliases are not allowed")
	ErrYAMLAnchor            = errors.New("policydoc: YAML anchors are not allowed")
	ErrYAMLMergeKey          = errors.New("policydoc: YAML merge keys (<<) are not allowed")
	ErrYAMLExplicitTag       = errors.New("policydoc: explicit YAML tags are not allowed")
	ErrYAMLDuplicateKey      = errors.New("policydoc: duplicate YAML mapping key")
	ErrYAMLNonStringKey      = errors.New("policydoc: non-string YAML mapping key")
	ErrYAMLMaxDepth          = errors.New("policydoc: YAML nesting exceeds maximum depth")
	ErrYAMLTooManyNodes      = errors.New("policydoc: YAML document has too many nodes")
	ErrYAMLScalarTooLarge    = errors.New("policydoc: YAML scalar exceeds maximum size")
	ErrYAMLTooManyKeys       = errors.New("policydoc: YAML mapping has too many keys")
	ErrYAMLInvalidUTF8       = errors.New("policydoc: YAML document is not valid UTF-8")
	ErrYAMLByteOrderMark     = errors.New("policydoc: YAML document has a byte-order mark")
	ErrYAMLNULByte           = errors.New("policydoc: YAML document contains a NUL byte")
	ErrYAMLControlChar       = errors.New("policydoc: YAML document contains a disallowed control character")
	ErrYAMLAmbiguousScalar   = errors.New("policydoc: unquoted scalar is ambiguous under YAML 1.1")
	ErrYAMLParse             = errors.New("policydoc: YAML syntax error")

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
)
