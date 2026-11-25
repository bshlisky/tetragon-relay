package yamlharden

import "errors"

// Every rejection this package can produce has a distinct sentinel (or
// wraps one with %w). Callers (internal/policydoc, internal/config) are
// expected to re-export these as their own aliases so their own callers
// can keep matching with errors.Is against a name scoped to the calling
// package, without this package's identity changing: an alias (var X =
// yamlharden.X) is the same error value, so errors.Is(err, policydoc.X)
// and errors.Is(err, yamlharden.X) agree.
var (
	ErrMultipleYAMLDocuments = errors.New("yamlharden: more than one YAML document")
	ErrEmptyYAMLDocument     = errors.New("yamlharden: empty YAML document")
	ErrYAMLAlias             = errors.New("yamlharden: YAML aliases are not allowed")
	ErrYAMLAnchor            = errors.New("yamlharden: YAML anchors are not allowed")
	ErrYAMLMergeKey          = errors.New("yamlharden: YAML merge keys (<<) are not allowed")
	ErrYAMLExplicitTag       = errors.New("yamlharden: explicit YAML tags are not allowed")
	ErrYAMLDuplicateKey      = errors.New("yamlharden: duplicate YAML mapping key")
	ErrYAMLNonStringKey      = errors.New("yamlharden: non-string YAML mapping key")
	ErrYAMLMaxDepth          = errors.New("yamlharden: YAML nesting exceeds maximum depth")
	ErrYAMLTooManyNodes      = errors.New("yamlharden: YAML document has too many nodes")
	ErrYAMLScalarTooLarge    = errors.New("yamlharden: YAML scalar exceeds maximum size")
	ErrYAMLTooManyKeys       = errors.New("yamlharden: YAML mapping has too many keys")
	ErrYAMLInvalidUTF8       = errors.New("yamlharden: YAML document is not valid UTF-8")
	ErrYAMLByteOrderMark     = errors.New("yamlharden: YAML document has a byte-order mark")
	ErrYAMLNULByte           = errors.New("yamlharden: YAML document contains a NUL byte")
	ErrYAMLControlChar       = errors.New("yamlharden: YAML document contains a disallowed control character")
	ErrYAMLAmbiguousScalar   = errors.New("yamlharden: unquoted scalar is ambiguous under YAML 1.1")
	ErrYAMLParse             = errors.New("yamlharden: YAML syntax error")

	// ErrYAMLInvisibleOrControlChar is returned when a decoded scalar
	// (key or value, after YAML escape processing) contains a Unicode
	// category Cc code point other than tab/LF/CR, any category Cf code
	// point, U+2028, U+2029, or a noncharacter. checkRawBytes only
	// inspects the raw document bytes, which a quoted scalar's escape
	// sequences (\0, \u202e, ...) bypass entirely; this check runs on
	// every decoded scalar value instead (architect review R2D-1).
	ErrYAMLInvisibleOrControlChar = errors.New("yamlharden: scalar contains a disallowed control or invisible character")
)
