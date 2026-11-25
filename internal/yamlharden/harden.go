package yamlharden

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// byteOrderMark is the UTF-8 encoding of U+FEFF.
var byteOrderMark = []byte{0xEF, 0xBB, 0xBF}

// yaml11AmbiguousExact is the set of plain (unquoted) scalar texts that a
// YAML 1.1 parser resolves as booleans but yaml.v3 (YAML 1.2 core schema)
// does not. A YAML document this project verifies is not guaranteed to be
// read by the same parser later (ADR 0013, threat T-27): if that later
// reader interprets "yes" as a boolean while this package reads it as the
// string "yes", the verifier would have checked a different document than
// the one actually used. Rejected unless quoted.
var yaml11AmbiguousExact = map[string]struct{}{
	"y": {}, "Y": {}, "n": {}, "N": {},
	"yes": {}, "Yes": {}, "YES": {},
	"no": {}, "No": {}, "NO": {},
	"on": {}, "On": {}, "ON": {},
	"off": {}, "Off": {}, "OFF": {},
}

// yaml11OctalLike matches a plain scalar that looks like a leading-zero
// octal integer (e.g. "0755"). yaml.v3's own int resolution
// (gopkg.in/yaml.v3's resolve.go, via strconv.ParseInt(s, 0, 64)) already
// treats this as octal, but other YAML parsers (and a human reader) may
// expect it to mean the literal digits, so it is rejected unless quoted.
var yaml11OctalLike = regexp.MustCompile(`^[-+]?0[0-7]+$`)

// yaml11Sexagesimal matches a plain scalar using YAML 1.1's base-60
// (sexagesimal) number notation, dropped entirely in YAML 1.2 and
// explicitly unsupported by yaml.v3 (resolve.go's own comment: "Base 60
// floats are a bad idea ... purposefully unsupported here"), meaning a
// YAML 1.1 parser and yaml.v3 would already disagree about its value.
var yaml11Sexagesimal = regexp.MustCompile(`^[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9]*)?$`)

// yaml11InfNan matches plain-scalar spellings of infinity/NaN. yaml.v3
// resolves these to a float already; they are rejected unless quoted so
// that this package's notion of "the YAML 1.1 ambiguous set" does not
// depend on yaml.v3-specific resolution behavior a reader might not expect.
var yaml11InfNan = regexp.MustCompile(`^[-+]?\.(inf|Inf|INF|nan|NaN|NAN)$`)

// isYAML11Ambiguous reports whether a plain scalar's literal text would be
// read differently by a YAML 1.1 parser than a reasonable literal reading
// of the characters would suggest.
func isYAML11Ambiguous(raw string) bool {
	if _, ok := yaml11AmbiguousExact[raw]; ok {
		return true
	}
	return yaml11OctalLike.MatchString(raw) || yaml11Sexagesimal.MatchString(raw) || yaml11InfNan.MatchString(raw)
}

// isPlainScalar reports whether n is an unquoted, untagged scalar: the only
// style for which a YAML 1.1/1.2 reader disagreement is possible, since any
// explicit quoting or tag fixes the type unambiguously.
func isPlainScalar(n *yaml.Node) bool {
	const nonPlain = yaml.DoubleQuotedStyle | yaml.SingleQuotedStyle | yaml.LiteralStyle | yaml.FoldedStyle | yaml.TaggedStyle
	return n.Kind == yaml.ScalarNode && n.Style&nonPlain == 0
}

// checkRawBytes enforces the raw-byte-level hardening rules that must hold
// before any YAML tokenizing happens: valid UTF-8, no byte-order mark, no
// NUL bytes, no control characters other than tab/LF/CR.
func checkRawBytes(raw []byte) error {
	if bytes.HasPrefix(raw, byteOrderMark) {
		return ErrYAMLByteOrderMark
	}
	if !utf8.Valid(raw) {
		return ErrYAMLInvalidUTF8
	}
	if bytes.IndexByte(raw, 0x00) >= 0 {
		return ErrYAMLNULByte
	}
	for _, b := range raw {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return ErrYAMLControlChar
		}
		// DEL and C1 controls (0x80-0x9F) are multi-byte in UTF-8 and
		// handled by inspecting decoded runes instead, since ranging
		// over raw bytes here only sees ASCII control characters
		// directly; non-ASCII control runes are covered below.
	}
	for _, r := range string(raw) {
		if r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			return ErrYAMLControlChar
		}
	}
	return nil
}

// isNoncharacter reports whether r is one of the 66 Unicode noncharacters:
// U+FDD0..U+FDEF, and the last two code points of every plane (U+FFFE,
// U+FFFF, U+1FFFE, U+1FFFF, ..., U+10FFFE, U+10FFFF).
func isNoncharacter(r rune) bool {
	if r >= 0xFDD0 && r <= 0xFDEF {
		return true
	}
	low := r & 0xFFFF
	return low == 0xFFFE || low == 0xFFFF
}

// isDisallowedScalarRune applies to every decoded YAML scalar (key or
// value): reject Unicode category Cc except tab/LF/CR, all of category Cf
// (bidi controls, zero-width characters, the byte-order mark as a decoded
// character, etc.), the Unicode line/paragraph separators U+2028/U+2029,
// and noncharacters. Tab/LF/CR are allowed here (they are legitimate in,
// e.g., a free-form message string); a caller wanting to reject them in
// specific fields (identifiers, selector values) does so itself, on top
// of this baseline.
func isDisallowedScalarRune(r rune) bool {
	switch r {
	case '\t', '\n', '\r':
		return false
	case 0x2028, 0x2029:
		return true
	}
	if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
		return true
	}
	return isNoncharacter(r)
}

// checkScalarContent scans a fully escape-decoded YAML scalar value for
// every rune isDisallowedScalarRune forbids. It must run on n.Value (the
// decoded form), never on the raw document bytes: checkRawBytes already
// rejects a literal NUL byte or control character typed directly into the
// document, but a double-quoted scalar's "\0" or "\u202e" escape sequence
// is plain ASCII in the raw bytes and only becomes the dangerous character
// once yaml.v3 decodes it, which is exactly what this check closes.
func checkScalarContent(s string) error {
	for _, r := range s {
		if isDisallowedScalarRune(r) {
			return fmt.Errorf("%w: %q", ErrYAMLInvisibleOrControlChar, s)
		}
	}
	return nil
}

// hardenedYAML walks a structurally-hardened yaml.Node tree. nodeCount and
// maxDepth bound the walk itself (DoS resistance); every structural
// rejection rule is enforced here in a single pass.
type hardenedYAML struct {
	nodeCount int
}

func (h *hardenedYAML) walk(n *yaml.Node, depth int) error {
	h.nodeCount++
	if h.nodeCount > limits.MaxYAMLNodeCount {
		return ErrYAMLTooManyNodes
	}
	if depth > limits.MaxYAMLDepth {
		return ErrYAMLMaxDepth
	}
	if n.Anchor != "" {
		return ErrYAMLAnchor
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return ErrYAMLExplicitTag
	}

	switch n.Kind { //nolint:exhaustive // DocumentNode never appears below the document's own root content node, which Parse strips before walking
	case yaml.AliasNode:
		return ErrYAMLAlias
	case yaml.ScalarNode:
		if len(n.Value) > limits.MaxYAMLScalarBytes {
			return ErrYAMLScalarTooLarge
		}
		if err := checkScalarContent(n.Value); err != nil {
			return err
		}
		if isPlainScalar(n) && isYAML11Ambiguous(n.Value) {
			return fmt.Errorf("%w: %q", ErrYAMLAmbiguousScalar, n.Value)
		}
		return nil
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if err := h.walk(c, depth+1); err != nil {
				return err
			}
		}
		return nil
	case yaml.MappingNode:
		return h.walkMapping(n, depth)
	default:
		return fmt.Errorf("%w: unexpected node kind %d", ErrYAMLParse, n.Kind)
	}
}

func (h *hardenedYAML) walkMapping(n *yaml.Node, depth int) error {
	if len(n.Content)%2 != 0 {
		return fmt.Errorf("%w: unbalanced mapping", ErrYAMLParse)
	}
	numKeys := len(n.Content) / 2
	if numKeys > limits.MaxKeysPerObject {
		return ErrYAMLTooManyKeys
	}
	seen := make(map[string]struct{}, numKeys)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i]
		val := n.Content[i+1]

		if key.Anchor != "" {
			return ErrYAMLAnchor
		}
		if key.Style&yaml.TaggedStyle != 0 {
			return ErrYAMLExplicitTag
		}
		if key.Kind == yaml.AliasNode {
			return ErrYAMLAlias
		}
		if len(key.Value) > limits.MaxYAMLScalarBytes {
			return ErrYAMLScalarTooLarge
		}
		if err := checkScalarContent(key.Value); err != nil {
			return err
		}
		if key.Kind == yaml.ScalarNode && key.Value == "<<" {
			return ErrYAMLMergeKey
		}
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return ErrYAMLNonStringKey
		}
		if isPlainScalar(key) && isYAML11Ambiguous(key.Value) {
			return fmt.Errorf("%w: %q", ErrYAMLAmbiguousScalar, key.Value)
		}

		fk := strictjson.FoldKey(key.Value)
		if _, dup := seen[fk]; dup {
			return fmt.Errorf("%w: %q", ErrYAMLDuplicateKey, key.Value)
		}
		seen[fk] = struct{}{}

		if err := h.walk(val, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// Parse decodes raw as exactly one YAML document, rejects every construct
// this package's rules forbid, and returns the single root content node
// (the document's one child, e.g. a mapping node) for conversion to
// canonical JSON or further typed decoding by the caller.
func Parse(raw []byte) (*yaml.Node, error) {
	if err := checkRawBytes(raw); err != nil {
		return nil, err
	}

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrEmptyYAMLDocument
		}
		return nil, fmt.Errorf("%w: %w", ErrYAMLParse, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, ErrEmptyYAMLDocument
	}

	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, ErrMultipleYAMLDocuments
	}

	root := doc.Content[0]
	h := &hardenedYAML{}
	if err := h.walk(root, 1); err != nil {
		return nil, err
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: top-level document must be a mapping", ErrYAMLParse)
	}
	return root, nil
}
