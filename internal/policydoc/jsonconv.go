package policydoc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"gopkg.in/yaml.v3"
)

// jsonNumberLiteral matches a scalar's raw YAML text that is *already*
// valid JSON number syntax verbatim (RFC 8259 grammar: optional leading
// '-', no leading '+', no leading zero before further digits except "0"
// itself, optional fraction, optional exponent). For any literal matching
// this, the canonicalizer emits the original bytes unchanged: the "numbers
// preserved exactly as parsed, no float re-encoding" rule in step 2 prompt
// Part B5 is satisfied exactly, including for integers wider than a
// float64 can represent without loss.
//
// YAML numeric spellings that are not already valid JSON syntax (hex
// "0x1A", underscore-grouped "1_000", explicit "+5") are resolved via
// yaml.v3's own decode and re-rendered with exact-precision
// strconv formatting instead; see renderNumber.
var jsonNumberLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// toCanonicalValue converts a hardened yaml.Node into a canonicalValue
// ready for deterministic JSON rendering (step 2 prompt Part B2/B5). The
// node must already have passed parseHardenedYAML's checks (no aliases,
// anchors, explicit tags, duplicate/non-string keys, depth/size bounds).
func toCanonicalValue(n *yaml.Node) (canonicalValue, error) {
	switch n.Kind { //nolint:exhaustive // DocumentNode/AliasNode never reach here: parseHardenedYAML rejects aliases and only ever hands this the single document's root content node

	case yaml.MappingNode:
		obj := make(map[string]canonicalValue, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			v, err := toCanonicalValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			obj[n.Content[i].Value] = v
		}
		return cvObject(obj), nil
	case yaml.SequenceNode:
		arr := make([]canonicalValue, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := toCanonicalValue(c)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return cvArray(arr), nil
	case yaml.ScalarNode:
		return scalarToCanonicalValue(n)
	default:
		return nil, fmt.Errorf("%w: unexpected node kind %d", ErrJSONConvert, n.Kind)
	}
}

func scalarToCanonicalValue(n *yaml.Node) (canonicalValue, error) {
	switch n.Tag {
	case "!!str":
		return cvString(n.Value), nil
	case "!!bool":
		// yaml.v3 only ever resolves "!!bool" for exactly these six
		// literal spellings (resolve.go's resolveMap); any other value
		// cannot reach this branch with that tag.
		return cvBool(n.Value == "true" || n.Value == "True" || n.Value == "TRUE"), nil
	case "!!null":
		return cvNull{}, nil
	case "!!int", "!!float":
		num, err := renderNumber(n)
		if err != nil {
			return nil, err
		}
		return cvNumber(num), nil
	case "!!binary":
		// Explicit !!binary tags are rejected earlier (explicit tags are
		// disallowed), so this path is defense in depth, not reachable
		// from a hardened node; kept exhaustive to avoid a silent
		// fallthrough-to-string on an unexpected tag.
		if _, err := base64.StdEncoding.DecodeString(n.Value); err != nil {
			return nil, fmt.Errorf("%w: invalid !!binary scalar", ErrJSONConvert)
		}
		return cvString(n.Value), nil
	default:
		return nil, fmt.Errorf("%w: unsupported scalar tag %q", ErrJSONConvert, n.Tag)
	}
}

// renderNumber returns the canonical JSON number text for a !!int/!!float
// scalar: the original text verbatim if it is already valid JSON number
// syntax, else an exact-precision re-rendering of yaml.v3's own resolved
// value (see jsonNumberLiteral's doc comment).
func renderNumber(n *yaml.Node) (string, error) {
	if jsonNumberLiteral.MatchString(n.Value) {
		return n.Value, nil
	}
	var v interface{}
	if err := n.Decode(&v); err != nil {
		return "", fmt.Errorf("%w: %w", ErrJSONConvert, err)
	}
	// yaml.v3's resolve() (resolve.go) returns Go `int` for any value
	// that fits in strconv.ParseInt's 64-bit range on a 64-bit int
	// platform (amd64/arm64, this project's only deployment targets per
	// architecture doc section 1.1's RHEL 9 scope): it only falls back
	// to a distinct int64 when int is narrower than 64 bits, which never
	// happens here, so no separate `case int64` is reachable.
	switch t := v.(type) {
	case int:
		return strconv.FormatInt(int64(t), 10), nil
	case uint64:
		return strconv.FormatUint(t, 10), nil
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), nil
	default:
		return "", fmt.Errorf("%w: scalar tagged %q decoded to unexpected Go type %T", ErrJSONConvert, n.Tag, v)
	}
}

// canonicalValue is the small closed set of value kinds canonical JSON
// rendering needs; it exists so number text can be carried verbatim
// instead of round-tripping through float64 (encoding/json's default
// number representation), which would violate "no float re-encoding".
type canonicalValue interface{ renderJSON(buf *bytes.Buffer) }

type cvObject map[string]canonicalValue
type cvArray []canonicalValue
type cvString string
type cvNumber string // pre-rendered, already-valid JSON number text
type cvBool bool
type cvNull struct{}

func (v cvObject) renderJSON(buf *bytes.Buffer) {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeJSONString(buf, k)
		buf.WriteByte(':')
		v[k].renderJSON(buf)
	}
	buf.WriteByte('}')
}

func (v cvArray) renderJSON(buf *bytes.Buffer) {
	buf.WriteByte('[')
	for i, e := range v {
		if i > 0 {
			buf.WriteByte(',')
		}
		e.renderJSON(buf)
	}
	buf.WriteByte(']')
}

func (v cvString) renderJSON(buf *bytes.Buffer) { writeJSONString(buf, string(v)) }
func (v cvNumber) renderJSON(buf *bytes.Buffer) { buf.WriteString(string(v)) }
func (v cvBool) renderJSON(buf *bytes.Buffer) {
	if v {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
}
func (cvNull) renderJSON(buf *bytes.Buffer) { buf.WriteString("null") }

// writeJSONString writes s as a JSON string literal using encoding/json's
// own escaping rules (via a throwaway Marshal), ensuring standards-correct
// escaping (including of U+2028/U+2029 and control characters) without
// reimplementing it.
func writeJSONString(buf *bytes.Buffer, s string) {
	// encoding/json.Marshal on a string can only fail for invalid UTF-8,
	// which parseHardenedYAML's checkRawBytes already rules out for the
	// whole document.
	b, _ := json.Marshal(s)
	buf.Write(b)
}

// canonicalJSON renders a yaml.Node tree (already hardened by
// parseHardenedYAML) to deterministic JSON bytes: sorted object keys, no
// insignificant whitespace, numbers preserved exactly as parsed (step 2
// prompt Part B5).
func canonicalJSON(root *yaml.Node) ([]byte, error) {
	cv, err := toCanonicalValue(root)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	cv.renderJSON(&buf)
	return buf.Bytes(), nil
}
