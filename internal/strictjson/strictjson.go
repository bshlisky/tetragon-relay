package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// --- schema resolution: map a Go type governing a JSON value to the rules
// that apply to an object at that position. ---

type schemaKind int

const (
	// schemaUnknown means no target type is known at this position (e.g.
	// decoding into interface{}, or validateKeys was called with a nil
	// root type). Only duplicate/fold-collision checking applies; any key
	// is otherwise accepted.
	schemaUnknown schemaKind = iota
	// schemaStruct means object keys must exactly (case-sensitively)
	// match one of the struct's JSON field names.
	schemaStruct
	// schemaMap means any string key is accepted (it becomes a map key),
	// but duplicate/fold-collision checking still applies.
	schemaMap
)

type schemaCtx struct {
	kind   schemaKind
	fields map[string]reflect.Type // json field name -> field type; schemaStruct only
	elem   reflect.Type            // map value type; schemaMap only
}

var timeType = reflect.TypeOf(time.Time{})

// deref strips pointer indirection.
func deref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// sliceElemType returns t's element type if t (after deref) is a slice or
// array, else nil.
func sliceElemType(t reflect.Type) reflect.Type {
	t = deref(t)
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		return t.Elem()
	}
	return nil
}

// structFields returns the JSON field name -> Go type mapping for an
// exported struct field set, honoring `json:"name"` tags the same way
// encoding/json does (first comma-separated segment, "-" meaning skipped,
// empty meaning use the Go field name).
func structFields(t reflect.Type) map[string]reflect.Type {
	out := make(map[string]reflect.Type, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		name := f.Name
		if tag := f.Tag.Get("json"); tag != "" {
			parts := strings.SplitN(tag, ",", 2)
			if parts[0] == "-" && len(parts) == 1 {
				continue
			}
			if parts[0] != "" {
				name = parts[0]
			}
		}
		out[name] = f.Type
	}
	return out
}

// resolveSchema determines the schema that governs a JSON *object* value of
// Go type t. Passing nil means "unknown"; non-struct, non-map types (and
// time.Time, which unmarshals from a JSON string, not an object) also
// resolve to schemaUnknown, since they are never the direct Go type of an
// object's contents in this package's usage.
func resolveSchema(t reflect.Type) schemaCtx {
	t = deref(t)
	if t == nil {
		return schemaCtx{kind: schemaUnknown}
	}
	switch t.Kind() { //nolint:exhaustive // every Kind other than Struct/Map is intentionally schemaUnknown via default
	case reflect.Struct:
		if t == timeType {
			return schemaCtx{kind: schemaUnknown}
		}
		return schemaCtx{kind: schemaStruct, fields: structFields(t)}
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return schemaCtx{kind: schemaUnknown}
		}
		return schemaCtx{kind: schemaMap, elem: t.Elem()}
	default:
		return schemaCtx{kind: schemaUnknown}
	}
}

// frame tracks one open JSON object or array while walking tokens, together
// with enough Go-type information to validate the next nested value.
type frame struct {
	array bool

	// object frames
	schema      schemaCtx
	seenKeys    []string
	awaitingKey bool
	pendingType reflect.Type // Go type of the value for the most recently read key

	// array frames
	elemType reflect.Type
}

func consumeValue(stack []*frame) {
	if len(stack) == 0 {
		return
	}
	if f := stack[len(stack)-1]; !f.array {
		f.awaitingKey = true
	}
}

// validateKeys walks data token-by-token and enforces, for every JSON
// object encountered:
//
//   - no two keys are equal under Unicode simple case folding
//     (strings.EqualFold); this also catches plain exact duplicates, and
//     catches cases encoding/json's own case-insensitive field matching
//     would otherwise paper over (e.g. "scope" and "SCOPE", or "keyid" and
//     the Kelvin sign form "\u212Aeyid")
//   - if rootType (or the Go type governing a nested position, derived from
//     rootType's struct/map field types) resolves to a struct, every key in
//     an object at that position must exactly, case-sensitively match one
//     of that struct's JSON field names; map-governed objects accept any
//     key (still fold-checked); unknown-governed positions (including a nil
//     rootType) accept any key
//   - nesting depth <= maxDepth
//
// Pass rootType = nil to perform only duplicate/fold-collision and depth
// checking with no knowledge of a target Go type (used by
// CheckNoDuplicateKeys).
func validateKeys(data []byte, maxDepth int, rootType reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var stack []*frame
	top := func() *frame {
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	// childType returns the Go type governing the value about to be
	// opened (object or array), based on the current top frame: the
	// pending key's type if inside an object, the element type if inside
	// an array, or rootType if this is the outermost value.
	childType := func() reflect.Type {
		p := top()
		if p == nil {
			return rootType
		}
		if p.array {
			return p.elemType
		}
		return p.pendingType
	}

	started := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("strictjson: tokenize: %w", err)
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if len(stack)+1 > maxDepth {
					return ErrMaxDepthExceeded
				}
				stack = append(stack, &frame{array: false, schema: resolveSchema(childType()), awaitingKey: true})
				started = true
			case '[':
				if len(stack)+1 > maxDepth {
					return ErrMaxDepthExceeded
				}
				stack = append(stack, &frame{array: true, elemType: sliceElemType(childType())})
				started = true
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("strictjson: unbalanced %q", t)
				}
				stack = stack[:len(stack)-1]
				consumeValue(stack)
			}
		case string:
			f := top()
			if f != nil && !f.array && f.awaitingKey {
				for _, seen := range f.seenKeys {
					if strings.EqualFold(seen, t) {
						return fmt.Errorf("%w: %q", ErrDuplicateKey, t)
					}
				}
				f.seenKeys = append(f.seenKeys, t)
				f.awaitingKey = false
				switch f.schema.kind { //nolint:exhaustive // schemaUnknown is the intentional default (no field enforcement)
				case schemaStruct:
					typ, ok := f.schema.fields[t]
					if !ok {
						return fmt.Errorf("%w: %q", ErrUnknownField, t)
					}
					f.pendingType = typ
				case schemaMap:
					f.pendingType = f.schema.elem
				default:
					f.pendingType = nil
				}
			} else {
				consumeValue(stack)
				started = true
			}
		default:
			// number, bool, nil
			consumeValue(stack)
			started = true
		}
		// Stop as soon as exactly one top-level JSON value has been
		// fully consumed. Anything after it is trailing data, which
		// DecodeStrict's separate pass (using encoding/json.Decoder
		// directly) detects; this pre-pass must not choke on trailing
		// garbage that isn't valid JSON at all.
		if started && len(stack) == 0 {
			break
		}
	}
	return nil
}

// CheckNoDuplicateKeys walks data token-by-token and returns an error if any
// JSON object contains two keys that are equal under Unicode simple case
// folding (architecture note: this also catches plain exact duplicates), or
// if nesting exceeds maxDepth. It has no knowledge of any target Go type;
// use DecodeStrict for exact-field-name enforcement against a struct.
func CheckNoDuplicateKeys(data []byte, maxDepth int) error {
	return validateKeys(data, maxDepth, nil)
}

// DecodeStrict decodes data into v, enforcing every rule required by
// architecture doc section 7.4 step 5 plus the hardening from the step 1
// review (A1):
//   - input must be valid UTF-8
//   - no two object keys at any depth are equal under Unicode simple case
//     folding, not just exact string equality
//   - every object key backed by a struct field in v's type must exactly,
//     case-sensitively match a JSON field name of that struct; map-backed
//     objects accept any key
//   - nesting depth <= maxDepth
//   - exactly one top-level JSON value, no trailing data
//
// v must be a pointer, as with json.Unmarshal.
func DecodeStrict(data []byte, maxDepth int, v interface{}) error {
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}
	if err := validateKeys(data, maxDepth, reflect.TypeOf(v)); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if err == io.EOF {
			return ErrNotSingleValue
		}
		return fmt.Errorf("strictjson: decode: %w", err)
	}
	// Reject trailing data. Using InputOffset and checking the remainder
	// for non-whitespace avoids re-tokenizing it, which could itself be
	// malformed (e.g. "{} garbage") and would otherwise surface as a
	// confusing syntax error instead of ErrTrailingData.
	//
	// trimJSONSpace, not bytes.TrimSpace, is used deliberately:
	// bytes.TrimSpace strips the full Unicode White_Space set (e.g. '\v',
	// '\f', U+00A0), but RFC 8259 defines JSON insignificant whitespace as
	// only space, tab, CR and LF. A fuzz-discovered input ("0\v") showed
	// bytes.TrimSpace would treat a trailing '\v' as insignificant and
	// accept the document, while encoding/json's own tokenizer (correctly,
	// per the RFC) treats '\v' as an invalid character. Accepting it here
	// would make this package's notion of "no trailing data" looser than
	// the JSON spec itself.
	if rest := trimJSONSpace(data[dec.InputOffset():]); len(rest) > 0 {
		return ErrTrailingData
	}
	return nil
}

// trimJSONSpace trims only the four bytes RFC 8259 defines as insignificant
// whitespace: space, tab, line feed, carriage return.
func trimJSONSpace(b []byte) []byte {
	isJSONSpace := func(c byte) bool {
		return c == ' ' || c == '\t' || c == '\n' || c == '\r'
	}
	start := 0
	for start < len(b) && isJSONSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isJSONSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}
