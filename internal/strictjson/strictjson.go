package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// frame tracks one open JSON object or array while walking tokens.
type frame struct {
	array       bool
	keys        map[string]struct{}
	awaitingKey bool // only meaningful when !array
}

// CheckNoDuplicateKeys walks data token-by-token and returns an error if any
// JSON object contains a duplicate key at any nesting depth, or if nesting
// exceeds maxDepth. It does not itself validate that data is otherwise
// well-formed JSON beyond what is needed to walk it; callers must still run
// a full decode.
func CheckNoDuplicateKeys(data []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var stack []*frame
	top := func() *frame {
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	consumeValue := func() {
		if f := top(); f != nil && !f.array {
			f.awaitingKey = true
		}
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
				stack = append(stack, &frame{array: false, keys: make(map[string]struct{}), awaitingKey: true})
				started = true
			case '[':
				if len(stack)+1 > maxDepth {
					return ErrMaxDepthExceeded
				}
				stack = append(stack, &frame{array: true})
				started = true
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("strictjson: unbalanced %q", t)
				}
				stack = stack[:len(stack)-1]
				consumeValue()
			}
		case string:
			f := top()
			if f != nil && !f.array && f.awaitingKey {
				if _, dup := f.keys[t]; dup {
					return fmt.Errorf("%w: %q", ErrDuplicateKey, t)
				}
				f.keys[t] = struct{}{}
				f.awaitingKey = false
			} else {
				consumeValue()
				started = true
			}
		default:
			// number, bool, nil
			consumeValue()
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

// DecodeStrict decodes data into v, enforcing every rule required by
// architecture doc section 7.4 step 5:
//   - input must be valid UTF-8
//   - no duplicate object keys at any depth
//   - nesting depth <= maxDepth
//   - no unknown fields relative to v's JSON tags
//   - exactly one top-level JSON value, no trailing data
//
// v must be a pointer, as with json.Unmarshal.
func DecodeStrict(data []byte, maxDepth int, v interface{}) error {
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}
	if err := CheckNoDuplicateKeys(data, maxDepth); err != nil {
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
	if rest := bytes.TrimSpace(data[dec.InputOffset():]); len(rest) > 0 {
		return ErrTrailingData
	}
	return nil
}
