package strictjson

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

// FuzzStrictJSON asserts that DecodeStrict never panics on any input, for
// any maxDepth in a small realistic range, regardless of how malformed the
// input is.
func FuzzStrictJSON(f *testing.F) {
	seeds := []string{
		``,
		`{}`,
		`[]`,
		`null`,
		`{"a":"b"}`,
		`{"a":"b","a":"c"}`,
		`{"a":{"b":{"c":{"b":1}}}}`,
		`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]`,
		`{"a": 1,} trailing`,
		"\xff\xfe\x00invalid utf8",
		`{"a":"unterminated`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeStrict panicked on %q: %v", data, r)
			}
		}()
		var v interface{}
		_ = DecodeStrict(data, 32, &v)

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CheckNoDuplicateKeys panicked on %q: %v", data, r)
			}
		}()
		_ = CheckNoDuplicateKeys(data, 32)
	})
}

// collectAllKeys walks well-formed JSON (independent of validateKeys, to
// keep this a genuinely separate check) and returns the set of every string
// that appeared in an object key position, anywhere in the document.
func collectAllKeys(data []byte) (map[string]struct{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	keys := make(map[string]struct{})

	type level struct {
		array       bool
		awaitingKey bool
	}
	var stack []level
	top := func() *level {
		if len(stack) == 0 {
			return nil
		}
		return &stack[len(stack)-1]
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, level{array: false, awaitingKey: true})
			case '[':
				stack = append(stack, level{array: true})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				if l := top(); l != nil && !l.array {
					l.awaitingKey = true
				}
			}
		case string:
			l := top()
			if l != nil && !l.array && l.awaitingKey {
				keys[t] = struct{}{}
				l.awaitingKey = false
			} else if l != nil && !l.array {
				l.awaitingKey = true
			}
		default:
			if l := top(); l != nil && !l.array {
				l.awaitingKey = true
			}
		}
	}
	return keys, nil
}

func equalKeySets(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// FuzzDecodeStrictKeySetRoundTrip is the step 1 review's A1 property:
// whenever DecodeStrict accepts an input, decoding it into a fully generic
// value (so no struct field can be dropped or defaulted) and re-marshaling
// it must reproduce exactly the same set of object keys the input had,
// anywhere in the document. A mismatch would mean DecodeStrict silently
// accepted a structure it then represented differently than what was
// signed/hashed.
func FuzzDecodeStrictKeySetRoundTrip(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"a":1}`,
		`{"a":{"b":2}}`,
		`{"a":[{"b":1},{"c":2}]}`,
		`[1,2,3]`,
		`"just a string"`,
		`null`,
		`{"a":"b","c":{"d":"e","f":[{"g":1}]}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var v interface{}
		if err := DecodeStrict(data, 32, &v); err != nil {
			return
		}
		remarshaled, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("re-marshal failed after successful decode: %v", err)
		}
		origKeys, err := collectAllKeys(data)
		if err != nil {
			t.Fatalf("collectAllKeys(original) failed after DecodeStrict accepted it: %v", err)
		}
		newKeys, err := collectAllKeys(remarshaled)
		if err != nil {
			t.Fatalf("collectAllKeys(remarshaled) failed: %v", err)
		}
		if !equalKeySets(origKeys, newKeys) {
			t.Fatalf("key set changed across decode+remarshal: orig=%v new=%v", origKeys, newKeys)
		}
	})
}
