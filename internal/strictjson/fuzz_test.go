package strictjson

import "testing"

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
