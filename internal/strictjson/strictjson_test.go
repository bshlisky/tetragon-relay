package strictjson

import (
	"errors"
	"testing"
)

type sample struct {
	A string `json:"a"`
	B int    `json:"b"`
}

func TestDecodeStrict_Valid(t *testing.T) {
	var s sample
	if err := DecodeStrict([]byte(`{"a":"x","b":1}`), 32, &s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.A != "x" || s.B != 1 {
		t.Fatalf("got %+v", s)
	}
}

func TestDecodeStrict_UnknownField(t *testing.T) {
	var s sample
	if err := DecodeStrict([]byte(`{"a":"x","b":1,"c":true}`), 32, &s); err == nil {
		t.Fatalf("expected error for unknown field")
	}
}

func TestDecodeStrict_DuplicateTopLevelKey(t *testing.T) {
	var s sample
	err := DecodeStrict([]byte(`{"a":"x","a":"y","b":1}`), 32, &s)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("err = %v, want ErrDuplicateKey", err)
	}
}

func TestDecodeStrict_DuplicateNestedKey(t *testing.T) {
	type outer struct {
		Inner sample `json:"inner"`
	}
	var o outer
	err := DecodeStrict([]byte(`{"inner":{"a":"x","a":"y","b":1}}`), 32, &o)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("err = %v, want ErrDuplicateKey", err)
	}
}

func TestDecodeStrict_DuplicateKeyInArrayOfObjects(t *testing.T) {
	type outer struct {
		Items []sample `json:"items"`
	}
	var o outer
	err := DecodeStrict([]byte(`{"items":[{"a":"x","b":1},{"a":"y","a":"z","b":2}]}`), 32, &o)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("err = %v, want ErrDuplicateKey", err)
	}
}

func TestDecodeStrict_MaxDepthExceeded(t *testing.T) {
	// Build a deeply nested array: [[[[...]]]]
	deep := ""
	for i := 0; i < 40; i++ {
		deep += "["
	}
	for i := 0; i < 40; i++ {
		deep += "]"
	}
	var v interface{}
	err := DecodeStrict([]byte(deep), 32, &v)
	if !errors.Is(err, ErrMaxDepthExceeded) {
		t.Fatalf("err = %v, want ErrMaxDepthExceeded", err)
	}
}

func TestDecodeStrict_WithinDepthLimit(t *testing.T) {
	shallow := ""
	for i := 0; i < 10; i++ {
		shallow += "["
	}
	shallow += "1"
	for i := 0; i < 10; i++ {
		shallow += "]"
	}
	var v interface{}
	if err := DecodeStrict([]byte(shallow), 32, &v); err != nil {
		t.Fatalf("unexpected error within depth limit: %v", err)
	}
}

func TestDecodeStrict_TrailingData(t *testing.T) {
	var s sample
	err := DecodeStrict([]byte(`{"a":"x","b":1} garbage`), 32, &s)
	if !errors.Is(err, ErrTrailingData) {
		t.Fatalf("err = %v, want ErrTrailingData", err)
	}
}

func TestDecodeStrict_InvalidUTF8(t *testing.T) {
	var s sample
	bad := []byte{'{', '"', 'a', '"', ':', '"', 0xff, 0xfe, '"', ',', '"', 'b', '"', ':', '1', '}'}
	err := DecodeStrict(bad, 32, &s)
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("err = %v, want ErrInvalidUTF8", err)
	}
}

func TestDecodeStrict_NotSingleValue(t *testing.T) {
	var s sample
	err := DecodeStrict([]byte(``), 32, &s)
	if err == nil {
		t.Fatalf("expected error for empty input")
	}
}

func TestDecodeStrict_NeverPanics(t *testing.T) {
	inputs := []string{
		``, `{`, `}`, `[`, `]`, `{"a":}`, `{"a":"b",}`, `null`, `true`, `1`,
		`"just a string"`, `{{{{`, `[[[[`, "\x00\x01\x02", `{"a":[1,2,{"b":[3,[4,[5]]]}]}`,
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on input %q: %v", in, r)
				}
			}()
			var v interface{}
			_ = DecodeStrict([]byte(in), 32, &v)
		}()
	}
}
