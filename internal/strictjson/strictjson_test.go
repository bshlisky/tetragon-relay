package strictjson

import (
	"errors"
	"testing"
	"time"
)

type sample struct {
	A string `json:"a"`
	B int    `json:"b"`
}

type scopeKeyid struct {
	Scope string `json:"scope"`
	KeyID string `json:"keyid"`
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

// TestDecodeStrict_TrailingNonJSONWhitespaceRejected is a regression for a
// bug FuzzDecodeStrictKeySetRoundTrip found: bytes.TrimSpace trims the full
// Unicode White_Space set (vertical tab, form feed, NBSP, ...), but RFC 8259
// defines JSON insignificant whitespace as only space/tab/CR/LF. A trailing
// '\v' (or similar) after a complete value is not valid JSON and must be
// rejected, not silently trimmed away as if it were whitespace.
func TestDecodeStrict_TrailingNonJSONWhitespaceRejected(t *testing.T) {
	var v interface{}
	cases := []string{"0\v", "0\f", "0\u00a0", "{}\v"}
	for _, data := range cases {
		if err := DecodeStrict([]byte(data), 32, &v); err == nil {
			t.Errorf("DecodeStrict(%q) accepted trailing non-JSON whitespace", data)
		}
	}
}

func TestDecodeStrict_TrailingJSONWhitespaceAccepted(t *testing.T) {
	var v interface{}
	cases := []string{"0 ", "0\t", "0\n", "0\r", "0 \t\r\n", "{} \n"}
	for _, data := range cases {
		if err := DecodeStrict([]byte(data), 32, &v); err != nil {
			t.Errorf("DecodeStrict(%q) rejected valid trailing JSON whitespace: %v", data, err)
		}
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

// TestDecodeStrict_CaseAndUnicodeFoldCollisions is the step 1 review's A1
// regression: encoding/json's own field matching is case-insensitive
// (including Unicode simple case folding), so a naive duplicate-key check
// that compares keys for exact string equality would let
// {"scope":"dev","SCOPE":"prod-db"} through, silently decoding to
// "prod-db". DecodeStrict must reject all of these.
func TestDecodeStrict_CaseAndUnicodeFoldCollisions(t *testing.T) {
	cases := map[string]string{
		"exact duplicate":                 `{"scope":"dev","scope":"prod-db","keyid":"k"}`,
		"different case: SCOPE":           `{"scope":"dev","SCOPE":"prod-db","keyid":"k"}`,
		"different case: Scope":           `{"scope":"dev","Scope":"prod-db","keyid":"k"}`,
		"Unicode fold: long s (ſcope)":    "{\"scope\":\"dev\",\"\u017Fcope\":\"prod-db\",\"keyid\":\"k\"}",
		"Unicode fold: Kelvin sign keyid": "{\"scope\":\"dev\",\"keyid\":\"k\",\"\u212Aeyid\":\"k2\"}",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var v scopeKeyid
			err := DecodeStrict([]byte(data), 32, &v)
			if !errors.Is(err, ErrDuplicateKey) {
				t.Fatalf("err = %v, want ErrDuplicateKey", err)
			}
		})
	}
}

// TestDecodeStrict_UnknownFieldIsCaseSensitive is the other half of A1: a
// key that differs only in case from a real field name must not be
// silently accepted as that field (which encoding/json's own matching would
// do); it must be rejected as an unknown field, not decoded at all.
func TestDecodeStrict_UnknownFieldIsCaseSensitive(t *testing.T) {
	cases := []string{
		`{"payloadtype":"x"}`,
		`{"PayloadType":"x"}`,
		`{"PAYLOADTYPE":"x"}`,
	}
	type payloadTypeOnly struct {
		PayloadType string `json:"payloadType"`
	}
	for _, data := range cases {
		var v payloadTypeOnly
		err := DecodeStrict([]byte(data), 32, &v)
		if !errors.Is(err, ErrUnknownField) {
			t.Errorf("DecodeStrict(%q) err = %v, want ErrUnknownField", data, err)
		}
	}
}

func TestDecodeStrict_MapFieldAcceptsAnyKeyButStillFoldChecked(t *testing.T) {
	type withMap struct {
		Keys map[string]int `json:"keys"`
	}
	var v withMap
	if err := DecodeStrict([]byte(`{"keys":{"anything-goes":1,"so-does-this":2}}`), 32, &v); err != nil {
		t.Fatalf("unexpected error for arbitrary map keys: %v", err)
	}
	if v.Keys["anything-goes"] != 1 || v.Keys["so-does-this"] != 2 {
		t.Fatalf("got %+v", v.Keys)
	}

	err := DecodeStrict([]byte(`{"keys":{"dup":1,"DUP":2}}`), 32, &v)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("err = %v, want ErrDuplicateKey for case-fold-colliding map keys", err)
	}
}

func TestDecodeStrict_TimeTimeFieldSchemaUnknown(t *testing.T) {
	type withTime struct {
		When time.Time `json:"when"`
	}
	// An attacker-supplied object where a time.Time value is expected:
	// resolveSchema(time.Time) must resolve to schemaUnknown (no field
	// enforcement), not panic or mis-structure. The real decode will then
	// fail with its own type error, which DecodeStrict surfaces normally.
	var v withTime
	if err := DecodeStrict([]byte(`{"when":{"nested":"object"}}`), 32, &v); err == nil {
		t.Fatalf("expected a decode error when an object is given for a time.Time field")
	}
}

func TestDecodeStrict_NonStringMapKeySchemaUnknown(t *testing.T) {
	type withIntMap struct {
		M map[int]string `json:"m"`
	}
	var v withIntMap
	// JSON object keys are always strings on the wire; a map[int]string
	// field's nested object keys are accepted (schemaUnknown: no field
	// enforcement possible for a non-string-keyed map), and encoding/json
	// itself converts "1" -> 1.
	if err := DecodeStrict([]byte(`{"m":{"1":"a","2":"b"}}`), 32, &v); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.M[1] != "a" || v.M[2] != "b" {
		t.Fatalf("got %+v", v.M)
	}
}

func TestDecodeStrict_StructFieldTagVariants(t *testing.T) {
	type tagged struct {
		NoTag      string `json:""`
		Skipped    string `json:"-"`
		unexported string //nolint:unused // exercising unexported-field skipping
		WithOpts   string `json:"with_opts,omitempty"`
	}
	_ = tagged{}.unexported
	var v tagged
	// "NoTag" has an empty tag, so its JSON name is the Go field name.
	// "Skipped" is tagged "-" and must not be settable via JSON at all,
	// even under its own Go field name.
	if err := DecodeStrict([]byte(`{"NoTag":"x","with_opts":"y"}`), 32, &v); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.NoTag != "x" || v.WithOpts != "y" {
		t.Fatalf("got %+v", v)
	}

	if err := DecodeStrict([]byte(`{"Skipped":"x"}`), 32, &v); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("err = %v, want ErrUnknownField for a field tagged json:\"-\"", err)
	}
}

func TestTrimJSONSpace(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"\t\r\n", ""},
		{"  x  ", "x"},
		{"\vx\v", "\vx\v"}, // vertical tab is NOT JSON whitespace
	}
	for _, c := range cases {
		if got := string(trimJSONSpace([]byte(c.in))); got != c.want {
			t.Errorf("trimJSONSpace(%q) = %q, want %q", c.in, got, c.want)
		}
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
