package dsse

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

func TestParseEnvelope_TooLarge(t *testing.T) {
	data := make([]byte, 101)
	_, err := ParseEnvelope(data, 100, 32)
	if !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Fatalf("err = %v, want ErrEnvelopeTooLarge", err)
	}
}

func TestParseEnvelope_MissingFields(t *testing.T) {
	cases := []string{
		`{}`,
		`{"payloadType":"t"}`,
		`{"payload":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `"}`,
		`{"payloadType":"t","payload":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `","signatures":[]}`,
	}
	for _, c := range cases {
		if _, err := ParseEnvelope([]byte(c), 1<<20, 32); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestParseEnvelope_BadBase64(t *testing.T) {
	data := []byte(`{"payloadType":"t","payload":"not-base64!!","signatures":[{"keyid":"k","sig":"AA=="}]}`)
	_, err := ParseEnvelope(data, 1<<20, 32)
	if !errors.Is(err, ErrInvalidBase64) {
		t.Fatalf("err = %v, want ErrInvalidBase64", err)
	}
}

func TestParseEnvelope_NonCanonicalBase64Rejected(t *testing.T) {
	// One bit of padding set that standard strict base64 rejects.
	data := []byte(`{"payloadType":"t","payload":"AB==","signatures":[{"keyid":"k","sig":"AA=="}]}`)
	if _, err := ParseEnvelope(data, 1<<20, 32); err == nil {
		t.Fatalf("expected non-canonical base64 to be rejected")
	}
}

func TestParseEnvelope_SignatureMissingKeyID(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	data := []byte(`{"payloadType":"t","payload":"` + payload + `","signatures":[{"keyid":"","sig":"AA=="}]}`)
	_, err := ParseEnvelope(data, 1<<20, 32)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("err = %v, want ErrInvalidEnvelope", err)
	}
}

func TestParseEnvelope_SignatureBadBase64(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	data := []byte(`{"payloadType":"t","payload":"` + payload + `","signatures":[{"keyid":"k1","sig":"not-base64!!"}]}`)
	_, err := ParseEnvelope(data, 1<<20, 32)
	if !errors.Is(err, ErrInvalidBase64) {
		t.Fatalf("err = %v, want ErrInvalidBase64", err)
	}
}

func TestParseEnvelope_Valid(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	data := []byte(`{"payloadType":"t","payload":"` + payload + `","signatures":[{"keyid":"k1","sig":"AA=="}]}`)
	env, err := ParseEnvelope(data, 1<<20, 32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.PayloadType != "t" {
		t.Errorf("PayloadType = %q", env.PayloadType)
	}
	if string(env.Payload) != `{"a":1}` {
		t.Errorf("Payload = %q", env.Payload)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != "k1" {
		t.Errorf("Signatures = %+v", env.Signatures)
	}
}

func makeSigEntries(n int, distinctKeys bool) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		kid := "k1"
		if distinctKeys {
			kid = fmt.Sprintf("k%d", i)
		}
		parts = append(parts, fmt.Sprintf(`{"keyid":%q,"sig":"AA=="}`, kid))
	}
	return strings.Join(parts, ",")
}

// TestParseEnvelope_TooManySignatures is the step 1 review's A4 hardening:
// an envelope may carry at most limits.MaxSignaturesPerEnvelope signatures.
func TestParseEnvelope_TooManySignatures(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	sigs := makeSigEntries(limits.MaxSignaturesPerEnvelope+1, true)
	data := []byte(`{"payloadType":"t","payload":"` + payload + `","signatures":[` + sigs + `]}`)
	_, err := ParseEnvelope(data, 1<<20, 32)
	if !errors.Is(err, ErrTooManySignatures) {
		t.Fatalf("err = %v, want ErrTooManySignatures", err)
	}
}

func TestParseEnvelope_ExactlyMaxSignaturesAccepted(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	sigs := makeSigEntries(limits.MaxSignaturesPerEnvelope, true)
	data := []byte(`{"payloadType":"t","payload":"` + payload + `","signatures":[` + sigs + `]}`)
	env, err := ParseEnvelope(data, 1<<20, 32)
	if err != nil {
		t.Fatalf("unexpected error at the exact limit: %v", err)
	}
	if len(env.Signatures) != limits.MaxSignaturesPerEnvelope {
		t.Fatalf("len(Signatures) = %d, want %d", len(env.Signatures), limits.MaxSignaturesPerEnvelope)
	}
}

// TestParseEnvelope_DuplicateSignatureKeyID is the step 1 review's A4
// hardening: two signatures sharing the same keyid are never legitimate and
// must reject the whole envelope, not be silently deduplicated.
func TestParseEnvelope_DuplicateSignatureKeyID(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	sigs := makeSigEntries(2, false) // both keyid "k1"
	data := []byte(`{"payloadType":"t","payload":"` + payload + `","signatures":[` + sigs + `]}`)
	_, err := ParseEnvelope(data, 1<<20, 32)
	if !errors.Is(err, ErrDuplicateSignatureKeyID) {
		t.Fatalf("err = %v, want ErrDuplicateSignatureKeyID", err)
	}
}

func TestParseEnvelope_NeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil, {}, []byte("{"), []byte("not json"), []byte(`{"payloadType":1}`),
		[]byte(`{"signatures":"not an array"}`),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on input %q: %v", in, r)
				}
			}()
			_, _ = ParseEnvelope(in, 1<<20, 32)
		}()
	}
}
