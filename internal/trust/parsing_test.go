package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/trust"
)

func TestRoot_TargetsVerifier_VerifyAndRequireLogProof(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	env, _, targetsKey, _ := standardRoot(t, 1, now.Add(24*time.Hour))
	root, err := trust.LoadInitialRoot(env)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	tv, err := root.TargetsVerifier(now)
	if err != nil {
		t.Fatalf("TargetsVerifier: %v", err)
	}
	if tv.RequireLogProof() {
		t.Fatalf("RequireLogProof() = true, want false")
	}

	payload := []byte(`{"hello":"world"}`)
	validEnvBytes := signEnvelope("application/vnd.relay.policybundle.v1+json", payload, targetsKey)
	parsedEnv, err := parseEnvForTest(validEnvBytes)
	if err != nil {
		t.Fatalf("parse test envelope: %v", err)
	}
	if err := tv.Verify(parsedEnv); err != nil {
		t.Fatalf("Verify of a correctly-signed envelope failed: %v", err)
	}

	stray := mustKey(t)
	strayEnvBytes := signEnvelope("application/vnd.relay.policybundle.v1+json", payload, stray)
	strayEnv, err := parseEnvForTest(strayEnvBytes)
	if err != nil {
		t.Fatalf("parse test envelope: %v", err)
	}
	if err := tv.Verify(strayEnv); !errors.Is(err, trust.ErrThresholdNotMet) {
		t.Fatalf("Verify with an untrusted key: err = %v, want ErrThresholdNotMet", err)
	}
}

func TestDeriveKeyID_Errors(t *testing.T) {
	if _, err := trust.DeriveKeyID(nil); !errors.Is(err, trust.ErrUnsupportedKeyType) {
		t.Fatalf("err = %v, want ErrUnsupportedKeyType", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	if _, err := trust.DeriveKeyID(&p256.PublicKey); !errors.Is(err, trust.ErrUnsupportedKeyType) {
		t.Fatalf("err = %v, want ErrUnsupportedKeyType", err)
	}
}

func TestLoadInitialRoot_MalformedPayloads(t *testing.T) {
	r1, r2 := mustKey(t), mustKey(t)

	cases := map[string]string{
		"not json at all": `not json`,
		"wrong schema":    `{"schema":"wrong","version":1,"expires":"2027-01-01T00:00:00Z","keys":{},"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`,
		"zero version":    `{"schema":"relay.root.v1","version":0,"expires":"2027-01-01T00:00:00Z","keys":{},"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`,
		"missing expires": `{"schema":"relay.root.v1","version":1,"keys":{},"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`,
		"no keys":         `{"schema":"relay.root.v1","version":1,"expires":"2027-01-01T00:00:00Z","keys":{},"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			env := signEnvelope(trust.RootPayloadType, []byte(payload), r1, r2)
			if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrMalformedMetadata) {
				t.Fatalf("err = %v, want ErrMalformedMetadata", err)
			}
		})
	}
}

func TestLoadInitialRoot_KeyIDMismatch(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	tk := mustKey(t)
	all := []*genKey{r1, r2, tk}
	payload := buildRootPayload(1, now.Add(24*time.Hour), all, roleOf([]*genKey{r1, r2}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{tk}, 1))
	// Corrupt: relabel tk's map key to something else, so declared != derived.
	bad := mapKeyRename(t, payload, tk.id, "sha256:"+hashLike())
	env := signEnvelope(trust.RootPayloadType, bad, r1, r2)
	if _, err := trust.LoadInitialRoot(env); err == nil {
		t.Fatalf("expected an error for a relabeled key id")
	}
}

func TestLoadInitialRoot_KeyBadBase64(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	payload := `{"schema":"relay.root.v1","version":1,"expires":"` + now.Add(24*time.Hour).Format(time.RFC3339) +
		`","keys":{"sha256:deadbeef":{"keytype":"ecdsa-p384","public_key_der_b64":"not-base64!!"}},` +
		`"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`
	env := signEnvelope(trust.RootPayloadType, []byte(payload), r1, r2)
	if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrMalformedMetadata) {
		t.Fatalf("err = %v, want ErrMalformedMetadata", err)
	}
}

// TestLoadInitialRoot_DuplicateSignatureSameKey covers the step 1 review's
// A4 hardening: dsse.ParseEnvelope itself now rejects an envelope with two
// signatures sharing the same keyid (never legitimate), so this fails at
// envelope parsing (ErrMalformedMetadata wrapping dsse's duplicate-keyid
// error) rather than reaching threshold counting at all. The
// "two distinct keys required for threshold 2" property is covered
// separately by TestLoadInitialRoot_ThresholdNotMet and the
// threshold_not_met / duplicate_signature_same_key_threshold2 vectors.
func TestLoadInitialRoot_DuplicateSignatureSameKey(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	tk := mustKey(t)
	payload := buildRootPayload(1, now.Add(24*time.Hour), []*genKey{r1, r2, tk},
		roleOf([]*genKey{r1, r2}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{tk}, 1))
	// Signed twice by the SAME key (r1).
	env := signEnvelope(trust.RootPayloadType, payload, r1, r1)
	if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrMalformedMetadata) {
		t.Fatalf("err = %v, want ErrMalformedMetadata (envelope-level duplicate keyid)", err)
	}
}

// TestRoot_Update_CandidatePayloadInvalid covers Update's own
// parseAndValidatePayload error path (distinct from a malformed envelope or
// wrong payloadType, which have their own tests): the envelope parses fine,
// but the payload inside fails validation (here: invalid role definition).
func TestRoot_Update_CandidatePayloadInvalid(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	env, rootKeys, _, _ := standardRoot(t, 1, now.Add(24*time.Hour))
	root, err := trust.LoadInitialRoot(env)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}

	newTk := mustKey(t)
	payload := buildRootPayload(2, now.Add(48*time.Hour), []*genKey{rootKeys[0], rootKeys[1], rootKeys[2], newTk},
		roleOf(rootKeys, 2), roleOf([]*genKey{newTk}, 0) /* invalid: threshold 0 */, roleOf([]*genKey{newTk}, 1))
	newEnv := signEnvelope(trust.RootPayloadType, payload, rootKeys[0], rootKeys[1])

	if _, err := root.Update(newEnv, now); !errors.Is(err, trust.ErrInvalidRoleDefinition) {
		t.Fatalf("err = %v, want ErrInvalidRoleDefinition", err)
	}
}

func TestRoot_Update_MalformedAndWrongPayloadType(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	env, _, _, _ := standardRoot(t, 1, now.Add(24*time.Hour))
	root, err := trust.LoadInitialRoot(env)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}

	if _, err := root.Update([]byte("not an envelope"), now); !errors.Is(err, trust.ErrMalformedMetadata) {
		t.Fatalf("err = %v, want ErrMalformedMetadata", err)
	}

	r1, r2 := mustKey(t), mustKey(t)
	tk := mustKey(t)
	payload := buildRootPayload(2, now.Add(48*time.Hour), []*genKey{r1, r2, tk},
		roleOf([]*genKey{r1, r2}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{tk}, 1))
	wrongType := signEnvelope("application/vnd.wrong.type", payload, r1, r2)
	if _, err := root.Update(wrongType, now); !errors.Is(err, trust.ErrPayloadTypeMismatch) {
		t.Fatalf("err = %v, want ErrPayloadTypeMismatch", err)
	}
}

func TestLoadInitialRoot_UnknownKeyType(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	badDER := base64.StdEncoding.EncodeToString(mustMarshalP384Pub(t))
	payload := `{"schema":"relay.root.v1","version":1,"expires":"` + now.Add(24*time.Hour).Format(time.RFC3339) +
		`","keys":{"sha256:deadbeef":{"keytype":"ecdsa-p256","public_key_der_b64":"` + badDER + `"}},` +
		`"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`
	env := signEnvelope(trust.RootPayloadType, []byte(payload), r1, r2)
	if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrUnknownKeyType) {
		t.Fatalf("err = %v, want ErrUnknownKeyType", err)
	}
}

// TestLoadInitialRoot_DeclaredKeyTypeDoesNotMatchSPKI covers step 4 prompt
// Part B1: a key declared "ecdsa-p384" whose SPKI is genuinely P-384 DER
// but relabeled (e.g. actually some other OID) is malformed metadata, not
// silently accepted or silently rejected as "unsupported".
func TestLoadInitialRoot_DeclaredKeyTypeDoesNotMatchSPKI(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-256 key: %v", err)
	}
	badDER := base64.StdEncoding.EncodeToString(der)
	payload := `{"schema":"relay.root.v1","version":1,"expires":"` + now.Add(24*time.Hour).Format(time.RFC3339) +
		`","keys":{"sha256:deadbeef":{"keytype":"ecdsa-p384","public_key_der_b64":"` + badDER + `"}},` +
		`"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`
	env := signEnvelope(trust.RootPayloadType, []byte(payload), r1, r2)
	if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrKeytypeSPKIMismatch) {
		t.Fatalf("err = %v, want ErrKeytypeSPKIMismatch", err)
	}
}

// TestLoadInitialRoot_InvalidRequireKeyTypes covers step 4 prompt Part
// B3's require_keytypes validation (present-but-empty, an unknown keytype,
// a duplicate keytype, a keytype the role has no key of) plus
// step-04a-review.md R4A-1's "omitted entirely" case: require_keytypes is
// mandatory on every role, so an omitted field is malformed metadata too,
// not "no requirement".
func TestLoadInitialRoot_InvalidRequireKeyTypes(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	keysJSON := func() string {
		return `"` + r1.id + `":{"keytype":"ecdsa-p384","public_key_der_b64":"` + r1.publicB64() + `"},` +
			`"` + r2.id + `":{"keytype":"ecdsa-p384","public_key_der_b64":"` + r2.publicB64() + `"},` +
			`"` + tk.id + `":{"keytype":"ecdsa-p384","public_key_der_b64":"` + tk.publicB64() + `"},` +
			`"` + lk.id + `":{"keytype":"ecdsa-p384","public_key_der_b64":"` + lk.publicB64() + `"}`
	}
	// requireKeyTypesField is the targets role's "require_keytypes": ...
	// JSON fragment including the key, or "" to omit the field entirely
	// (R4A-1's case).
	cases := map[string]string{
		"omitted":           "",
		"present but empty": `,"require_keytypes":[]`,
		"unknown keytype":   `,"require_keytypes":["dilithium3"]`,
		"duplicate keytype": `,"require_keytypes":["ecdsa-p384","ecdsa-p384"]`,
		"type has no key":   `,"require_keytypes":["mldsa-87"]`,
	}
	for name, requireKeyTypesField := range cases {
		t.Run(name, func(t *testing.T) {
			payload := `{"schema":"relay.root.v1","version":1,"expires":"` + now.Add(24*time.Hour).Format(time.RFC3339) +
				`","keys":{` + keysJSON() + `},` +
				`"roles":{"root":{"keyids":["` + r1.id + `","` + r2.id + `"],"threshold":2,"require_keytypes":["ecdsa-p384"]},` +
				`"targets":{"keyids":["` + tk.id + `"],"threshold":1` + requireKeyTypesField + `},` +
				`"log":{"keyids":["` + lk.id + `"],"threshold":1,"require_keytypes":["ecdsa-p384"]}}}`
			env := signEnvelope(trust.RootPayloadType, []byte(payload), r1, r2)
			if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrInvalidRequireKeyTypes) {
				t.Fatalf("err = %v, want ErrInvalidRequireKeyTypes", err)
			}
		})
	}
}

// TestLoadInitialRoot_RequireKeyTypesOmittedOnRootOrLogRole covers R4A-1 for
// the root and log roles specifically (the table above only varies the
// targets role): omitting require_keytypes on root, or on log, with every
// other role valid, must also be rejected.
func TestLoadInitialRoot_RequireKeyTypesOmittedOnRootOrLogRole(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	all := []*genKey{r1, r2, tk, lk}

	t.Run("root role omits require_keytypes", func(t *testing.T) {
		payload := buildRootPayload(1, now.Add(24*time.Hour), all,
			roleOfOmittingKeyTypes([]*genKey{r1, r2}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
		env := signEnvelope(trust.RootPayloadType, payload, r1, r2)
		if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrInvalidRequireKeyTypes) {
			t.Fatalf("err = %v, want ErrInvalidRequireKeyTypes", err)
		}
	})

	t.Run("log role omits require_keytypes", func(t *testing.T) {
		payload := buildRootPayload(1, now.Add(24*time.Hour), all,
			roleOf([]*genKey{r1, r2}, 2), roleOf([]*genKey{tk}, 1), roleOfOmittingKeyTypes([]*genKey{lk}, 1))
		env := signEnvelope(trust.RootPayloadType, payload, r1, r2)
		if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrInvalidRequireKeyTypes) {
			t.Fatalf("err = %v, want ErrInvalidRequireKeyTypes", err)
		}
	})
}

func TestLoadInitialRoot_InvalidRootAndLogRoles(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	all := []*genKey{r1, r2, tk, lk}

	t.Run("invalid root role", func(t *testing.T) {
		payload := buildRootPayload(1, now.Add(24*time.Hour), all,
			wireRole{KeyIDs: []string{r1.id}, Threshold: 0}, roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
		env := signEnvelope(trust.RootPayloadType, payload, r1, r2)
		if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrInvalidRoleDefinition) {
			t.Fatalf("err = %v, want ErrInvalidRoleDefinition", err)
		}
	})

	t.Run("invalid log role", func(t *testing.T) {
		payload := buildRootPayload(1, now.Add(24*time.Hour), all,
			roleOf([]*genKey{r1, r2}, 2), roleOf([]*genKey{tk}, 1), wireRole{KeyIDs: []string{lk.id}, Threshold: 0})
		env := signEnvelope(trust.RootPayloadType, payload, r1, r2)
		if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrInvalidRoleDefinition) {
			t.Fatalf("err = %v, want ErrInvalidRoleDefinition", err)
		}
	})
}

func TestLoadInitialRoot_EnvelopeLevelMalformed(t *testing.T) {
	if _, err := trust.LoadInitialRoot([]byte("not an envelope at all")); !errors.Is(err, trust.ErrMalformedMetadata) {
		t.Fatalf("err = %v, want ErrMalformedMetadata", err)
	}
}

func TestLoadInitialRoot_KeyBadDER(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	badDER := base64.StdEncoding.EncodeToString([]byte("not a real DER key"))
	payload := `{"schema":"relay.root.v1","version":1,"expires":"` + now.Add(24*time.Hour).Format(time.RFC3339) +
		`","keys":{"sha256:deadbeef":{"keytype":"ecdsa-p384","public_key_der_b64":"` + badDER + `"}},` +
		`"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`
	env := signEnvelope(trust.RootPayloadType, []byte(payload), r1, r2)
	if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrMalformedMetadata) {
		t.Fatalf("err = %v, want ErrMalformedMetadata", err)
	}
}

// TestLoadInitialRoot_NonMinimalLengthSPKIRejected is step-04a-review.md
// R4A-2's required test: a hand-built non-canonical DER encoding of a real
// ECDSA P-384 key, re-encoding the outer SubjectPublicKeyInfo SEQUENCE's
// length in long form (0x81 0xNN) where the canonical encoding
// crypto/x509.MarshalPKIXPublicKey always produces uses short form. This is
// the classic BER/DER confusion R4A-2 is concerned with (two byte-distinct
// encodings of the same key deriving two different key IDs). No such
// encoding was found that this package's parser (encoding/asn1, used both
// directly and via crypto/x509.ParsePKIXPublicKey) actually accepts: Go's
// asn1 decoder enforces minimal length encoding and rejects this one
// outright ("asn1: structure error: non-minimal length"), so it is
// rejected as ErrMalformedMetadata at the structural-parsing stage, never
// reaching (and therefore never needing) the canonical re-encoding
// equality check in parseTrustedKey. That check (ErrNonCanonicalSPKI)
// remains a defensive invariant: every attempt to construct an alternate
// DER encoding this parser accepts failed at an earlier, independent
// layer, consistent with ADR 0022's note that Go's DER parsing is strict.
func TestLoadInitialRoot_NonMinimalLengthSPKIRejected(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	tk := mustKey(t)

	canonical, err := base64.StdEncoding.DecodeString(tk.publicB64())
	if err != nil {
		t.Fatalf("decode canonical DER: %v", err)
	}
	if canonical[0] != 0x30 || canonical[1] >= 0x80 {
		t.Fatalf("test assumption violated: canonical DER does not start with a short-form SEQUENCE length")
	}
	// Re-encode the outer SEQUENCE length from short form (one byte) to
	// long form (0x81 <len>), leaving every other byte — and therefore
	// the decoded key material — unchanged.
	nonMinimal := append([]byte{0x30, 0x81, canonical[1]}, canonical[2:]...)
	nonMinimalB64 := base64.StdEncoding.EncodeToString(nonMinimal)
	// DeriveKeyIDFromDER hashes the DER bytes as given, so the
	// non-minimal encoding's derived ID differs from tk.id; use the ID
	// it actually derives so this fails for the reason under test
	// (malformed DER), not an unrelated key-ID mismatch.
	nonMinimalID := trust.DeriveKeyIDFromDER(nonMinimal)

	payload := `{"schema":"relay.root.v1","version":1,"expires":"` + now.Add(24*time.Hour).Format(time.RFC3339) +
		`","keys":{"` + string(nonMinimalID) + `":{"keytype":"ecdsa-p384","public_key_der_b64":"` + nonMinimalB64 + `"}},` +
		`"roles":{"root":{"keyids":["` + r1.id + `","` + r2.id + `"],"threshold":2,"require_keytypes":["ecdsa-p384"]},` +
		`"targets":{"keyids":["` + string(nonMinimalID) + `"],"threshold":1,"require_keytypes":["ecdsa-p384"]},` +
		`"log":{"keyids":["` + r1.id + `"],"threshold":1,"require_keytypes":["ecdsa-p384"]}}}`
	env := signEnvelope(trust.RootPayloadType, []byte(payload), r1, r2)
	if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrMalformedMetadata) {
		t.Fatalf("err = %v, want ErrMalformedMetadata (non-minimal length rejected by encoding/asn1 itself)", err)
	}
}
