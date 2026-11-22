package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestLoadInitialRoot_DuplicateSignatureSameKey(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	tk := mustKey(t)
	payload := buildRootPayload(1, now.Add(24*time.Hour), []*genKey{r1, r2, tk},
		roleOf([]*genKey{r1, r2}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{tk}, 1))
	// Signed twice by the SAME key (r1); threshold 2 requires two DISTINCT keys.
	env := signEnvelope(trust.RootPayloadType, payload, r1, r1)
	if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrThresholdNotMet) {
		t.Fatalf("err = %v, want ErrThresholdNotMet", err)
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

func TestLoadInitialRoot_DeclaredNonP384KeyType(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2 := mustKey(t), mustKey(t)
	badDER := base64.StdEncoding.EncodeToString(mustMarshalP384Pub(t))
	payload := `{"schema":"relay.root.v1","version":1,"expires":"` + now.Add(24*time.Hour).Format(time.RFC3339) +
		`","keys":{"sha256:deadbeef":{"keytype":"ecdsa-p256","public_key_der_b64":"` + badDER + `"}},` +
		`"roles":{"root":{"keyids":[],"threshold":1},"targets":{"keyids":[],"threshold":1},"log":{"keyids":[],"threshold":1}}}`
	env := signEnvelope(trust.RootPayloadType, []byte(payload), r1, r2)
	if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrUnsupportedKeyType) {
		t.Fatalf("err = %v, want ErrUnsupportedKeyType", err)
	}
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
