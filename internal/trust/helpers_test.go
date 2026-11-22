package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

// This file contains minimal, test-only helpers for building and signing
// root metadata envelopes directly in internal/trust's own test suite,
// independent of cmd/bundlesign-test (which is build-tag gated and cannot be
// imported from an ordinary _test.go file). It duplicates a small amount of
// wire-shape knowledge deliberately: if the two ever disagree, both the
// vector self-check in cmd/bundlesign-test and these tests would need to be
// wrong in the same way for a bug to hide, which is unlikely.

type genKey struct {
	id   string
	priv *ecdsa.PrivateKey
}

func mustKey(t testingT) *genKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id, err := trust.DeriveKeyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("derive key id: %v", err)
	}
	return &genKey{id: string(id), priv: priv}
}

func (k *genKey) publicB64() string {
	der, _ := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
	return base64.StdEncoding.EncodeToString(der)
}

func (k *genKey) sign(pae []byte) []byte {
	digest := sha512.Sum384(pae)
	sig, _ := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	return sig
}

type wireKeyEntry struct {
	KeyType      string `json:"keytype"`
	PublicKeyDER string `json:"public_key_der_b64"`
}
type wireRole struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}
type wireRoles struct {
	Root    wireRole `json:"root"`
	Targets wireRole `json:"targets"`
	Log     wireRole `json:"log"`
}
type wireRootPayload struct {
	Schema          string                  `json:"schema"`
	Version         uint64                  `json:"version"`
	Expires         time.Time               `json:"expires"`
	Keys            map[string]wireKeyEntry `json:"keys"`
	Roles           wireRoles               `json:"roles"`
	RequireLogProof bool                    `json:"require_log_proof"`
}
type wireSig struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}
type wireEnvelope struct {
	PayloadType string    `json:"payloadType"`
	Payload     string    `json:"payload"`
	Signatures  []wireSig `json:"signatures"`
}

func roleOf(keys []*genKey, threshold int) wireRole {
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.id)
	}
	return wireRole{KeyIDs: ids, Threshold: threshold}
}

func buildRootPayload(version int, expires time.Time, allKeys []*genKey, root, targets, log wireRole) []byte {
	keys := make(map[string]wireKeyEntry, len(allKeys))
	for _, k := range allKeys {
		keys[k.id] = wireKeyEntry{KeyType: "ecdsa-p384", PublicKeyDER: k.publicB64()}
	}
	p := wireRootPayload{
		Schema:  "relay.root.v1",
		Version: uint64(version),
		Expires: expires,
		Keys:    keys,
		Roles:   wireRoles{Root: root, Targets: targets, Log: log},
	}
	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return b
}

func signEnvelope(payloadType string, payload []byte, signers ...*genKey) []byte {
	pae := dsse.PAE(payloadType, payload)
	sigs := make([]wireSig, 0, len(signers))
	for _, k := range signers {
		sigs = append(sigs, wireSig{KeyID: k.id, Sig: base64.StdEncoding.EncodeToString(k.sign(pae))})
	}
	env := wireEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  sigs,
	}
	b, err := json.Marshal(env)
	if err != nil {
		panic(err)
	}
	return b
}

// standardRoot builds a self-signed root with 3 root keys (threshold 2), 1
// targets key (threshold 1), and 1 log key (threshold 1), returning the
// signed envelope bytes and the individual keys for further use.
func standardRoot(t testingT, version int, expires time.Time) (envelope []byte, rootKeys []*genKey, targetsKey *genKey, logKey *genKey) {
	t.Helper()
	r1, r2, r3 := mustKey(t), mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	all := []*genKey{r1, r2, r3, tk, lk}
	payload := buildRootPayload(version, expires, all, roleOf([]*genKey{r1, r2, r3}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
	env := signEnvelope(trust.RootPayloadType, payload, r1, r2)
	return env, []*genKey{r1, r2, r3}, tk, lk
}

// testingT is the subset of *testing.T used by helpers, so they can also be
// called from fuzz targets (*testing.F does not satisfy *testing.T).
type testingT interface {
	Helper()
	Fatalf(format string, args ...interface{})
}

func parseEnvForTest(envBytes []byte) (*dsse.Envelope, error) {
	return dsse.ParseEnvelope(envBytes, limits.MaxRootMetadataBytes, limits.MaxJSONDepth)
}

// mapKeyRename does a naive textual replace of a quoted JSON object key,
// relying on the key being unique in payload (true for the small, synthetic
// payloads these tests build).
func mapKeyRename(t testingT, payload []byte, oldKey, newKey string) []byte {
	t.Helper()
	old := `"` + oldKey + `":`
	repl := `"` + newKey + `":`
	s := string(payload)
	idx := indexOf(s, old)
	if idx < 0 {
		t.Fatalf("mapKeyRename: %q not found in payload", oldKey)
	}
	return []byte(s[:idx] + repl + s[idx+len(old):])
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// mustMarshalP384Pub returns the DER SubjectPublicKeyInfo of a fresh,
// genuinely P-384 key, for tests that need valid DER bytes paired with a
// deliberately wrong "keytype" string.
func mustMarshalP384Pub(t testingT) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return der
}

func hashLike() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"[:64]
}
