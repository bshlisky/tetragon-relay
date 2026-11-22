package verify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

// This file contains minimal, test-only helpers for signing ad hoc bundle
// payloads directly in internal/verify's own test suite, to exercise edge
// cases not covered by the committed testdata/vectors fixtures (which are
// produced by the separate, build-tag-gated cmd/bundlesign-test). As in
// internal/trust/helpers_test.go, the wire shape is deliberately duplicated
// in miniature rather than shared, so that a bug in one generator is
// unlikely to be mirrored by the other.

type edgeKey struct {
	id   string
	priv *ecdsa.PrivateKey
}

func newEdgeKey(t *testing.T) *edgeKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id, err := trust.DeriveKeyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("derive key id: %v", err)
	}
	return &edgeKey{id: string(id), priv: priv}
}

func (k *edgeKey) publicB64() string {
	der, _ := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
	return base64.StdEncoding.EncodeToString(der)
}

func (k *edgeKey) sign(pae []byte) []byte {
	digest := sha512.Sum384(pae)
	sig, _ := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	return sig
}

type edgeWireSig struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}
type edgeWireEnvelope struct {
	PayloadType string        `json:"payloadType"`
	Payload     string        `json:"payload"`
	Signatures  []edgeWireSig `json:"signatures"`
}

func edgeSignEnvelope(payloadType string, payload []byte, signers ...*edgeKey) []byte {
	pae := dsse.PAE(payloadType, payload)
	sigs := make([]edgeWireSig, 0, len(signers))
	for _, k := range signers {
		sigs = append(sigs, edgeWireSig{KeyID: k.id, Sig: base64.StdEncoding.EncodeToString(k.sign(pae))})
	}
	env := edgeWireEnvelope{
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

// edgeRoot builds a self-signed root with a single root key (threshold 1)
// and a single targets key (threshold 1); the log role reuses the root key
// since these edge-case tests do not exercise log proofs.
func edgeRoot(t *testing.T, requireLogProof bool, expires time.Time) (env []byte, targetsKey *edgeKey) {
	t.Helper()
	r1 := newEdgeKey(t)
	tk := newEdgeKey(t)

	type keyEntry struct {
		KeyType      string `json:"keytype"`
		PublicKeyDER string `json:"public_key_der_b64"`
	}
	type role struct {
		KeyIDs    []string `json:"keyids"`
		Threshold int      `json:"threshold"`
	}
	type roles struct {
		Root    role `json:"root"`
		Targets role `json:"targets"`
		Log     role `json:"log"`
	}
	type rootPayload struct {
		Schema          string              `json:"schema"`
		Version         uint64              `json:"version"`
		Expires         time.Time           `json:"expires"`
		Keys            map[string]keyEntry `json:"keys"`
		Roles           roles               `json:"roles"`
		RequireLogProof bool                `json:"require_log_proof"`
	}

	rp := rootPayload{
		Schema:  "relay.root.v1",
		Version: 1,
		Expires: expires,
		Keys: map[string]keyEntry{
			r1.id: {KeyType: "ecdsa-p384", PublicKeyDER: r1.publicB64()},
			tk.id: {KeyType: "ecdsa-p384", PublicKeyDER: tk.publicB64()},
		},
		Roles: roles{
			Root:    role{KeyIDs: []string{r1.id}, Threshold: 1},
			Targets: role{KeyIDs: []string{tk.id}, Threshold: 1},
			Log:     role{KeyIDs: []string{r1.id}, Threshold: 1},
		},
		RequireLogProof: requireLogProof,
	}
	payload, err := json.Marshal(rp)
	if err != nil {
		t.Fatalf("marshal root payload: %v", err)
	}
	return edgeSignEnvelope(trust.RootPayloadType, payload, r1), tk
}

func edgeTargetsVerifier(t *testing.T, env []byte, now time.Time) trust.Verifier {
	t.Helper()
	root, err := trust.LoadInitialRoot(env)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	tv, err := root.TargetsVerifier(now)
	if err != nil {
		t.Fatalf("TargetsVerifier: %v", err)
	}
	return tv
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// edgeRootForFuzz is edgeRoot without a *testing.T dependency, for use in a
// FuzzXxx function's one-time setup (which runs before f.Fuzz and does not
// have a *testing.T). It panics on unexpected generation failure, which
// would indicate a broken test environment, not a fuzz finding.
func edgeRootForFuzz(expires time.Time) (env []byte, targetsKey *edgeKey) {
	newKey := func() *edgeKey {
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			panic(err)
		}
		id, err := trust.DeriveKeyID(&priv.PublicKey)
		if err != nil {
			panic(err)
		}
		return &edgeKey{id: string(id), priv: priv}
	}
	r1 := newKey()
	tk := newKey()

	type keyEntry struct {
		KeyType      string `json:"keytype"`
		PublicKeyDER string `json:"public_key_der_b64"`
	}
	type role struct {
		KeyIDs    []string `json:"keyids"`
		Threshold int      `json:"threshold"`
	}
	type roles struct {
		Root    role `json:"root"`
		Targets role `json:"targets"`
		Log     role `json:"log"`
	}
	type rootPayload struct {
		Schema  string              `json:"schema"`
		Version uint64              `json:"version"`
		Expires time.Time           `json:"expires"`
		Keys    map[string]keyEntry `json:"keys"`
		Roles   roles               `json:"roles"`
	}

	rp := rootPayload{
		Schema:  "relay.root.v1",
		Version: 1,
		Expires: expires,
		Keys: map[string]keyEntry{
			r1.id: {KeyType: "ecdsa-p384", PublicKeyDER: r1.publicB64()},
			tk.id: {KeyType: "ecdsa-p384", PublicKeyDER: tk.publicB64()},
		},
		Roles: roles{
			Root:    role{KeyIDs: []string{r1.id}, Threshold: 1},
			Targets: role{KeyIDs: []string{tk.id}, Threshold: 1},
			Log:     role{KeyIDs: []string{r1.id}, Threshold: 1},
		},
	}
	payload, err := json.Marshal(rp)
	if err != nil {
		panic(err)
	}
	return edgeSignEnvelope(trust.RootPayloadType, payload, r1), tk
}

func decodeB64Fuzz(f *testing.F, s string) ([]byte, error) {
	f.Helper()
	return base64.StdEncoding.DecodeString(s)
}
