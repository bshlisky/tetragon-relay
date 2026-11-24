package agent_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

// This file duplicates a small amount of root-metadata wire-shape
// knowledge, the same way internal/trust/helpers_test.go and
// internal/verify/helpers_test.go do, so internal/agent's tests can build
// real, signable trust-root envelopes without importing cmd/bundlesign-test
// (build-tag gated) or internal/trust's own unexported test helpers
// (package trust_test, not importable here).

type genKey struct {
	id   string
	priv *ecdsa.PrivateKey
}

func mustKey(t *testing.T) *genKey {
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
	KeyIDs          []string `json:"keyids"`
	Threshold       int      `json:"threshold"`
	RequireKeyTypes []string `json:"require_keytypes,omitempty"`
}
type wireRoles struct {
	Root    wireRole `json:"root"`
	Targets wireRole `json:"targets"`
	Log     wireRole `json:"log"`
}
type wireRootPayload struct {
	Schema  string                  `json:"schema"`
	Version uint64                  `json:"version"`
	Expires time.Time               `json:"expires"`
	Keys    map[string]wireKeyEntry `json:"keys"`
	Roles   wireRoles               `json:"roles"`
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
	return wireRole{KeyIDs: ids, Threshold: threshold, RequireKeyTypes: []string{"ecdsa-p384"}}
}

func buildRootPayload(version int, expires time.Time, allKeys []*genKey, root, targets, log wireRole) []byte {
	keys := make(map[string]wireKeyEntry, len(allKeys))
	for _, k := range allKeys {
		keys[k.id] = wireKeyEntry{KeyType: "ecdsa-p384", PublicKeyDER: k.publicB64()}
	}
	p := wireRootPayload{Schema: "relay.root.v1", Version: uint64(version), Expires: expires, Keys: keys, Roles: wireRoles{Root: root, Targets: targets, Log: log}}
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
	env := wireEnvelope{PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: sigs}
	b, err := json.Marshal(env)
	if err != nil {
		panic(err)
	}
	return b
}

// standardRoot builds a self-signed root (3 root keys threshold 2, 1
// targets key, 1 log key) at the given version/expiry, returning the
// signed envelope bytes and the root keys (for signing a later rotation).
func standardRoot(t *testing.T, version int, expires time.Time) (envelope []byte, rootKeys []*genKey) {
	t.Helper()
	r1, r2, r3 := mustKey(t), mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	all := []*genKey{r1, r2, r3, tk, lk}
	payload := buildRootPayload(version, expires, all, roleOf([]*genKey{r1, r2, r3}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
	env := signEnvelope(trust.RootPayloadType, payload, r1, r2)
	return env, []*genKey{r1, r2, r3}
}

// rotatedRoot builds a NEW root at version+1 with a fresh key set, signed
// by a threshold of BOTH oldRootKeys and the new root's own keys (so it
// satisfies (*trust.Root).Update), and returns its bytes.
func rotatedRoot(t *testing.T, version int, expires time.Time, oldRootKeys []*genKey) []byte {
	t.Helper()
	b, _ := rotatedRootWithKeys(t, version, expires, oldRootKeys)
	return b
}

// rotatedRootWithKeys is rotatedRoot, additionally returning the new
// root's own key set so a test can chain a further rotation on top of it
// (step-04b-review.md R4B-1's multi-version forward chaining).
func rotatedRootWithKeys(t *testing.T, version int, expires time.Time, oldRootKeys []*genKey) (envelope []byte, newRootKeys []*genKey) {
	t.Helper()
	r1, r2, r3 := mustKey(t), mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	all := []*genKey{r1, r2, r3, tk, lk}
	payload := buildRootPayload(version, expires, all, roleOf([]*genKey{r1, r2, r3}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
	pae := dsse.PAE(trust.RootPayloadType, payload)
	sigs := []wireSig{
		{KeyID: oldRootKeys[0].id, Sig: base64.StdEncoding.EncodeToString(oldRootKeys[0].sign(pae))},
		{KeyID: oldRootKeys[1].id, Sig: base64.StdEncoding.EncodeToString(oldRootKeys[1].sign(pae))},
		{KeyID: r1.id, Sig: base64.StdEncoding.EncodeToString(r1.sign(pae))},
		{KeyID: r2.id, Sig: base64.StdEncoding.EncodeToString(r2.sign(pae))},
	}
	env := wireEnvelope{PayloadType: trust.RootPayloadType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: sigs}
	b, err := json.Marshal(env)
	if err != nil {
		panic(err)
	}
	return b, []*genKey{r1, r2, r3}
}
