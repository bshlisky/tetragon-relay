package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
)

// This file is an internal (white-box) test: it constructs *dsse.Envelope
// values directly rather than going through dsse.ParseEnvelope, so it can
// exercise verifyRoleThreshold's defensive branches that are no longer
// reachable through any public API now that dsse.ParseEnvelope itself
// rejects duplicate signature keyids (step 1 review A4). Those branches are
// kept deliberately as defense in depth; this test is what proves they
// still do the right thing if that invariant were ever weakened upstream.

func genTestKey(t *testing.T) (KeyID, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id, err := DeriveKeyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("derive key id: %v", err)
	}
	return id, priv
}

func signPAE(priv *ecdsa.PrivateKey, pae []byte) []byte {
	digest := sha512.Sum384(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		panic(err)
	}
	return sig
}

func TestVerifyRoleThreshold_DuplicateSignatureInEnvelopeCountsOnce(t *testing.T) {
	kid, priv := genTestKey(t)
	env := &dsse.Envelope{PayloadType: "t", Payload: []byte("payload")}
	pae := dsse.PAE(env.PayloadType, env.Payload)
	sig := signPAE(priv, pae)
	// Two identical signature entries from the same key, which
	// dsse.ParseEnvelope would never actually produce (it rejects
	// duplicate keyids), constructed directly to exercise the defensive
	// "already verified" branch.
	env.Signatures = []dsse.Signature{{KeyID: string(kid), Sig: sig}, {KeyID: string(kid), Sig: sig}}

	keys := map[KeyID]*ecdsa.PublicKey{kid: &priv.PublicKey}
	role := Role{KeyIDs: []KeyID{kid}, Threshold: 2}
	if verifyRoleThreshold(env, keys, role) {
		t.Fatalf("two signatures from the same key must not satisfy a threshold of 2")
	}
}

func TestVerifyRoleThreshold_SignatureFromKeyNotInKeySet(t *testing.T) {
	kid, priv := genTestKey(t)
	env := &dsse.Envelope{PayloadType: "t", Payload: []byte("payload")}
	pae := dsse.PAE(env.PayloadType, env.Payload)
	env.Signatures = []dsse.Signature{{KeyID: string(kid), Sig: signPAE(priv, pae)}}

	// kid is listed in the role but deliberately absent from the keys
	// map (defensive branch: parseAndValidatePayload's own invariants
	// should make this impossible via the public API, since role
	// validation requires every role key ID to exist in the key set).
	role := Role{KeyIDs: []KeyID{kid}, Threshold: 1}
	if verifyRoleThreshold(env, map[KeyID]*ecdsa.PublicKey{}, role) {
		t.Fatalf("a role key absent from the key set must never satisfy the threshold")
	}
}

func TestRequireDisjointRoles_AllPairwiseOverlaps(t *testing.T) {
	a, _ := genTestKey(t)
	b, _ := genTestKey(t)
	c, _ := genTestKey(t)

	cases := []struct {
		name           string
		root, targ, lg Role
	}{
		{"root/targets overlap", Role{KeyIDs: []KeyID{a}}, Role{KeyIDs: []KeyID{a}}, Role{KeyIDs: []KeyID{c}}},
		{"root/log overlap", Role{KeyIDs: []KeyID{a}}, Role{KeyIDs: []KeyID{b}}, Role{KeyIDs: []KeyID{a}}},
		{"targets/log overlap", Role{KeyIDs: []KeyID{a}}, Role{KeyIDs: []KeyID{b}}, Role{KeyIDs: []KeyID{b}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := requireDisjointRoles(c.root, c.targ, c.lg); err == nil {
				t.Fatalf("expected an error for %s", c.name)
			}
		})
	}

	if err := requireDisjointRoles(Role{KeyIDs: []KeyID{a}}, Role{KeyIDs: []KeyID{b}}, Role{KeyIDs: []KeyID{c}}); err != nil {
		t.Fatalf("unexpected error for genuinely disjoint roles: %v", err)
	}
}
