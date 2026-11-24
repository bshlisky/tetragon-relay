package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

func fixedNow() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// buildHybridTargetsRoot builds a minimal, self-signed root whose TARGETS
// role requires both ecdsa-p384 and mldsa-87 (so checkMLDSARequirement has
// something to flag), duplicating the same small amount of wire-shape
// knowledge internal/trust/helpers_test.go and internal/agent/helpers_test.go
// (package agent_test, not importable from this white-box file) do.
func buildHybridTargetsRoot(t *testing.T, now time.Time) ([]byte, error) {
	t.Helper()
	newECDSAKey := func() (id string, priv *ecdsa.PrivateKey, pubB64 string) {
		p, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa key: %v", err)
		}
		kid, err := trust.DeriveKeyID(&p.PublicKey)
		if err != nil {
			t.Fatalf("derive key id: %v", err)
		}
		der, _ := x509.MarshalPKIXPublicKey(&p.PublicKey)
		return string(kid), p, base64.StdEncoding.EncodeToString(der)
	}
	r1id, r1, r1pub := newECDSAKey()
	r2id, r2, r2pub := newECDSAKey()
	tid, _, tpub := newECDSAKey()
	lid, _, lpub := newECDSAKey()

	mpriv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("generate mldsa key: %v", err)
	}
	mder, err := x509.MarshalPKIXPublicKey(mpriv.PublicKey())
	if err != nil {
		t.Fatalf("marshal mldsa public key: %v", err)
	}
	mid := string(trust.DeriveKeyIDFromDER(mder))

	type keyEntry struct {
		KeyType      string `json:"keytype"`
		PublicKeyDER string `json:"public_key_der_b64"`
	}
	type role struct {
		KeyIDs          []string `json:"keyids"`
		Threshold       int      `json:"threshold"`
		RequireKeyTypes []string `json:"require_keytypes,omitempty"`
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
		Expires: now.Add(365 * 24 * time.Hour),
		Keys: map[string]keyEntry{
			r1id: {KeyType: "ecdsa-p384", PublicKeyDER: r1pub},
			r2id: {KeyType: "ecdsa-p384", PublicKeyDER: r2pub},
			tid:  {KeyType: "ecdsa-p384", PublicKeyDER: tpub},
			mid:  {KeyType: "mldsa-87", PublicKeyDER: base64.StdEncoding.EncodeToString(mder)},
			lid:  {KeyType: "ecdsa-p384", PublicKeyDER: lpub},
		},
		Roles: roles{
			Root:    role{KeyIDs: []string{r1id, r2id}, Threshold: 2, RequireKeyTypes: []string{"ecdsa-p384"}},
			Targets: role{KeyIDs: []string{tid, mid}, Threshold: 1, RequireKeyTypes: []string{"ecdsa-p384", "mldsa-87"}},
			Log:     role{KeyIDs: []string{lid}, Threshold: 1, RequireKeyTypes: []string{"ecdsa-p384"}},
		},
	}
	payload, err := json.Marshal(rp)
	if err != nil {
		t.Fatalf("marshal root payload: %v", err)
	}
	pae := dsse.PAE(trust.RootPayloadType, payload)
	sign := func(p *ecdsa.PrivateKey) string {
		digest := sha512.Sum384(pae)
		sig, _ := ecdsa.SignASN1(rand.Reader, p, digest[:])
		return base64.StdEncoding.EncodeToString(sig)
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
	env := wireEnvelope{
		PayloadType: trust.RootPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []wireSig{
			{KeyID: r1id, Sig: sign(r1)},
			{KeyID: r2id, Sig: sign(r2)},
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b, nil
}

// This file is a white-box (package agent) test for error branches not
// otherwise reachable through the black-box startup_test.go suite:
// selftest.go's decode-failure branches (exercised by temporarily
// swapping the embedded constants is not possible since they are
// constants, so these instead directly unit-test the lower-level decode
// helpers' error wrapping with deliberately invalid base64) and
// checkMLDSARequirement's rejection branch, which requires
// Capabilities.MLDSAAvailable=false — never true in this development
// environment (RunCryptoSelfTest_Succeeds), so it must be constructed
// directly.

func TestCheckMLDSARequirement_FlagsEachRoleNeedingIt(t *testing.T) {
	caps := Capabilities{MLDSAAvailable: false}

	// trust.Root's role accessors (RootRole/TargetsRole/LogRole) are
	// exported and return copies; build one directly via the package's
	// own exported construction path (LoadInitialRoot) rather than
	// reaching into unexported fields, matching how a real caller would
	// obtain a *trust.Root.
	now := fixedNow()
	envelope, _ := buildHybridTargetsRoot(t, now)
	root, err := trust.LoadInitialRoot(envelope)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}

	err = checkMLDSARequirement(root, caps, &FakeAuditor{})
	if !errors.Is(err, ErrMLDSAUnavailable) {
		t.Fatalf("err = %v, want ErrMLDSAUnavailable", err)
	}

	auditor := &FakeAuditor{}
	_ = checkMLDSARequirement(root, caps, auditor)
	found := false
	for _, e := range auditor.Events {
		if e.Step == "mldsa_requirement" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no mldsa_requirement audit event recorded")
	}
}

func TestCheckMLDSARequirement_NoOpWhenAvailableOrNilRoot(t *testing.T) {
	if err := checkMLDSARequirement(nil, Capabilities{MLDSAAvailable: false}, &FakeAuditor{}); err != nil {
		t.Fatalf("nil root: err = %v, want nil", err)
	}
	now := fixedNow()
	envelope, _ := buildHybridTargetsRoot(t, now)
	root, err := trust.LoadInitialRoot(envelope)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	if err := checkMLDSARequirement(root, Capabilities{MLDSAAvailable: true}, &FakeAuditor{}); err != nil {
		t.Fatalf("MLDSAAvailable=true: err = %v, want nil", err)
	}
}

func TestRunCryptoSelfTest_ECDSAFailureRefusesToStart(t *testing.T) {
	_, err := runCryptoSelfTest("not base64!!", selfTestECDSAPubDERB64, selfTestECDSASigB64, selfTestMLDSA87RawPubB64, selfTestMLDSA87SigB64)
	if !errors.Is(err, ErrECDSASelfTestFailed) {
		t.Fatalf("err = %v, want ErrECDSASelfTestFailed", err)
	}
}

func TestRunCryptoSelfTest_MLDSAFailureIsNotFatal(t *testing.T) {
	caps, err := runCryptoSelfTest(selfTestMessageB64, selfTestECDSAPubDERB64, selfTestECDSASigB64, "not base64!!", selfTestMLDSA87SigB64)
	if err != nil {
		t.Fatalf("err = %v, want nil (an ML-DSA failure must not refuse to start)", err)
	}
	if caps.MLDSAAvailable {
		t.Fatalf("MLDSAAvailable = true, want false")
	}
	if caps.MLDSAErr == nil {
		t.Fatalf("MLDSAErr = nil, want the decode error")
	}
}

func TestVerifyECDSASelfTest_EachFailureBranch(t *testing.T) {
	good := selfTestMessageB64
	goodPub := selfTestECDSAPubDERB64
	goodSig := selfTestECDSASigB64

	if err := verifyECDSASelfTest(good, goodPub, goodSig); err != nil {
		t.Fatalf("the real vector must pass: %v", err)
	}
	if err := verifyECDSASelfTest("not base64!!", goodPub, goodSig); err == nil {
		t.Fatalf("expected a message decode error")
	}
	if err := verifyECDSASelfTest(good, "not base64!!", goodSig); err == nil {
		t.Fatalf("expected a public key decode error")
	}
	if err := verifyECDSASelfTest(good, goodPub, "not base64!!"); err == nil {
		t.Fatalf("expected a signature decode error")
	}
	// Valid base64 that is not a parseable SPKI at all.
	notASPKI := base64.StdEncoding.EncodeToString([]byte("not a real DER key"))
	if err := verifyECDSASelfTest(good, notASPKI, goodSig); err == nil {
		t.Fatalf("expected a public key parse error")
	}
	// A structurally valid, but non-ECDSA, SPKI (ML-DSA-87's own test
	// vector's public key).
	if err := verifyECDSASelfTest(good, selfTestMLDSA87RawPubB64AsFakeDER(t), goodSig); err == nil {
		t.Fatalf("expected an error for a non-ECDSA public key")
	}
	// A well-formed ECDSA key and signature, but over the wrong message
	// (or signed by a different key): the signature must not verify.
	otherMsg := base64.StdEncoding.EncodeToString([]byte("a different message entirely"))
	if err := verifyECDSASelfTest(otherMsg, goodPub, goodSig); err == nil {
		t.Fatalf("expected a verification failure for the wrong message")
	}
}

// selfTestMLDSA87RawPubB64AsFakeDER returns something that decodes as
// valid base64 but is not a parseable SubjectPublicKeyInfo, reusing the
// ML-DSA raw public key bytes (which are not DER) purely as "valid
// base64, invalid DER" filler.
func selfTestMLDSA87RawPubB64AsFakeDER(t *testing.T) string {
	t.Helper()
	return selfTestMLDSA87RawPubB64
}

func TestVerifyMLDSASelfTest_EachFailureBranch(t *testing.T) {
	good := selfTestMessageB64
	goodPub := selfTestMLDSA87RawPubB64
	goodSig := selfTestMLDSA87SigB64

	if err := verifyMLDSASelfTest(good, goodPub, goodSig); err != nil {
		t.Fatalf("the real vector must pass: %v", err)
	}
	if err := verifyMLDSASelfTest("not base64!!", goodPub, goodSig); err == nil {
		t.Fatalf("expected a message decode error")
	}
	if err := verifyMLDSASelfTest(good, "not base64!!", goodSig); err == nil {
		t.Fatalf("expected a public key decode error")
	}
	if err := verifyMLDSASelfTest(good, goodPub, "not base64!!"); err == nil {
		t.Fatalf("expected a signature decode error")
	}
	// A wrong-size raw public key: dsse.VerifyMLDSA87 wraps
	// mldsa.NewPublicKey's construction error.
	tooShort := base64.StdEncoding.EncodeToString([]byte("too short"))
	if err := verifyMLDSASelfTest(good, tooShort, goodSig); err == nil {
		t.Fatalf("expected a key-construction error for a too-short public key")
	}
	otherMsg := base64.StdEncoding.EncodeToString([]byte("a different message entirely"))
	if err := verifyMLDSASelfTest(otherMsg, goodPub, goodSig); err == nil {
		t.Fatalf("expected a verification failure for the wrong message")
	}
}
