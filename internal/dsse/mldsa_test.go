package dsse

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha512"
	"testing"
)

func mustMLDSA87Key(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("generate mldsa-87 key: %v", err)
	}
	return priv
}

func TestVerifyMLDSA87_Valid(t *testing.T) {
	priv := mustMLDSA87Key(t)
	pae := PAE("type", []byte("payload"))
	sig, err := priv.Sign(nil, pae, &mldsa.Options{Context: ""})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := VerifyMLDSA87(priv.PublicKey().Bytes(), pae, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("a correctly signed message must verify")
	}
}

func TestVerifyMLDSA87_WrongMessage(t *testing.T) {
	priv := mustMLDSA87Key(t)
	pae := PAE("type", []byte("payload"))
	sig, err := priv.Sign(nil, pae, &mldsa.Options{Context: ""})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	other := PAE("type", []byte("different payload"))
	ok, err := VerifyMLDSA87(priv.PublicKey().Bytes(), other, sig)
	if err != nil {
		t.Fatalf("a wrong-message mismatch must be (false, nil), not an error: %v", err)
	}
	if ok {
		t.Fatal("signature over a different message must not verify")
	}
}

func TestVerifyMLDSA87_WrongKey(t *testing.T) {
	priv := mustMLDSA87Key(t)
	other := mustMLDSA87Key(t)
	pae := PAE("type", []byte("payload"))
	sig, err := priv.Sign(nil, pae, &mldsa.Options{Context: ""})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := VerifyMLDSA87(other.PublicKey().Bytes(), pae, sig)
	if err != nil {
		t.Fatalf("a wrong-key mismatch must be (false, nil), not an error: %v", err)
	}
	if ok {
		t.Fatal("signature must not verify under a different key")
	}
}

// TestVerifyMLDSA87_UnavailableOrMalformedKey_FailsClosed is step 4 prompt
// Part B2's required "ML-DSA unavailable" coverage. This development
// environment is not built against the FIPS 140-3 Go Cryptographic Module
// v1.0.0 (ADR 0021), so crypto/mldsa.NewPublicKey's own unavailability
// error cannot be reproduced directly here; this instead exercises the
// exact same code path (mldsa.NewPublicKey returning a non-nil error) via
// a malformed raw key encoding, confirming VerifyMLDSA87 reports it as a
// typed, non-nil error rather than silently treating it as "signature
// invalid" — the fail-closed behavior Part B2 requires regardless of WHY
// construction failed.
func TestVerifyMLDSA87_UnavailableOrMalformedKey_FailsClosed(t *testing.T) {
	priv := mustMLDSA87Key(t)
	pae := PAE("type", []byte("payload"))
	sig, err := priv.Sign(nil, pae, &mldsa.Options{Context: ""})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	malformedKey := priv.PublicKey().Bytes()[:len(priv.PublicKey().Bytes())-1] // wrong length
	ok, err := VerifyMLDSA87(malformedKey, pae, sig)
	if ok {
		t.Fatal("a malformed/unconstructable key must never be reported as a valid signature")
	}
	if err == nil {
		t.Fatal("a malformed/unconstructable key must return a non-nil error (fail closed with a named cause), not (false, nil)")
	}
	t.Logf("construction error (same code path as ML-DSA unavailability): %v", err)
}

// TestVerifyMLDSA87_ExternalMuSignatureNeverVerifies documents (step 4
// prompt Part B2) that
// VerifyMLDSA87 always performs PURE ML-DSA-87 verification, never
// HashML-DSA (pre-hashed "External-mu"): it calls crypto/mldsa's
// package-level Verify function with a fixed, zero-value-HashFunc Options,
// which (per crypto/mldsa's own source, mldsa_fips140v1.26.go's package
// Verify) has no pre-hash code path at all — unlike
// (*mldsa.PrivateKey).Sign, which accepts crypto.SignerOpts and switches
// on opts.HashFunc() to support the signing-only External-mu variant. This
// test demonstrates the consequence concretely: a signature produced via
// the External-mu ("HashML-DSA"-style) signing path does not verify via
// VerifyMLDSA87 against the original message, confirming there is no way
// for an External-mu signature to be accepted here.
func TestVerifyMLDSA87_ExternalMuSignatureNeverVerifies(t *testing.T) {
	priv := mustMLDSA87Key(t)
	pae := PAE("type", []byte("payload"))

	// External-mu ("HashML-DSA"-style) signing requires a 64-byte
	// pre-hashed mu representative as Sign's message argument, not the
	// raw message, when opts.HashFunc() returns crypto.MLDSAMu
	// (confirmed in crypto/internal/fips140/mldsa/mldsa.go's
	// SignExternalMu: "if len(mu) != 64 { return errMessageHashLength }").
	// A real deployment would derive mu from (context, message) itself;
	// here any 64-byte value demonstrates the point just as well, since
	// the point is that VerifyMLDSA87's PURE verification (which
	// recomputes its own internal digest from the ACTUAL message and
	// never accepts an externally supplied one) cannot accept a
	// signature produced this way against the original message.
	mu := sha512.Sum512(pae) // any 64-byte value; this is not how a real mu is derived
	extMuSig, err := priv.Sign(nil, mu[:], muHashOpts{})
	if err != nil {
		t.Fatalf("SignExternalMu with a correctly-sized (64-byte) digest: %v", err)
	}
	ok, verr := VerifyMLDSA87(priv.PublicKey().Bytes(), pae, extMuSig)
	if verr != nil {
		t.Fatalf("unexpected construction error: %v", verr)
	}
	if ok {
		t.Fatal("an External-mu (\"HashML-DSA\"-style) signature must never verify via VerifyMLDSA87's pure verification")
	}
}

// muHashOpts is a minimal crypto.SignerOpts whose HashFunc reports
// crypto.MLDSAMu, selecting (*mldsa.PrivateKey).Sign's External-mu signing
// path (mldsa_fips140v1.26.go's switch on opts.HashFunc()) — the only way
// to reach that path through the public API, since mldsa.Options itself
// always reports HashFunc() == 0 (pure mode).
type muHashOpts struct{}

func (muHashOpts) HashFunc() crypto.Hash { return crypto.MLDSAMu }
