package dsse

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"testing"
)

func TestPAE_Basic(t *testing.T) {
	got := PAE("application/json", []byte(`{"a":1}`))
	want := []byte("DSSEv1 16 application/json 7 {\"a\":1}")
	if !bytes.Equal(got, want) {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
}

// TestPAE_LengthPrefixPreventsAmbiguity demonstrates why PAE must encode
// explicit lengths: without them, two different (payloadType, payload)
// splits that concatenate to the same bytes would be indistinguishable, and
// a signature computed over one split would verify for the other. This is
// the "PAE length mismatch" property referenced in
// testdata/vectors/README.md.
func TestPAE_LengthPrefixPreventsAmbiguity(t *testing.T) {
	// Two splits of the same concatenated bytes "abcdef":
	//   split 1: type="ab", payload="cdef"
	//   split 2: type="abcd", payload="ef"
	// A naive PAE without length prefixes (just "DSSEv1" SP type SP
	// payload) would produce identical bytes for both splits whenever
	// type+payload concatenates the same way. Our PAE must not.
	pae1 := PAE("ab", []byte("cdef"))
	pae2 := PAE("abcd", []byte("ef"))
	if bytes.Equal(pae1, pae2) {
		t.Fatalf("PAE collided for different (type, payload) splits: %q", pae1)
	}

	// Concretely: a signature over one split's PAE must not verify
	// against the other split's PAE, even though the "naive" concatenated
	// payload bytes are identical.
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	digest1 := sha512.Sum384(pae1)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest1[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !VerifyECDSAP384(&priv.PublicKey, pae1, sig) {
		t.Fatalf("signature must verify against the PAE it was computed over")
	}
	if VerifyECDSAP384(&priv.PublicKey, pae2, sig) {
		t.Fatalf("signature over split 1's PAE must NOT verify against split 2's PAE")
	}
}

func TestVerifyECDSAP384_RejectsNonP384(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pae := PAE("type", []byte("payload"))
	digest := sha512.Sum384(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if VerifyECDSAP384(&priv.PublicKey, pae, sig) {
		t.Fatalf("VerifyECDSAP384 must reject a P-256 key")
	}
}

func TestVerifyECDSAP384_NeverPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyECDSAP384 panicked: %v", r)
		}
	}()
	if VerifyECDSAP384(nil, nil, nil) {
		t.Fatalf("expected false for nil inputs")
	}
	if VerifyECDSAP384(nil, []byte("x"), []byte("y")) {
		t.Fatalf("expected false for nil key")
	}
}
