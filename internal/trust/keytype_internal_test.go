package trust

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"
)

func mustMLDSAPriv(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("generate mldsa-87 key: %v", err)
	}
	return priv
}

// marshalTestSPKI builds a minimal SubjectPublicKeyInfo with the given
// algorithm OID and parameters, and rawKey as the BIT STRING content,
// using the same pkixPublicKey/pkixAlgorithmIdentifier shapes
// parseSPKIAlgorithm itself parses — bypassing crypto/x509 entirely, so
// deliberately invalid combinations (a truncated ML-DSA-87 key, non-absent
// parameters) that crypto/x509/crypto/mldsa would never produce can be
// constructed directly.
func marshalTestSPKI(t *testing.T, oid asn1.ObjectIdentifier, params asn1.RawValue, rawKey []byte) []byte {
	t.Helper()
	spki := pkixPublicKey{
		Algorithm: pkixAlgorithmIdentifier{Algorithm: oid, Parameters: params},
		PublicKey: asn1.BitString{Bytes: rawKey, BitLength: len(rawKey) * 8},
	}
	der, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("marshal test SPKI: %v", err)
	}
	return der
}

func TestParseSPKIAlgorithm_Errors(t *testing.T) {
	if _, _, _, err := parseSPKIAlgorithm([]byte("not asn.1 at all")); err == nil {
		t.Fatal("expected an error for non-ASN.1 input")
	}

	priv := mustMLDSAPriv(t)
	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, _, _, err := parseSPKIAlgorithm(append(der, 0x00)); err == nil {
		t.Fatal("expected an error for trailing data after SubjectPublicKeyInfo")
	}
}

func TestParseTrustedKey_UnknownDeclaredType(t *testing.T) {
	priv := mustMLDSAPriv(t)
	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// parseAndValidatePayload always filters to knownKeyTypes before
	// calling parseTrustedKey; this exercises parseTrustedKey's own
	// defensive default branch directly.
	if _, err := parseTrustedKey(KeyType("bogus-type"), der); !errors.Is(err, ErrUnknownKeyType) {
		t.Fatalf("err = %v, want ErrUnknownKeyType", err)
	}
}

func TestParseTrustedKey_MLDSAWithNonAbsentParameters(t *testing.T) {
	// RFC 9881 section 4: ML-DSA SubjectPublicKeyInfo carries no
	// AlgorithmIdentifier parameters. Synthesize one that does (an ASN.1
	// NULL, the ECDSA/RSA-style convention), reusing the real OID and
	// key bytes, which parseTrustedKey must reject even though the OID
	// itself matches.
	priv := mustMLDSAPriv(t)
	rawKey := priv.PublicKey().Bytes()
	nullParams := asn1.RawValue{FullBytes: []byte{0x05, 0x00}} // ASN.1 NULL
	badDER := marshalTestSPKI(t, oidMLDSA87, nullParams, rawKey)
	if _, err := parseTrustedKey(KeyTypeMLDSA87, badDER); !errors.Is(err, ErrMalformedMetadata) {
		t.Fatalf("err = %v, want ErrMalformedMetadata", err)
	}
}

func TestParseTrustedKey_MLDSAWrongLength(t *testing.T) {
	priv := mustMLDSAPriv(t)
	rawKey := priv.PublicKey().Bytes()
	short := marshalTestSPKI(t, oidMLDSA87, asn1.RawValue{}, rawKey[:len(rawKey)-1])
	if _, err := parseTrustedKey(KeyTypeMLDSA87, short); !errors.Is(err, ErrKeytypeSPKIMismatch) {
		t.Fatalf("err = %v, want ErrKeytypeSPKIMismatch", err)
	}
}

func TestTrustedKey_VerifySignature_MLDSAConstructionError(t *testing.T) {
	tk := TrustedKey{Type: KeyTypeMLDSA87, mldsa: []byte("too short to be a real key")}
	ok, err := tk.verifySignature([]byte("pae"), []byte("sig"))
	if ok {
		t.Fatal("a key that cannot even be constructed must never report a valid signature")
	}
	if !errors.Is(err, ErrMLDSAUnavailable) {
		t.Fatalf("err = %v, want ErrMLDSAUnavailable", err)
	}
}

func TestTrustedKey_VerifySignature_UnknownType(t *testing.T) {
	tk := TrustedKey{Type: KeyType("bogus")}
	ok, err := tk.verifySignature([]byte("pae"), []byte("sig"))
	if ok {
		t.Fatal("an unknown key type must never report a valid signature")
	}
	if !errors.Is(err, ErrUnknownKeyType) {
		t.Fatalf("err = %v, want ErrUnknownKeyType", err)
	}
}
