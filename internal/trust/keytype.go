package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
)

// TrustedKey is one parsed, type-tagged public key from root metadata
// (step 4 prompt Part B1). Exactly one of the two fields is set, matching
// Type. mldsaRaw holds the raw ML-DSA-87 public key encoding (the BIT
// STRING content of its SubjectPublicKeyInfo, [mldsa.PublicKey.Bytes]'s
// shape) rather than an already-constructed *mldsa.PublicKey: constructing
// one requires crypto/mldsa, which is unavailable under the FIPS 140-3 Go
// Cryptographic Module v1.0.0 (ADR 0021), and root-metadata PARSING must
// not depend on that — only the one signature-verification call site that
// actually needs an mldsa-87 key does (ADR 0022). ecdsa-p384 keys have no
// such constraint, so they are parsed eagerly into a usable *ecdsa.PublicKey
// as before.
type TrustedKey struct {
	Type  KeyType
	ecdsa *ecdsa.PublicKey
	mldsa []byte
}

// oidECDSAPublicKey and oidNamedCurveP384 are RFC 5480's OIDs for an EC
// public key and the P-384 (secp384r1) named curve, respectively — the
// shape crypto/x509.MarshalPKIXPublicKey already produces for an
// *ecdsa.PublicKey on that curve. They are used only to recognize a
// declared ecdsa-p384 key when verifying keytype/SPKI agreement does not
// otherwise require decoding through crypto/x509.
var (
	oidECDSAPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	// oidMLDSA87 is RFC 9881's OID for ML-DSA-87
	// (2.16.840.1.101.3.4.3.19; RFC 9881 section 4), reproduced here so
	// this check never depends on crypto/mldsa's own (unexported)
	// equivalent and works even when crypto/mldsa is unavailable
	// (ADR 0021).
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// pkixPublicKey and pkixAlgorithmIdentifier mirror the ASN.1 shapes
// crypto/x509 itself parses (RFC 5280 section 4.1.2.7), used here only to
// read the SubjectPublicKeyInfo's AlgorithmIdentifier OID (and, for
// mldsa-87, the raw key bytes) WITHOUT calling crypto/x509.ParsePKIXPublicKey
// — which, for an ML-DSA SPKI, calls crypto/mldsa.NewPublicKey internally
// (confirmed in ADR 0021) and would therefore fail under a build lacking
// ML-DSA even just to check which algorithm a key declares.
type pkixPublicKey struct {
	Algorithm pkixAlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// parseSPKIAlgorithm reads der's AlgorithmIdentifier OID and the raw
// (right-aligned) public key bytes, without depending on crypto/mldsa.
func parseSPKIAlgorithm(der []byte) (oid asn1.ObjectIdentifier, params asn1.RawValue, rawKey []byte, err error) {
	var pk pkixPublicKey
	rest, err := asn1.Unmarshal(der, &pk)
	if err != nil {
		return nil, asn1.RawValue{}, nil, fmt.Errorf("trust: parse SubjectPublicKeyInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, asn1.RawValue{}, nil, fmt.Errorf("trust: trailing data after SubjectPublicKeyInfo")
	}
	if pk.PublicKey.BitLength%8 != 0 {
		return nil, asn1.RawValue{}, nil, fmt.Errorf("trust: SubjectPublicKeyInfo public key is not a whole number of bytes")
	}
	return pk.Algorithm.Algorithm, pk.Algorithm.Parameters, pk.PublicKey.RightAlign(), nil
}

// mldsaAlgorithmIdentifier is RFC 9881 section 4's AlgorithmIdentifier for
// ML-DSA-87: just the OID, with no parameters field at all (not even an
// explicit NULL) — unlike pkixAlgorithmIdentifier above, which carries an
// (optional) Parameters field for ECDSA's named-curve case.
type mldsaAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

// mldsaPKIXPublicKey is the canonical SubjectPublicKeyInfo shape for an
// ML-DSA-87 key (RFC 9881 section 4): AlgorithmIdentifier with absent
// parameters, then the raw public key as a BIT STRING.
type mldsaPKIXPublicKey struct {
	Algorithm mldsaAlgorithmIdentifier
	PublicKey asn1.BitString
}

// marshalMLDSA87SPKI builds the canonical DER SubjectPublicKeyInfo for an
// ML-DSA-87 key from its raw public key bytes, without calling
// crypto/x509.MarshalPKIXPublicKey (which would require constructing a
// *mldsa.PublicKey via crypto/mldsa, unavailable under ADR 0021's FIPS
// build) or crypto/mldsa at all. Used by parseTrustedKey (step-04a-review.md
// R4A-2) to require that a parsed key's declared DER was already in this
// one canonical form.
func marshalMLDSA87SPKI(rawKey []byte) ([]byte, error) {
	return asn1.Marshal(mldsaPKIXPublicKey{
		Algorithm: mldsaAlgorithmIdentifier{Algorithm: oidMLDSA87},
		PublicKey: asn1.BitString{Bytes: rawKey, BitLength: len(rawKey) * 8},
	})
}

// requireCanonicalECDSASPKI returns ErrNonCanonicalSPKI unless der is
// exactly x509.MarshalPKIXPublicKey(pub) (step-04a-review.md R4A-2).
// Go's x509.MarshalPKIXPublicKey always produces the same canonical DER
// for a given *ecdsa.PublicKey (RFC 5480's AlgorithmIdentifier.parameters
// is the curve OID; there is no other encoding freedom in that shape), and
// encoding/asn1 enforces minimal length/integer encoding (confirmed by
// TestLoadInitialRoot_NonMinimalLengthSPKIRejected), so no der this
// package's own parser accepts has ever been found to fail this check —
// it is a defensive invariant, exercised directly by
// TestRequireCanonicalECDSASPKI_RejectsMismatch with a hand-crafted,
// deliberately mismatched der (not reachable via parseTrustedKey's public
// entry point).
func requireCanonicalECDSASPKI(pub *ecdsa.PublicKey, der []byte) error {
	canonical, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || !bytes.Equal(canonical, der) {
		return fmt.Errorf("%w: keytype %q SPKI is not the canonical encoding of its own key", ErrNonCanonicalSPKI, KeyTypeECDSAP384)
	}
	return nil
}

// requireCanonicalMLDSA87SPKI returns ErrNonCanonicalSPKI unless der is
// exactly marshalMLDSA87SPKI(rawKey). See requireCanonicalECDSASPKI's doc
// comment: the same "defensive invariant, not reachable in practice"
// reasoning applies, exercised directly by
// TestRequireCanonicalMLDSA87SPKI_RejectsMismatch.
func requireCanonicalMLDSA87SPKI(rawKey, der []byte) error {
	canonical, err := marshalMLDSA87SPKI(rawKey)
	if err != nil || !bytes.Equal(canonical, der) {
		return fmt.Errorf("%w: keytype %q SPKI is not the canonical encoding of its own key", ErrNonCanonicalSPKI, KeyTypeMLDSA87)
	}
	return nil
}

// parseTrustedKey decodes der (a SubjectPublicKeyInfo) as declaredType and
// validates that its algorithm OID actually matches that declaration (step
// 4 prompt Part B1: "The keytype must match the SPKI's algorithm OID; a
// mismatch is malformed metadata"). It never constructs a *mldsa.PublicKey
// (see TrustedKey's doc comment); ecdsa-p384 keys are fully parsed, since
// doing so has no FIPS-module dependency.
func parseTrustedKey(declaredType KeyType, der []byte) (TrustedKey, error) {
	oid, params, rawKey, err := parseSPKIAlgorithm(der)
	if err != nil {
		return TrustedKey{}, fmt.Errorf("%w: %w", ErrMalformedMetadata, err)
	}

	switch declaredType {
	case KeyTypeECDSAP384:
		if !oid.Equal(oidECDSAPublicKey) {
			return TrustedKey{}, fmt.Errorf("%w: keytype %q but SPKI algorithm OID is %s", ErrKeytypeSPKIMismatch, declaredType, oid)
		}
		// Check the AlgorithmIdentifier's own named-curve parameter
		// directly (RFC 5480), rather than relying solely on
		// crypto/x509's parsed *ecdsa.PublicKey.Curve comparison below:
		// this rejects a declared-but-wrong EC curve (e.g. P-256) with
		// ErrKeytypeSPKIMismatch before ever constructing the key,
		// symmetric with the mldsa-87 branch's own OID-first check.
		var curveOID asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(params.FullBytes, &curveOID); err != nil || !curveOID.Equal(oidNamedCurveP384) {
			return TrustedKey{}, fmt.Errorf("%w: keytype %q but SPKI named curve is not P-384", ErrKeytypeSPKIMismatch, declaredType)
		}
		pubAny, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return TrustedKey{}, fmt.Errorf("%w: invalid DER: %w", ErrMalformedMetadata, err)
		}
		pub, ok := pubAny.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P384() {
			return TrustedKey{}, fmt.Errorf("%w: keytype %q is not ECDSA P-384", ErrKeytypeSPKIMismatch, declaredType)
		}
		// step-04a-review.md R4A-2: re-encode and require byte
		// equality with the provided DER (requireCanonicalECDSASPKI),
		// so two distinct encodings of the same key can never derive
		// two different key IDs (DeriveKeyIDFromDER hashes the DER
		// bytes as given) and slip past the A6 role-disjointness
		// check by counting as "different" keys.
		if err := requireCanonicalECDSASPKI(pub, der); err != nil {
			return TrustedKey{}, err
		}
		return TrustedKey{Type: KeyTypeECDSAP384, ecdsa: pub}, nil

	case KeyTypeMLDSA87:
		if !oid.Equal(oidMLDSA87) {
			return TrustedKey{}, fmt.Errorf("%w: keytype %q but SPKI algorithm OID is %s", ErrKeytypeSPKIMismatch, declaredType, oid)
		}
		// RFC 9881 section 4: ML-DSA SubjectPublicKeyInfo carries no
		// AlgorithmIdentifier parameters (absent, not NULL).
		if len(params.FullBytes) != 0 {
			return TrustedKey{}, fmt.Errorf("%w: mldsa-87 key has non-absent AlgorithmIdentifier parameters", ErrMalformedMetadata)
		}
		if len(rawKey) != mldsa.MLDSA87PublicKeySize {
			return TrustedKey{}, fmt.Errorf("%w: mldsa-87 public key is %d bytes, want %d", ErrKeytypeSPKIMismatch, len(rawKey), mldsa.MLDSA87PublicKeySize)
		}
		// step-04a-review.md R4A-2: re-encode via an explicitly built
		// SPKI (requireCanonicalMLDSA87SPKI; RFC 9881's OID, absent
		// parameters) and require byte equality with the provided
		// DER. Built by hand rather than via
		// crypto/x509.MarshalPKIXPublicKey, which for an ML-DSA key
		// calls crypto/mldsa internally (ADR 0021) and would
		// reintroduce the FIPS-build dependency parseTrustedKey
		// deliberately avoids for mldsa-87 (TrustedKey's doc comment).
		if err := requireCanonicalMLDSA87SPKI(rawKey, der); err != nil {
			return TrustedKey{}, err
		}
		return TrustedKey{Type: KeyTypeMLDSA87, mldsa: rawKey}, nil

	default:
		return TrustedKey{}, fmt.Errorf("%w: %q", ErrUnknownKeyType, declaredType)
	}
}

// verifySignature reports whether sig is a valid signature over pae under
// this key. It returns (false, non-nil error) only when the key's
// algorithm could not even be evaluated (step 4 prompt Part B2: ML-DSA
// unavailable in this build) — never for an ordinary invalid signature,
// which is (false, nil), the same convention dsse.VerifyECDSAP384 already
// uses.
func (k TrustedKey) verifySignature(pae, sig []byte) (bool, error) {
	switch k.Type {
	case KeyTypeECDSAP384:
		return dsse.VerifyECDSAP384(k.ecdsa, pae, sig), nil
	case KeyTypeMLDSA87:
		ok, err := dsse.VerifyMLDSA87(k.mldsa, pae, sig)
		if err != nil {
			return false, fmt.Errorf("%w: %w", ErrMLDSAUnavailable, err)
		}
		return ok, nil
	default:
		// Unreachable via any value produced by parseTrustedKey, which
		// never returns a TrustedKey with an unrecognized Type.
		return false, fmt.Errorf("%w: %q", ErrUnknownKeyType, k.Type)
	}
}
