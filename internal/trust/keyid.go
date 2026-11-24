package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// KeyID identifies a public key: the lowercase hex SHA-256 digest of its
// DER-encoded SubjectPublicKeyInfo, prefixed "sha256:". Step 4 prompt Part
// B1: this formula is unchanged for every key type, ecdsa-p384 or
// mldsa-87 alike.
type KeyID string

// DeriveKeyIDFromDER computes the KeyID for a SubjectPublicKeyInfo-encoded
// public key, for any key type: just the SHA-256 of the raw DER bytes.
// Unlike DeriveKeyID, this never inspects or validates the key's own
// algorithm (internal/trust's own parsing path does that separately, via
// parseTrustedKey, before ever calling this) and never fails.
func DeriveKeyIDFromDER(der []byte) KeyID {
	sum := sha256.Sum256(der)
	return KeyID("sha256:" + hex.EncodeToString(sum[:]))
}

// DeriveKeyID computes the KeyID for pub. It returns ErrUnsupportedKeyType
// for any key that is not ECDSA P-384.
func DeriveKeyID(pub *ecdsa.PublicKey) (KeyID, error) {
	if pub == nil || pub.Curve != elliptic.P384() {
		return "", ErrUnsupportedKeyType
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("trust: marshal public key: %w", err)
	}
	return DeriveKeyIDFromDER(der), nil
}
