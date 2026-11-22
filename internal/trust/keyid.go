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
// DER-encoded SubjectPublicKeyInfo, prefixed "sha256:".
type KeyID string

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
	sum := sha256.Sum256(der)
	return KeyID("sha256:" + hex.EncodeToString(sum[:])), nil
}
