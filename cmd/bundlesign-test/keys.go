//go:build testtools

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// testKey is a TEST-ONLY ECDSA key pair plus its derived trust.KeyID. These
// keys are generated fresh on every run and are never used outside this
// tool's generated testdata/vectors fixtures.
type testKey struct {
	id        string
	curve     elliptic.Curve
	priv      *ecdsa.PrivateKey
	keyType   string // "ecdsa-p384" normally; may be forced to a lie for vectors
	publicB64 string
}

func newKey(curve elliptic.Curve, declaredKeyType string) (*testKey, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	id := "sha256:" + hex.EncodeToString(sum[:])
	return &testKey{
		id:        id,
		curve:     curve,
		priv:      priv,
		keyType:   declaredKeyType,
		publicB64: base64.StdEncoding.EncodeToString(der),
	}, nil
}

// newP384Key generates a standard, honestly-declared ECDSA P-384 test key.
func newP384Key() (*testKey, error) {
	return newKey(elliptic.P384(), "ecdsa-p384")
}

// sign produces an ASN.1 DER ECDSA signature over pae using SHA-384,
// matching internal/dsse.VerifyECDSAP384's expectations exactly.
func (k *testKey) sign(pae []byte) ([]byte, error) {
	digest := sha512.Sum384(pae)
	return ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
}
