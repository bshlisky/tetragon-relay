//go:build testtools

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// testKey is a TEST-ONLY key pair (ECDSA P-384 or ML-DSA-87) plus its
// derived trust.KeyID. These keys are generated fresh on every run and are
// never used outside this tool's generated testdata/vectors fixtures.
// Exactly one of ecdsaPriv/mldsaPriv is set, matching keyType.
type testKey struct {
	id        string
	ecdsaPriv *ecdsa.PrivateKey
	mldsaPriv *mldsa.PrivateKey
	keyType   string // "ecdsa-p384" or "mldsa-87" normally; may be forced to a lie for vectors
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
		ecdsaPriv: priv,
		keyType:   declaredKeyType,
		publicB64: base64.StdEncoding.EncodeToString(der),
	}, nil
}

// newP384Key generates a standard, honestly-declared ECDSA P-384 test key.
func newP384Key() (*testKey, error) {
	return newKey(elliptic.P384(), "ecdsa-p384")
}

// newMLDSA87Key generates a standard, honestly-declared ML-DSA-87 test key
// (step 4 prompt Part B6: "cmd/bundlesign-test generates ML-DSA-87 test
// keys too").
func newMLDSA87Key() (*testKey, error) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, fmt.Errorf("generate mldsa-87 key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("marshal mldsa-87 public key: %w", err)
	}
	sum := sha256.Sum256(der)
	id := "sha256:" + hex.EncodeToString(sum[:])
	return &testKey{
		id:        id,
		mldsaPriv: priv,
		keyType:   "mldsa-87",
		publicB64: base64.StdEncoding.EncodeToString(der),
	}, nil
}

// sign produces a signature over pae matching this key's declared type:
// ASN.1 DER ECDSA over SHA-384 for ecdsa-p384 (internal/dsse.VerifyECDSAP384's
// expectations), or a pure (empty-context) ML-DSA-87 signature for
// mldsa-87 (internal/dsse.VerifyMLDSA87's expectations).
func (k *testKey) sign(pae []byte) ([]byte, error) {
	switch {
	case k.ecdsaPriv != nil:
		digest := sha512.Sum384(pae)
		return ecdsa.SignASN1(rand.Reader, k.ecdsaPriv, digest[:])
	case k.mldsaPriv != nil:
		return k.mldsaPriv.Sign(nil, pae, &mldsa.Options{Context: ""})
	default:
		return nil, fmt.Errorf("testKey %q has neither an ECDSA nor an ML-DSA private key", k.id)
	}
}
