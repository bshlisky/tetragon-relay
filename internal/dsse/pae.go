package dsse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"strconv"
)

// PAE computes the DSSE v1 Pre-Authentication Encoding of (payloadType,
// payload):
//
//	PAE = "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
//
// where SP is a single space and len(...) is the ASCII decimal encoding of
// the byte length of the field that follows. Explicit length prefixes make
// the encoding unambiguous: without them, ("ab", "c") and ("a", "bc") would
// produce the same concatenated bytes and the same signature would verify
// for either split.
func PAE(payloadType string, payload []byte) []byte {
	out := make([]byte, 0, len(payloadType)+len(payload)+32)
	out = append(out, "DSSEv1 "...)
	out = append(out, strconv.Itoa(len(payloadType))...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(payload))...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// VerifyECDSAP384 verifies an ASN.1 DER-encoded ECDSA signature over pae
// using pub, which must be a P-384 key. The message is hashed with SHA-384
// before verification, matching the curve's security strength.
//
// It returns false (never an error) for any non-P-384 key, any malformed
// signature, or any signature that does not verify; callers must treat
// "false" as "reject", never as "retry" or "assume valid".
func VerifyECDSAP384(pub *ecdsa.PublicKey, pae []byte, sigDER []byte) bool {
	if pub == nil || pub.Curve != elliptic.P384() {
		return false
	}
	digest := sha512.Sum384(pae)
	return ecdsa.VerifyASN1(pub, digest[:], sigDER)
}
