package dsse

import (
	"crypto/mldsa"
	"fmt"
)

// mldsa87Options is the fixed, empty-context Options every ML-DSA-87
// verification in this project uses (step 4 prompt Part B2: "pure
// ML-DSA-87 ... using Go's crypto/mldsa, with an empty context string").
var mldsa87Options = &mldsa.Options{Context: ""}

// VerifyMLDSA87 verifies a pure (non-pre-hashed) ML-DSA-87 signature over
// pae, where rawPub is the raw ML-DSA-87 public key encoding (not a
// SubjectPublicKeyInfo DER; callers that have DER must extract the BIT
// STRING content first — see internal/trust's parseTrustedKey).
//
// It returns (false, non-nil error) only when the key itself could not be
// constructed — the one case this project must distinguish from "the
// signature just didn't verify", since it can mean crypto/mldsa is
// unavailable in this build (the FIPS 140-3 Go Cryptographic Module
// v1.0.0: crypto/mldsa's own doc comment, confirmed by reading
// mldsa_fips140v1.0.go directly, where NewPublicKey always returns a fixed
// error). An ordinary invalid signature is (false, nil), the same
// convention VerifyECDSAP384 uses.
//
// This is always the PURE ML-DSA-87 verification mode, never HashML-DSA
// (pre-hash): the package-level mldsa.Verify function used here has no
// hash-mode parameter at all (unlike mldsa.PrivateKey.Sign, which accepts
// crypto.SignerOpts and switches on opts.HashFunc() for the signing-only
// "External mu ML-DSA" variant, RFC 9881 section on external-mu signing).
// Reading crypto/mldsa's source (mldsa_fips140v1.26.go's package-level
// Verify) confirms it always calls the non-pre-hashed path with no branch
// for any other mode, so there is no way for a caller of this function to
// end up doing HashML-DSA verification even by mistake.
func VerifyMLDSA87(rawPub, pae, sig []byte) (bool, error) {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA87(), rawPub)
	if err != nil {
		return false, fmt.Errorf("dsse: construct ML-DSA-87 public key: %w", err)
	}
	if err := mldsa.Verify(pub, pae, sig, mldsa87Options); err != nil {
		return false, nil //nolint:nilerr // an invalid signature is (false, nil) by design, matching VerifyECDSAP384's convention; only key construction failure (above) is a reportable error
	}
	return true, nil
}
