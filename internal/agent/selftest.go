package agent

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
)

// Capabilities records what this build's crypto self-test (step-04a-
// review.md R4A-3) found available, as of agent startup.
type Capabilities struct {
	// MLDSAAvailable is true if the embedded known-good ML-DSA-87 test
	// vector verified. False means this build's crypto/mldsa is
	// unavailable (e.g. the FIPS 140-3 Go Cryptographic Module v1.0.0,
	// ADR 0021) or otherwise broken.
	MLDSAAvailable bool
	// MLDSAErr is the error RunCryptoSelfTest observed from the
	// ML-DSA-87 vector, for logging/audit, or nil if MLDSAAvailable.
	MLDSAErr error
}

// RunCryptoSelfTest verifies an embedded known-good ECDSA P-384 signature
// and an embedded known-good ML-DSA-87 signature (step-04b.md Part D2
// step 1 / step-04a-review.md R4A-3). It returns ErrECDSASelfTestFailed if
// the ECDSA vector does not verify — every production trust-root role
// requires ecdsa-p384 (ADR 0022 Part B5), so a build that cannot even
// verify a known-good ECDSA signature cannot usefully start at all. The
// ML-DSA-87 vector's outcome is never an error return: it is recorded in
// the returned Capabilities so a role that happens to require mldsa-87
// (none do today) can be rejected with a named, typed reason instead of
// an opaque signature failure (see VerifierFor).
func RunCryptoSelfTest() (Capabilities, error) {
	return runCryptoSelfTest(selfTestMessageB64, selfTestECDSAPubDERB64, selfTestECDSASigB64, selfTestMLDSA87RawPubB64, selfTestMLDSA87SigB64)
}

// runCryptoSelfTest is RunCryptoSelfTest parameterized over its vectors,
// so tests can exercise the ECDSA-failure and ML-DSA-failure branches with
// a deliberately broken vector; RunCryptoSelfTest always calls it with the
// real embedded constants.
func runCryptoSelfTest(msgB64, ecdsaPubB64, ecdsaSigB64, mldsaPubB64, mldsaSigB64 string) (Capabilities, error) {
	if err := verifyECDSASelfTest(msgB64, ecdsaPubB64, ecdsaSigB64); err != nil {
		return Capabilities{}, fmt.Errorf("%w: %w", ErrECDSASelfTestFailed, err)
	}

	caps := Capabilities{}
	if err := verifyMLDSASelfTest(msgB64, mldsaPubB64, mldsaSigB64); err != nil {
		caps.MLDSAErr = err
	} else {
		caps.MLDSAAvailable = true
	}
	return caps, nil
}

// verifyECDSASelfTest and verifyMLDSASelfTest take their vector as
// explicit base64 parameters (rather than reading the selfTest* constants
// directly) purely so tests can exercise their decode/verify-failure
// branches with a deliberately broken vector; RunCryptoSelfTest always
// calls them with the real embedded constants.
func verifyECDSASelfTest(msgB64, pubDERB64, sigB64 string) error {
	msg, err := base64.StdEncoding.DecodeString(msgB64)
	if err != nil {
		return fmt.Errorf("decode embedded message: %w", err)
	}
	der, err := base64.StdEncoding.DecodeString(pubDERB64)
	if err != nil {
		return fmt.Errorf("decode embedded ECDSA public key: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode embedded ECDSA signature: %w", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("parse embedded ECDSA public key: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("embedded public key is not ECDSA")
	}
	if !dsse.VerifyECDSAP384(pub, msg, sig) {
		return fmt.Errorf("embedded known-good ECDSA P-384 signature did not verify")
	}
	return nil
}

func verifyMLDSASelfTest(msgB64, rawPubB64, sigB64 string) error {
	msg, err := base64.StdEncoding.DecodeString(msgB64)
	if err != nil {
		return fmt.Errorf("decode embedded message: %w", err)
	}
	rawPub, err := base64.StdEncoding.DecodeString(rawPubB64)
	if err != nil {
		return fmt.Errorf("decode embedded ML-DSA-87 public key: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode embedded ML-DSA-87 signature: %w", err)
	}
	ok, err := dsse.VerifyMLDSA87(rawPub, msg, sig)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("embedded known-good ML-DSA-87 signature did not verify")
	}
	return nil
}
