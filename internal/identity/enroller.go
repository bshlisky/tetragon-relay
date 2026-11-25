package identity

import (
	"context"
	"crypto/x509"
)

// Enroller exchanges proof of identity plus a CSR signed by the TPM
// HostSigner for a certificate chain. It never receives or generates a
// private key (docs/prompts/step-05b.md Part B1; docs/decisions/0030-
// enroller-must-certify-tpm-held-key.md explains why this interface shape
// is itself the enforcement mechanism for "no software-generated SVID").
//
// chain[0] must be the leaf certificate for the key that signed csr;
// chain[1:] are the intermediate(s) needed to verify chain[0] against the
// caller's configured enrollment trust bundle (Config.EnrollmentTrustBundle).
// Enroll does not need to return the trust bundle itself; CertManager
// already has it from configuration.
type Enroller interface {
	Enroll(ctx context.Context, csr []byte) (chain []*x509.Certificate, err error)
}
