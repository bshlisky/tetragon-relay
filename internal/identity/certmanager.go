package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"
)

// CertManager builds a CSR from a crypto.Signer (production:
// *tpm.HostSigner), exchanges it for a certificate chain through an
// Enroller, and validates every property of the returned chain itself
// (docs/prompts/step-05b.md B2). It never trusts an Enroller's own
// judgment about whether a chain is well-formed, matching this project's
// "no silent fallbacks" rule.
//
// CertManager does not import internal/tpm: it takes a crypto.Signer, so
// it can be built and tested without any TPM dependency, the same
// decoupling internal/tpm.HostSigner itself already has from
// internal/agent's wiring (step 5a).
type CertManager struct {
	cfg      Config
	signer   crypto.Signer
	enroller Enroller
	chain    []*x509.Certificate
}

// NewCertManager constructs a CertManager. It does not enroll or load a
// chain itself; call Load (to pick up a previously persisted chain) or
// Enroll (to obtain a new one) after construction.
func NewCertManager(cfg Config, signer crypto.Signer, enroller Enroller) (*CertManager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, fmt.Errorf("identity: signer is nil")
	}
	if enroller == nil {
		return nil, fmt.Errorf("identity: enroller is nil")
	}
	return &CertManager{cfg: cfg, signer: signer, enroller: enroller}, nil
}

// Chain returns the currently active certificate chain, or nil if none
// has been enrolled or loaded yet.
func (m *CertManager) Chain() []*x509.Certificate { return m.chain }

// Enroll builds a CSR from m's signer, exchanges it with the configured
// Enroller, validates the returned chain against now, persists it (public
// data only; the private key never leaves the TPM), and makes it the
// active chain. On any validation failure, the previously active chain
// (if any) is left untouched.
func (m *CertManager) Enroll(ctx context.Context, now time.Time) ([]*x509.Certificate, error) {
	chain, err := m.enrollWithSigner(ctx, m.signer, now)
	if err != nil {
		return nil, err
	}
	m.chain = chain
	return chain, nil
}

// Rotate enrolls newSigner (a brand-new TPM key, independently created by
// the caller -- e.g. internal/tpm.RotateHostSigner -- since CertManager
// itself has no TPM dependency) under a fresh CSR and certificate. On
// success, m's active signer and chain switch to the new key/chain; the
// caller is responsible for retiring the OLD TPM key blob only after this
// returns successfully (B2: "the old key is retired only after the new
// certificate is in use" -- matching internal/tpm.HostSigner.
// RetireHostSigner's own "nothing calls this automatically" contract).
func (m *CertManager) Rotate(ctx context.Context, now time.Time, newSigner crypto.Signer) ([]*x509.Certificate, error) {
	if newSigner == nil {
		return nil, fmt.Errorf("identity: new signer is nil")
	}
	chain, err := m.enrollWithSigner(ctx, newSigner, now)
	if err != nil {
		return nil, err
	}
	m.signer = newSigner
	m.chain = chain
	return chain, nil
}

func (m *CertManager) enrollWithSigner(ctx context.Context, signer crypto.Signer, now time.Time) ([]*x509.Certificate, error) {
	csr, err := BuildCSR(signer, m.cfg)
	if err != nil {
		return nil, err
	}
	chain, err := m.enroller.Enroll(ctx, csr)
	if err != nil {
		return nil, fmt.Errorf("identity: enroll: %w", err)
	}
	if err := m.validateChain(chain, signer, now); err != nil {
		return nil, err
	}
	if err := persistChain(m.cfg.StoreDir, chain); err != nil {
		return nil, err
	}
	return chain, nil
}

// validateChain implements every rejection B2 lists. Checks run in a
// fixed order so a given malformed chain always fails with the same,
// specific error (easier to test and to diagnose from an operator's
// perspective) rather than whichever check happens to run first.
func (m *CertManager) validateChain(chain []*x509.Certificate, signer crypto.Signer, now time.Time) error {
	if len(chain) == 0 {
		return ErrEmptyChain
	}
	leaf := chain[0]

	signerPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("identity: signer public key is %T, want *ecdsa.PublicKey", signer.Public())
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafPub.Equal(signerPub) {
		return ErrLeafKeyMismatch
	}

	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != m.cfg.HostSPIFFEID() {
		return ErrURISANMismatch
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return ErrURISANMismatch
	}

	if !hasClientAuthEKU(leaf) {
		return ErrMissingClientAuthEKU
	}

	if leaf.NotBefore.After(now.Add(m.cfg.ClockSkew)) {
		return ErrNotYetValid
	}
	if !leaf.NotAfter.After(now) {
		return ErrExpired
	}
	if leaf.NotAfter.After(now.Add(m.cfg.MaxCertTTL)) {
		return ErrTTLTooLong
	}

	pool := x509.NewCertPool()
	for _, c := range m.cfg.EnrollmentTrustBundle {
		pool.AddCert(c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrChainVerificationFailed, err)
	}
	return nil
}

func hasClientAuthEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

// RenewAt returns the time at which renewal should be attempted: 50% of
// leaf's lifetime (architecture doc 5.4; B2).
func RenewAt(leaf *x509.Certificate) time.Time {
	half := leaf.NotAfter.Sub(leaf.NotBefore) / 2
	return leaf.NotBefore.Add(half)
}

// ShouldRenew reports whether now has reached leaf's renewal point.
func ShouldRenew(leaf *x509.Certificate, now time.Time) bool {
	return !now.Before(RenewAt(leaf))
}

// ExpiringSoonThreshold is B2's "under 15 minutes left" threshold for
// reporting the identity as expiring soon, so the agent state machine can
// enter DEGRADED (step 6; architecture doc 8.4).
const ExpiringSoonThreshold = 15 * time.Minute

// ExpiringSoon reports whether leaf has under ExpiringSoonThreshold left
// at now.
func ExpiringSoon(leaf *x509.Certificate, now time.Time) bool {
	return leaf.NotAfter.Sub(now) < ExpiringSoonThreshold
}
