package agent

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/identity"
)

// chainHolder is the subset of *identity.CertManager RealIdentityRotator
// needs, so it can be tested without a real TPM-backed signer.
type chainHolder interface {
	Chain() []*x509.Certificate
}

// RealIdentityRotator implements IdentityRotator from a real
// *identity.CertManager (relayd's production wiring, Part C).
type RealIdentityRotator struct {
	CertManager chainHolder
}

// ExpiringSoon implements IdentityRotator using
// identity.ExpiringSoon/ExpiringSoonThreshold against the active chain's
// leaf. Reports false (never expiring) if there is no active chain at
// all -- a host with no identity cannot be "expiring", it is simply
// UNENROLLED, a different condition the state machine already models.
func (r *RealIdentityRotator) ExpiringSoon(now time.Time) bool {
	chain := r.CertManager.Chain()
	if len(chain) == 0 {
		return false
	}
	return identity.ExpiringSoon(chain[0], now)
}

// Rotate implements IdentityRotator. Left unimplemented pending a
// concrete internal/tpm.RotateHostSigner wiring decision (this package
// does not import internal/tpm, matching identity.CertManager's own
// decoupling); returns a named error rather than panicking or silently
// no-opping, so a RotateIdentity request is audited (ControlLoop already
// does this) but never pretends to have succeeded.
func (r *RealIdentityRotator) Rotate(context.Context) error {
	return fmt.Errorf("agent: identity rotation wiring is not implemented in this step (step 6a); RotateIdentity requests are audited but not yet acted on")
}
