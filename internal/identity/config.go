package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// Config is everything CertManager needs beyond the TPM signer and the
// Enroller. It carries no secrets: the enrollment trust bundle and the
// host's own identity are both public.
type Config struct {
	// TrustDomain is the SPIFFE trust domain, architecture doc 5.1:
	// "spiffe://mgmt.<customer>.internal" -- this field holds just
	// "mgmt.<customer>.internal", without the scheme.
	TrustDomain string
	// HostUUID is assigned at inventory registration (architecture doc
	// 5.1) and never derived from the hostname. As of this step, no
	// config loader or host-facts field in this repository carries it
	// yet (internal/hostprobe.HostFacts has no host_uuid field; see
	// docs/reports/step-05b.md section 9 for where this is cited as an
	// open question) -- the caller (relayd's main, step 6) is
	// responsible for sourcing it and passing it in here.
	HostUUID string
	// EnrollmentTrustBundle is the set of CA certificates a returned
	// chain must verify against. This is a SEPARATE trust domain from
	// the policy trust root (architecture doc section 5: "Two separate
	// trust domains are kept").
	EnrollmentTrustBundle []*x509.Certificate
	// MaxCertTTL bounds how far in the future a returned certificate's
	// NotAfter may be; a chain whose leaf NotAfter exceeds
	// now+MaxCertTTL is rejected (B2: "not after the configured maximum
	// TTL").
	MaxCertTTL time.Duration
	// ClockSkew bounds how far in the future a returned certificate's
	// NotBefore may be; a chain whose leaf NotBefore is after
	// now+ClockSkew is rejected (B2: "not before now - skew" --
	// expressed here as the allowance on the other side of "now", the
	// only direction that can actually be validated without knowing the
	// signer's own clock skew budget, see Validate's doc comment).
	ClockSkew time.Duration
	// StoreDir is the directory the certificate chain (never the
	// private key, which stays in the TPM) is persisted under
	// (architecture doc 8.5, inside /var/lib/tetragon-relay/).
	StoreDir string
	// RotationInterval is how often CertManager generates a brand-new
	// TPM key and re-enrolls under it (B2: "default 7 days", matching
	// architecture doc 5.4's host key rotation cadence).
	RotationInterval time.Duration
}

// DefaultRotationInterval is architecture doc 5.4's host key rotation
// cadence, used when Config.RotationInterval is zero.
const DefaultRotationInterval = 7 * 24 * time.Hour

var (
	// ErrEmptyTrustDomain is returned by Config.Validate when TrustDomain is empty.
	ErrEmptyTrustDomain = errors.New("identity: config: trust domain is empty")
	// ErrEmptyHostUUID is returned by Config.Validate when HostUUID is empty.
	ErrEmptyHostUUID = errors.New("identity: config: host UUID is empty")
	// ErrEmptyEnrollmentBundle is returned by Config.Validate when EnrollmentTrustBundle is empty.
	ErrEmptyEnrollmentBundle = errors.New("identity: config: enrollment trust bundle is empty")
	// ErrNonPositiveMaxCertTTL is returned by Config.Validate when MaxCertTTL is not positive.
	ErrNonPositiveMaxCertTTL = errors.New("identity: config: max cert TTL must be positive")
	// ErrNegativeClockSkew is returned by Config.Validate when ClockSkew is negative.
	ErrNegativeClockSkew = errors.New("identity: config: clock skew must not be negative")
	// ErrEmptyStoreDir is returned by Config.Validate when StoreDir is empty.
	ErrEmptyStoreDir = errors.New("identity: config: store directory is empty")
	// ErrNonPositiveRotationInt is returned by Config.Validate when RotationInterval is negative.
	ErrNonPositiveRotationInt = errors.New("identity: config: rotation interval must be positive")
)

// Validate rejects any configuration whose zero value would silently
// disable a security check (the project's "secure zero values" rule):
// an empty trust bundle would make chain verification vacuous, an empty
// host UUID would build a meaningless SPIFFE ID, a non-positive MaxCertTTL
// would reject every chain, a negative ClockSkew is nonsensical.
func (c Config) Validate() error {
	if c.TrustDomain == "" {
		return ErrEmptyTrustDomain
	}
	if c.HostUUID == "" {
		return ErrEmptyHostUUID
	}
	if len(c.EnrollmentTrustBundle) == 0 {
		return ErrEmptyEnrollmentBundle
	}
	if c.MaxCertTTL <= 0 {
		return ErrNonPositiveMaxCertTTL
	}
	if c.ClockSkew < 0 {
		return ErrNegativeClockSkew
	}
	if c.StoreDir == "" {
		return ErrEmptyStoreDir
	}
	if c.RotationInterval < 0 {
		return ErrNonPositiveRotationInt
	}
	return nil
}

// rotationInterval returns Config.RotationInterval, or
// DefaultRotationInterval if it is zero.
func (c Config) rotationInterval() time.Duration {
	if c.RotationInterval == 0 {
		return DefaultRotationInterval
	}
	return c.RotationInterval
}

// HostSPIFFEID returns this host's SPIFFE ID (architecture doc 5.1:
// "spiffe://<trust-domain>/host/<host-uuid>").
func (c Config) HostSPIFFEID() string {
	return fmt.Sprintf("spiffe://%s/host/%s", c.TrustDomain, c.HostUUID)
}
