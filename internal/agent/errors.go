package agent

import "errors"

var (
	// ErrECDSASelfTestFailed is returned by RunCryptoSelfTest (and by
	// Startup, which refuses to start) when the embedded known-good
	// ECDSA P-384 test vector does not verify. Every production role
	// requires ecdsa-p384 (ADR 0022 Part B5), so this build cannot
	// usefully run at all.
	ErrECDSASelfTestFailed = errors.New("agent: ECDSA P-384 crypto self-test failed")

	// ErrMLDSAUnavailable is returned by VerifierFor when a role
	// requires mldsa-87 (trust.Role.RequireKeyTypes) but this build's
	// crypto self-test found ML-DSA-87 unavailable. Step-04a-review.md
	// R4A-3: named explicitly so an operator sees "ML-DSA unavailable
	// in this build," not a generic signature failure.
	ErrMLDSAUnavailable = errors.New("agent: ML-DSA unavailable in this build")

	// ErrStoreOpenFailed wraps a non-tamper failure opening
	// internal/store (e.g. the sealer or monotonic counter are not yet
	// available). Distinct from store.ErrTampered, which Startup
	// surfaces directly.
	ErrStoreOpenFailed = errors.New("agent: failed to open the persistent state store")

	// ErrNoTrustRoot is returned by Startup when the store holds no
	// persisted trust root and no initial root was configured (should
	// not occur in a correctly packaged install: the RPM always ships
	// one).
	ErrNoTrustRoot = errors.New("agent: no trust root available")

	// ErrInitialRootInvalid is returned by Startup when the
	// RPM-shipped initial root (used at first boot, or considered as a
	// forward move at every subsequent boot per Part C7) fails to
	// parse or self-verify.
	ErrInitialRootInvalid = errors.New("agent: RPM-shipped initial trust root is invalid")

	// ErrTooManyRootFiles is returned by Startup when
	// Config.AvailableRPMRoots has more than limits.MaxRootChainFiles
	// entries (step-04b-review.md R4B-1: "bound the number of files
	// read"). This is a configuration error (the caller is expected to
	// have already bounded how many files it ever reads from
	// /etc/tetragon-relay/trust/roots/), not a security decision this
	// package makes silently by truncating the set.
	ErrTooManyRootFiles = errors.New("agent: too many RPM-shipped root files configured")
)
