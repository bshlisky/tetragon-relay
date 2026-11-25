package identity

import "errors"

var (
	// ErrEmptyChain is returned when an Enroller returns a chain with no
	// certificates at all.
	ErrEmptyChain = errors.New("identity: enroller returned an empty certificate chain")

	// ErrLeafKeyMismatch is returned when the returned leaf certificate's
	// public key does not equal the signer's public key: the Enroller
	// certified a different key than the one the CSR proved possession
	// of, which must never be trusted (B2: "leaf public key equals the
	// HostSigner's public key").
	ErrLeafKeyMismatch = errors.New("identity: leaf certificate public key does not match the signing key")

	// ErrURISANMismatch is returned when the leaf certificate's URI SAN
	// does not exactly equal the expected SPIFFE ID (B2).
	ErrURISANMismatch = errors.New("identity: leaf certificate URI SAN does not match the expected SPIFFE ID")

	// ErrMissingClientAuthEKU is returned when the leaf certificate does
	// not have the clientAuth EKU (B2; architecture doc 5.1: "EKU
	// clientAuth for hosts").
	ErrMissingClientAuthEKU = errors.New("identity: leaf certificate is missing the clientAuth EKU")

	// ErrNotYetValid is returned when the leaf certificate's NotBefore is
	// further in the future than the configured clock skew allows.
	ErrNotYetValid = errors.New("identity: leaf certificate is not yet valid")

	// ErrExpired is returned when the leaf certificate's NotAfter is at
	// or before the validation time.
	ErrExpired = errors.New("identity: leaf certificate is expired")

	// ErrTTLTooLong is returned when the leaf certificate's NotAfter
	// exceeds the configured maximum TTL from the validation time (B2:
	// "not after the configured maximum TTL").
	ErrTTLTooLong = errors.New("identity: leaf certificate validity window exceeds the configured maximum TTL")

	// ErrChainVerificationFailed is returned when the chain does not
	// verify against the configured enrollment trust bundle.
	ErrChainVerificationFailed = errors.New("identity: certificate chain does not verify against the enrollment trust bundle")

	// ErrNoPersistedChain is returned by Load when no certificate chain
	// has been persisted yet (distinct from a read/parse failure of an
	// existing file, which is a hard error, not "absent").
	ErrNoPersistedChain = errors.New("identity: no persisted certificate chain")
)
