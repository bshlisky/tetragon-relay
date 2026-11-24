package trust

import "errors"

var (
	// ErrUnsupportedKeyType is returned for any key that is not ECDSA on
	// the P-384 curve.
	ErrUnsupportedKeyType = errors.New("trust: unsupported key type (only ECDSA P-384 is accepted)")

	// ErrKeyIDMismatch is returned when a key's declared ID in root
	// metadata does not match the ID derived from its public key bytes.
	ErrKeyIDMismatch = errors.New("trust: declared key ID does not match derived key ID")

	// ErrInvalidRoleDefinition is returned when a role's threshold or
	// key-ID list is structurally invalid (threshold < 1, threshold >
	// len(keyids), duplicate key IDs, or a key ID not present in the
	// metadata's key set).
	ErrInvalidRoleDefinition = errors.New("trust: invalid role definition")

	// ErrPayloadTypeMismatch is returned when a root envelope's
	// payloadType is not the expected root-metadata media type.
	ErrPayloadTypeMismatch = errors.New("trust: unexpected payload type")

	// ErrThresholdNotMet is returned when the number of distinct,
	// successfully verified signatures from keys listed in a role is
	// below that role's threshold.
	ErrThresholdNotMet = errors.New("trust: signature threshold not met")

	// ErrOldThresholdNotMet is returned by Update specifically when the
	// outgoing root key set's threshold is not met, to distinguish it
	// from ErrNewThresholdNotMet for callers and tests.
	ErrOldThresholdNotMet = errors.New("trust: root update not signed by threshold of outgoing root keys")

	// ErrNewThresholdNotMet is returned by Update specifically when the
	// incoming root key set's threshold is not met.
	ErrNewThresholdNotMet = errors.New("trust: root update not signed by threshold of incoming root keys")

	// ErrVersionRollback is returned when a root update's version is not
	// greater than the current version.
	ErrVersionRollback = errors.New("trust: root update version is not greater than current version")

	// ErrVersionSkip is returned when a root update's version skips
	// ahead by more than one.
	ErrVersionSkip = errors.New("trust: root update version must be exactly current version + 1")

	// ErrExpiredMetadata is returned when a root update's own expiry is
	// already in the past at the time it would be accepted.
	ErrExpiredMetadata = errors.New("trust: new root metadata is already expired")

	// ErrRootMetadataExpired is returned by TargetsVerifier when the
	// current root metadata has expired as of the supplied time.
	ErrRootMetadataExpired = errors.New("trust: root metadata has expired")

	// ErrMalformedMetadata is returned for any structurally invalid root
	// metadata payload (missing fields, invalid JSON shape).
	ErrMalformedMetadata = errors.New("trust: malformed root metadata payload")

	// ErrRootValidityTooLong is returned by Update when a candidate root
	// metadata's expiry is further than limits.MaxRootValidity from the
	// time Update is called. The initial root loaded by LoadInitialRoot
	// is exempt (there is no "now" to compare against at build time).
	ErrRootValidityTooLong = errors.New("trust: root metadata validity window exceeds maximum")

	// ErrUnknownKeyType is returned when a key entry's keytype string
	// (or a role's require_keytypes entry) is not one of the known
	// values ("ecdsa-p384", "mldsa-87"). Step 4 prompt Part B1: unknown
	// keytype values are malformed metadata, never ignored.
	ErrUnknownKeyType = errors.New("trust: unknown key type")

	// ErrKeytypeSPKIMismatch is returned when a key entry's declared
	// keytype does not match its SubjectPublicKeyInfo's actual algorithm
	// OID (or curve, for ecdsa-p384; or size, for mldsa-87). Step 4
	// prompt Part B1.
	ErrKeytypeSPKIMismatch = errors.New("trust: declared keytype does not match SPKI algorithm")

	// ErrMLDSAUnavailable is returned when an mldsa-87 signature cannot
	// be evaluated because this build lacks crypto/mldsa support (the
	// FIPS 140-3 Go Cryptographic Module v1.0.0; ADR 0021) or, defensively,
	// any other failure constructing the key at verification time. Every
	// mldsa-87 signature fails verification (fail closed) when this
	// occurs; it is never treated as "skip this key". Step 4 prompt Part
	// B2.
	ErrMLDSAUnavailable = errors.New("trust: ML-DSA is unavailable in this build")

	// ErrInvalidRequireKeyTypes is returned when a role's
	// require_keytypes list is empty-but-present-in-JSON (as opposed to
	// omitted), contains an unknown or duplicate keytype, or lists a
	// keytype with no key of that type present in the role. Step 4
	// prompt Part B3.
	ErrInvalidRequireKeyTypes = errors.New("trust: invalid require_keytypes")
)
