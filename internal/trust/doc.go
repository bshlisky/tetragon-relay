// Package trust implements the TUF-style trust-root metadata model from
// architecture doc section 7.6: the set of ECDSA P-384 keys and per-role
// thresholds (root, targets, log) that a host pins, and the rules for
// rotating that metadata without ever accepting a downgrade, replay, or a
// root update that was not jointly authorized by both the outgoing and
// incoming root key sets.
//
// This package never decides whether a *policy bundle* is acceptable; it
// only answers "is this the metadata we trust" and "does this signature set
// meet a role's threshold". internal/verify uses the Verifier returned by
// (*Root).TargetsVerifier to check bundle signatures.
//
// Security responsibility: the trust root is the only thing standing
// between a compromised controller and kernel-level policy on every host
// (INV-4: the controller cannot produce a signature the agent accepts).
// This package must never accept root metadata that has not been
// authenticated by a threshold of keys that were themselves already
// trusted, and must never go backwards in version or accept expired
// metadata as current.
//
// Invariants addressed: INV-1 (signature/threshold is the basis of policy
// acceptance), INV-4 (controller compromise cannot forge a valid signer),
// T-13 (signing key stolen; root metadata is how a stolen key is revoked),
// T-24 (trust-root rollback or freeze).
package trust
