// Package verify implements the bundle verification algorithm specified in
// architecture doc section 7.4, exactly and in the order given there. This
// is the single place on a host where a policy bundle is accepted or
// rejected; every other component (apply, in a later step) only acts on a
// Result with Code == Accept.
//
// The package is pure: Verify performs no I/O, consults no global state, and
// logs nothing. All inputs — the time, the host's identity and allowed
// scopes, the trust verifier, the current epoch, the Tetragon version, and
// the guardrail checker — are supplied explicitly by the caller. This makes
// the function deterministic and fuzzable, and means a bug here cannot be
// masked by environment-dependent behavior.
//
// Security responsibility: no TracingPolicy bundle is ever treated as
// acceptable unless it passes every check in this package, in this order.
// The first failing check determines the result; later checks are not
// consulted, and their failure (or success) must not change behavior once
// an earlier check has already rejected.
//
// Invariants / threats addressed: INV-1 (signature, target, epoch, expiry
// before any policy is honored), T-07 (replay / downgrade via epoch),
// T-08 (cross-host bundle replay via target binding), T-09 (compromised
// controller forging envelopes; it cannot produce a valid signature),
// T-13 (stolen signing key; mitigated one layer up in internal/trust, but
// this package is what actually calls into it), T-24 (trust-root rollback;
// mitigated by internal/trust, surfaced here as a REJECTED_SIGNATURE when a
// Verifier cannot be obtained from expired metadata).
package verify
