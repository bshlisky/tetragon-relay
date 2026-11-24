// Package store implements the agent's crash-safe, tamper-evident
// persistent state (step-04b.md Part C; architecture doc sections 7.6,
// 7.7, 8.2, 8.4 and 8.10's "store" module).
//
// A Store holds, as of the last successfully committed generation:
//
//   - per-scope epochs (verify.EpochSource)
//   - per-scope monitor-mode policy-name history (guard.PolicyHistory)
//   - the last-known-good policy set per relay domain (apply.LKGStore)
//   - the current trust root's raw signed bytes and version
//   - a monotonically increasing generation number
//
// Large values (LKG sets, trust-root metadata) are stored as
// content-addressed files under blobs/ (name = hex SHA-256 of the bytes).
// A single small index file references them and carries an HMAC-SHA-384
// (internal/store/index.go) computed with a key from a KeySealer, so an
// offline edit (e.g. from rescue media) is detected at next Open. The
// index's generation is mirrored in a MonotonicCounter so an attacker
// cannot roll the store back to an older, validly-HMAC'd copy (step-04b.md
// Part C5).
//
// Deviation from architecture doc section 8.2/C2's literal "LKG: ... as
// raw DSSE bytes (never re-encoded)": apply.LKGStore (step 3,
// internal/apply/interfaces.go) is a fixed, already-accepted interface
// that only ever gives this package the already-verified, already-parsed
// LKGSet (policy name, version and canonical JSON per policy, plus mode)
// — never the raw DSSE envelope bytes, which the apply engine does not
// retain. This package therefore content-addresses the canonical JSON
// encoding of LKGSet as the blob instead of a raw envelope. This preserves
// every crash-safety and tamper-evidence property section 8.2 asks for
// (an immutable, hash-verified blob referenced by the index) at the
// LKGSet granularity rather than the raw-envelope granularity; see
// docs/reports/step-04b.md's Deviations section.
package store
