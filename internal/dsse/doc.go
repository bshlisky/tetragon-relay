// Package dsse implements the minimal subset of the Dead Simple Signing
// Envelope (DSSE, https://github.com/secure-systems-lab/dsse) format needed
// by this project: envelope parsing per architecture doc section 7.3 and the
// Pre-Authentication Encoding (PAE) used to compute what gets signed,
// per section 7.4 step 3.
//
// This is a hand-rolled, reviewable subset rather than a dependency: the
// envelope shape is small and fixed (payloadType, base64 payload, one or
// more {keyid, sig} signatures), and both internal/trust (root metadata)
// and internal/verify (policy bundles) need identical, non-divergent parsing
// of that shape plus identical PAE construction and ECDSA-P384 signature
// verification. See docs/decisions/0001-dependencies.md.
//
// This package performs no key management and no trust decisions; it only
// parses envelopes and verifies raw ECDSA signatures against a supplied
// public key. internal/trust decides which keys and thresholds are
// authoritative.
//
// Invariants / threats addressed: INV-1 (signature verification must use
// the exact, unambiguous bytes that were signed); T-07 (replay),
// T-09 (compromised controller forging envelopes).
package dsse
