// Package strictjson implements the strict JSON decoding rules required by
// architecture doc section 7.4 step 5: reject unknown fields, reject
// duplicate keys at any nesting depth, bound nesting depth, require valid
// UTF-8, and reject trailing data after the top-level value.
//
// encoding/json's Decoder.DisallowUnknownFields rejects unknown fields but
// silently accepts duplicate object keys (last one wins), which would let an
// attacker smuggle a value past a naive reviewer or a downstream parser that
// disagrees about which duplicate "wins". This package adds a token-level
// pre-pass that walks the raw JSON and rejects duplicates and excessive
// depth before encoding/json ever sees the bytes.
//
// Security responsibility: this is the single, shared hardening layer for
// all attacker-controlled JSON parsed by internal/verify (bundle payloads)
// and internal/trust (root metadata payloads and envelopes), so the two
// packages cannot silently diverge on what counts as well-formed input.
//
// Invariants / threats addressed: INV-1 (verification must be exact, not
// best-effort); T-09 (compromised controller crafting an envelope to exploit
// parser disagreement).
package strictjson
