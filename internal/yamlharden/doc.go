// Package yamlharden implements the hardened YAML ingestion rules every
// YAML document this project trusts must pass before any further parsing:
// valid UTF-8, no byte-order mark, no NUL/control bytes, no anchors,
// aliases, explicit tags or merge keys, bounded depth/node-count/scalar
// size, string-only non-duplicate mapping keys, and rejection of any
// unquoted scalar a YAML 1.1 parser would resolve differently than
// yaml.v3 does (ADR 0013, threat T-27) or that decodes (via an escape
// sequence) to a disallowed control or invisible Unicode character
// (architect review R2D-1).
//
// This package was extracted from internal/policydoc (step 2 prompt Part
// B1's original implementation) by docs/prompts/step-06a.md Part B2, so
// internal/config's relay.yaml ingestion can reuse the identical rules
// rather than duplicating them. internal/policydoc's Parse keeps its own
// exported error sentinels (internal/policydoc/errors.go) as aliases of
// this package's, so no caller of internal/policydoc observes any
// behavior change: Parse(raw) returns byte-for-byte the same hardened
// yaml.Node tree, under the same conditions, as internal/policydoc's own
// (now removed) copy did.
package yamlharden
