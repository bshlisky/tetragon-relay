# ADR 0004: Root metadata wire format

## Status

Accepted.

## Context

Architecture doc section 7.6 specifies the TUF role model (root, targets,
log roles; a threshold per role; version-monotonic rotation signed by both
old and new root key thresholds; 365-day root expiry) but does not specify a
concrete JSON wire format for the root metadata payload the way section 7.3
specifies the bundle payload JSON shape in full, with an example.

## Decision

The root metadata payload (the base64-decoded `payload` field of a DSSE
envelope whose `payloadType` is `application/vnd.relay.root.v1+json`) is:

```json
{
  "schema": "relay.root.v1",
  "version": 1,
  "expires": "2027-11-21T00:00:00Z",
  "keys": {
    "sha256:<hex>": { "keytype": "ecdsa-p384", "public_key_der_b64": "<base64 DER SPKI>" }
  },
  "roles": {
    "root":    { "keyids": ["sha256:..."], "threshold": 2 },
    "targets": { "keyids": ["sha256:..."], "threshold": 1 },
    "log":     { "keyids": ["sha256:..."], "threshold": 1 }
  },
  "require_log_proof": false
}
```

This mirrors the shape of the bundle payload (section 7.3) for consistency:
a `schema` discriminator, explicit versioning, and role/key structures that
map directly onto `internal/trust.Roles` and `internal/trust.Role`.

`require_log_proof` is an addition not specified anywhere in the
architecture doc; it exists so `internal/verify` has something concrete to
read for "trust.require_log_proof" (architecture doc section 7.4 step 4).
See docs/reports/step-01.md, Open questions, for the gap this fills.

## Consequences

- This format is internal to this codebase; the real controller/signer
  implementation (out of scope for this step) will need to produce metadata
  in exactly this shape, or this ADR and the parsing code must be updated
  together.
- `internal/trust`'s wire structs (`rootPayload`, `keyEntry`, `rolePayload`,
  `rolesPayload` in `internal/trust/types.go`) are the single source of
  truth for this shape; `cmd/bundlesign-test` and the `_test.go` helper
  files in `internal/trust` and `internal/verify` each duplicate a minimal,
  independent copy of this shape for generating test fixtures (see
  testdata/vectors/README.md for why that duplication is deliberate).
