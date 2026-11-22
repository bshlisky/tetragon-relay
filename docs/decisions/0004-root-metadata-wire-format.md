# ADR 0004: Root metadata wire format

## Status

Accepted, amended by the step 1 architect review (item A6); amendments
below.

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

## Amendments (step 1 review, item A6)

Three additional rules, enforced in `internal/trust/root.go`, without
changing the wire shape above:

1. **Pairwise-disjoint roles.** No key ID may appear in more than one of
   `roles.root`, `roles.targets`, `roles.log`. A key that could act in more
   than one role would collapse the separation of authority the three-role
   model exists to provide — e.g. a single stolen targets key could then
   also rotate the root. Enforced by `requireDisjointRoles` inside
   `parseAndValidatePayload`, so it applies to both `LoadInitialRoot` and
   `Update`. Violations return `ErrInvalidRoleDefinition`.
2. **Maximum root validity at rotation time.** `(*Root).Update` rejects a
   candidate whose `expires` is more than `limits.MaxRootValidity` (400
   days) past the `now` it is called with (`ErrRootValidityTooLong`). The
   *initial* root loaded by `LoadInitialRoot` is exempt: there is no "now"
   available at RPM build time to compare against, and architecture doc
   section 7.6 already fixes its validity at 365 days by convention, not by
   code in this package. This amendment only bounds how far a *rotation*
   can push validity into the future.
3. **Immutability.** `Root.keys` and `Root.roles` are unexported; `KeyCount`,
   `RootRole`, `TargetsRole`, and `LogRole` return counts/copies. Both
   fields are reference types (a map; slices inside `Role`), so exporting
   them would let any caller holding a `*Root` mutate the trust store
   directly — e.g. inject an attacker-chosen key into the map — bypassing
   every check in this package.

