# ADR 0002: Root metadata envelope size cap

## Status

Accepted.

## Context

Architecture doc section 7.4 step 1 specifies a 1 MiB cap on policy bundle
envelopes, but does not specify a cap for trust-root metadata envelopes
(section 7.6). Root metadata is structurally much smaller: a handful of
ECDSA P-384 public keys (DER-encoded SubjectPublicKeyInfo is ~120 bytes each)
and three short role definitions.

## Decision

`internal/limits.MaxRootMetadataBytes` is set to 64 KiB. At realistic scale
(tens of keys, three roles), a root metadata envelope is on the order of a
few KiB; 64 KiB leaves generous headroom (hundreds of keys) while still
bounding the work an attacker-supplied `TrustUpdate` message can force before
any parsing happens, independent of the bundle envelope cap.

## Consequences

- If the real deployment ever needs more than roughly 150-200 keys in a
  single root metadata document, this constant will need to be revisited.
- This is listed as an open question for the architect in
  docs/reports/step-01.md, since the number is this project's choice, not
  one specified in the architecture doc.
