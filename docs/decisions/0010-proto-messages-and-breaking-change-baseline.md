# ADR 0010: Concrete shapes for the placeholder proto messages, and a breaking-change baseline

## Status

Accepted. Supersedes ADR 0005.

## Context

ADR 0005 (step 1) added minimal placeholder definitions for `TetragonHealth`,
`StateReport`, `Alert`, `HelloAck`, `PolicyBundle`, `StateRequest`,
`RotateIdentity`, and `TrustUpdate`, since architecture doc section 6.2
references them in its `oneof`s but never defines their fields. The step 1
architect review (item A8) specifies concrete shapes for all of these, plus
changes to `Hello` and `Heartbeat` (replacing a single `current_epoch` field
with a `scope -> epoch` map, since a host can belong to more than one scope
per architecture doc section 8.6's `host.allowed_scopes`), and adds
`REJECTED_CAPABILITY` to `ApplyResult.Status`.

## Decision

`api/relay/control/v1/control.proto` now matches the review's specification
exactly:

- `Hello` and `Heartbeat` carry `map<string, uint64> epochs` instead of a
  single `current_epoch`; `Hello` gains `config_digest` (sha256 of
  `relay.yaml`, architecture doc section 8.5).
- `HelloAck`, `PolicyBundle`, `StateRequest`, `RotateIdentity`, `TrustUpdate`,
  `StateReport`, `LoadedPolicy`, `TetragonHealth`, `Terminate`, and `Alert`
  are given the fields specified in the review, replacing ADR 0005's
  placeholders.
- `ApplyResult.Status` gains `REJECTED_CAPABILITY = 9` (used by the
  guardrail/capability work in a later step; see the review's Part C, G8).
- `PolicyBundle.envelope` and `TrustUpdate.signed_roots` carry raw DSSE
  envelope bytes directly (not a JSON string field as ADR 0005's
  placeholders did), with an explicit doc comment that these bytes must
  never be re-encoded in transit, since `internal/verify` and
  `internal/trust` verify signatures over the exact bytes received.

Because this protocol has no external consumers yet, the review authorized
changing field types freely in this step. From this point forward, a
`buf breaking` baseline is enforced: `make breaking` compares the working
tree's `api/` against `PROTO_BASELINE` (a pinned commit SHA in the
`Makefile`), which is set to the commit that lands this ADR and the A8 proto
rewrite. That SHA is recorded in `docs/reports/step-02.md` section 14 (item
A8) once the commit exists.

## Consequences

- Any proto change after the baseline commit that `buf breaking` flags must
  either be reverted, replaced with a non-breaking alternative, or
  accompanied by an explicit decision to break compatibility (which, once
  there are real consumers, should itself go through architect review).
- `LoadedPolicy` and the `Alert`/`Terminate` enums are new; nothing in this
  step's Go code (which only implements `internal/trust` and
  `internal/verify`, not the gRPC client/server) consumes them yet.
