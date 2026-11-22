# ADR 0005: Minimal definitions for proto messages not specified in the architecture doc

## Status

Accepted; flagged as a deviation/open question for the architect.

## Context

Architecture doc section 6.2's `control.proto` listing defines `AgentMessage`
and `ControllerMessage` as `oneof`s referencing `Hello`, `Heartbeat`,
`ApplyResult`, `StateReport`, `Alert`, `HelloAck`, `PolicyBundle`,
`StateRequest`, `RotateIdentity`, and `TrustUpdate`. Only `Hello`,
`Heartbeat`, and `ApplyResult` are actually defined with fields in that
section. The prompt requires transcribing section 6.2 "exactly... field
numbers included," which is only possible for the messages that have
field-level definitions there; the rest do not compile without *some*
definition.

## Decision

Minimal, conservative placeholder messages were added for `TetragonHealth`,
`StateReport`, `Alert`, `HelloAck`, `PolicyBundle`, `StateRequest`,
`RotateIdentity`, and `TrustUpdate`, each inferred from how it is referenced
elsewhere in the architecture doc:

- `HelloAck` carries the 32-byte nonce mentioned in sections 5.2 and 6.3.
- `PolicyBundle` and `TrustUpdate` each carry the raw DSSE envelope JSON
  bytes, since section 7.3 describes bundles and section 7.6 describes trust
  updates as opaque signed envelopes that `internal/verify`/`internal/trust`
  parse, not something the control-plane protocol itself needs to understand.
- `TetragonHealth`, `StateReport`, `Alert`, `StateRequest`, `RotateIdentity`
  are given the smallest plausible shape consistent with their names and
  usage in section 6.3's session lifecycle description, clearly marked as
  placeholders.

## Consequences

- These eight message shapes are **not** validated against anything the
  architect specified and must be reviewed before any client/server code
  (a later step) relies on their fields.
- This is called out explicitly in docs/reports/step-01.md under
  "Deviations" and "Open questions"; it is not something this step's tests
  exercise beyond "the .proto compiles and `buf lint`/`buf generate` succeed."
