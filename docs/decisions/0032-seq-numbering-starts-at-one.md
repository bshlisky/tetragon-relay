# ADR 0032: `seq` numbering is pinned -- starts at 1, exactly +1, else a protocol error

## Status

Accepted.

## Context

Architecture doc section 6.2's `AgentMessage`/`ControllerMessage` both carry `uint64 seq`,
documented only as "strictly increasing per stream". `docs/server-contract.md` section 1.1
(as written through step 5b) left the starting value unspecified: "this step does not fix a
starting value; the gateway must track the stream's own first-seen `seq` and require strict
increase from there, never assume it starts at 0 or 1." `internal/controlclient.SendHello`
and `internal/testcontroller.Server.Connect` both already exist but neither enforces or
documents a starting value; the agent's own inbound message loop that will need to enforce
this does not exist yet (it is this step's Part D).

`docs/reviews/step-05b-review.md`'s open question 3 asks for this to be pinned rather than
left open, so both sides of a connection neither built in the same repository (the agent) nor
built in this repository at all (the gateway, per `docs/server-contract.md`'s own framing) can
implement the identical, unambiguous rule without any out-of-band coordination beyond this
document.

## Decision

In each direction independently (the agent's own `AgentMessage.seq` and the controller's own
`ControllerMessage.seq` are two separate counters, per `docs/server-contract.md` section 1.1):

- The first message sent on a stream has `seq = 1`.
- Every following message's `seq` is exactly the previous message's `seq` plus 1.
- Any other value -- `seq = 0`, a gap, a regression, or a repeat -- is a protocol error.

A protocol error closes the stream:

- **The agent**, on receiving a `ControllerMessage` with a `seq` that is not exactly the
  previous `ControllerMessage.seq + 1` (or not `1` for the first message), closes the stream
  and reconnects with the existing full-jitter backoff (architecture doc 6.3 step 6) -- the
  same path as any other stream loss, since a mis-sequenced gateway is not distinguishable
  from a transport failure at the agent's layer and no `Terminate` message from a
  non-conforming peer can be trusted once sequencing itself is broken.
- **The gateway**, on receiving an `AgentMessage` with a `seq` that is not exactly the
  previous `AgentMessage.seq + 1` (or not `1` for the first message), sends
  `Terminate{reason: PROTOCOL_ERROR}` and closes the stream (consistent with
  `docs/server-contract.md` section 4's existing "`seq` gaps or regressions close the
  stream").

This is implemented in two places by this step:

1. `internal/testcontroller.Server.Connect` (the one piece of gateway-side code this
   repository builds, per `docs/server-contract.md`'s own scope) now rejects a first
   `AgentMessage` whose `seq != 1` with `Terminate{PROTOCOL_ERROR}`, closing the stream.
   Enforcement of the FULL sequence (every later message, not just the first) requires the
   multi-message control loop this test server does not implement (`docs/server-contract.md`
   section 8's existing scope note); a real gateway's message loop must enforce the complete
   rule, not just the first message.
2. `internal/agent`'s control loop (this step's Part D) enforces the complete rule on every
   inbound `ControllerMessage`, starting with `HelloAck`.

## Consequences

- `docs/server-contract.md` section 1.1's `seq` rows are updated to state the pinned rule
  instead of "this step does not fix a starting value."
- `internal/testcontroller`'s reference server is no longer a correct reference for a
  gateway that defers its own seq-start choice; `docs/server-contract.md`'s conformance
  checklist (section 8) is updated to reference the pinned rule, not a self-chosen one.
- `internal/agent`'s control-loop tests (Part D, Part E of this step) include an
  out-of-order-`seq` test server scenario (`cmd/testcontroller`'s scripted-sequence
  extension, Part E2) alongside `internal/testcontroller`'s own first-message check.
- This does not change `control.proto`: `seq` was already `uint64` with no documented
  starting value in the wire format itself: only the two sides' behavior is pinned, not the
  message shape.
</content>
