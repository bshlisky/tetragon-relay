# ADR 0036: One apply worker, one pending-bundle slot, verified at dequeue

## Status

Proposed (docs/prompts/step-06b.md B2/B3).

## Context

A bundle apply includes the health window (architecture doc 7.7 step 7),
which is 60 s by default and up to 600 s. If the control stream's loop ran
the apply itself, it would send no heartbeats for that long. The
controller marks a host SILENT after 45 s and LOST after 120 s (6.3 step
5), and LOST quarantines it (INV-5). The health window's own reachability
check ("agent can still reach the controller") would then fail because of
the apply itself.

`apply.Engine` is single-flight (`TryLock`). A second bundle that arrives
during an apply needs a defined outcome. Rejecting it with
`ErrApplyInProgress` would push retry logic onto the controller. Queueing
every bundle would apply bundles the controller has already replaced.

## Decision

1. **One apply worker goroutine** (`agent.ApplyWorker`) owns every bundle
   apply. The stream loop hands it the raw envelope (`SubmitBundle`) and
   returns at once. It keeps receiving, heartbeating and handling every
   other message throughout. The worker sends the ApplyResult through the
   `Outbox`, which the stream loop drains.
2. **One pending slot.** A bundle that arrives while the worker is busy is
   held in a single slot. A newer arrival replaces it, and the replaced
   bundle gets ApplyResult `REJECTED_EPOCH`, detail `"superseded"`,
   `bundle_digest` = SHA-256 of its envelope and `epoch` = 0. The epoch is
   left at 0 because the superseded bundle was never verified, so the agent
   reports nothing from its payload.
3. **Verified at dequeue, not on arrival.** The slot holds raw bytes. A
   pending bundle goes through the whole of `verify.Verify` (trust root,
   epoch, guardrails, monitor history) when the worker takes it, against
   the state the previous apply left. A bundle that was valid on arrival
   but whose epoch is no longer ahead of the store is rejected
   `REJECTED_EPOCH`.
4. **The ApplyResult outlives the stream.** The Outbox survives reconnects.
   An apply that finishes while the stream is down has its ApplyResult sent
   first on the next stream, after HelloAck. Outbound seq is assigned when
   a message is sent, never when it is queued (ADR 0032).
5. **The worker is a liveness component** (`apply_worker`). While idle it
   touches every 5 s. While a job runs, the worker loop waits on the job's
   own goroutine and keeps touching, but only for `health_window +
   limits.ApplyWorkerLivenessSlack` (120 s). A job still running past that
   bound is stalled: the worker stops touching, and systemd's watchdog
   restarts relayd.
6. **State-machine ownership.** While APPLYING, ROLLBACK or DRIFT (a
   reconcile episode), the worker owns the state machine's transitions.
   RunSession does not fire StreamLost/HelloAck/InSync in those states
   (architecture 8.4 has no such edges). When the worker settles in STEADY
   with the stream down, it fires StreamLost itself. Both sides decide under
   `agent.Link`'s mutex. (DRIFT was added after E3 run 45941496156, S11, saw
   the stream close mid-episode.)
7. **Later work runs on the same worker** (steps 6b C/D): trust updates and
   reconcile cycles. That one goroutine is what guarantees that a trust
   root never changes mid-verification (C2) and that reconcile never runs
   concurrently with an apply (D1).

## Consequences

- The controller sees at most one ApplyResult per bundle it sent. A
  superseded bundle gets one too (`REJECTED_EPOCH`/`superseded`), so the
  controller can account for every bundle it sent.
- A controller that sends bundles N+1 and N+2 back to back gets N+1
  applied and N+2 applied after it, or, if N+3 arrives during N+1's apply,
  N+2 superseded and N+3 applied. N+2's policies never take effect, which
  is correct because N+3 replaces them.
- An apply that is still running when relayd stops is interrupted. LKG
  stays authoritative (step 4b D1) and reconcile re-asserts it on the next
  start.
