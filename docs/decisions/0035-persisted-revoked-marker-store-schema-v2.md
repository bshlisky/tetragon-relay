# ADR 0035: REVOKED is persisted in the store (index schema v2, bumped in place)

## Status

Accepted (docs/reviews/step-06a-e3-decisions.md D2).

## Context

Architecture doc 8.4 makes REVOKED terminal: it is entered on
`Terminate{REVOKED}`, and the only way out is operator re-enrollment
(REVOKED -> UNENROLLED; `agent.Reenroller`, ADR 0023). Through E3 run
45858158620, REVOKED existed only in memory. Any restart, whether systemd's
watchdog, a crash, a reboot or `systemctl restart`, brought relayd back
through UNENROLLED -> ENROLLING -> CONNECTING, and it reconnected to the
controller that had just revoked it. That is what E3 S4 caught (together
with the liveness bug D1 fixed).

## Decision

1. `internal/store`'s index payload gains an optional `revoked` marker,
   `{at, reason}`. It is part of the canonical, HMAC-SHA-384-covered
   payload like every other field, so editing or removing it on disk is
   tamper (`ErrTampered`). Rollback to an older index without the marker is
   caught by the existing monotonic-counter check.
2. The index schema string goes from `relay.store.index.v1` to
   `relay.store.index.v2`, **in place, with no migration**. No store has
   ever been deployed: relayd has not shipped, and every existing store is a
   test or CI artifact. A v1 index now fails `decodeIndexFile`'s schema
   check, which Open reports as tamper. That is the intended behavior for
   any index this build did not write.
3. Bounds: `reason` is at most `limits.MaxRevokedReasonBytes` (256), and
   `at` must be non-zero. Both are checked on write (`MarkRevoked`) and on
   load (`verifyIndexLimits`). internal/agent cuts the controller's
   `Terminate.detail` (as `"REVOKED: <detail>"`) to that length at a UTF-8
   boundary before writing.
4. API:
   - `MarkRevoked(at, reason)`: idempotent. The first revocation's time and
     reason are kept.
   - `Revocation()`: reads the marker.
   - `ClearRevocation()`: the only way to remove the marker. It is
     documented as reserved for the Reenroller path (ADR 0023). Startup and
     the session runner never call it, and nothing calls it yet, since
     Reenroller is still an interface only.
5. internal/agent:
   - `RunSession` persists the marker (`SessionConfig.Revocations`, which
     is required) before it parks (D1). If persisting fails, an audit
     record (`revocation_persist_failed`) says so, and the session still
     parks.
   - At startup, `agent.RestoreRevocation` moves the state machine straight
     to REVOKED when a marker exists. RunSession then parks without dialing,
     and the LKG applied at startup stays enforced. A store read error is
     fatal; it is never read as "not revoked".

## Consequences

- A revoked host stays revoked across restarts until an operator
  re-enrolls it. Until Reenroller is implemented, recovery means
  re-provisioning the host's store, which is the same story as a TAMPERED
  store today (step-04b C6).
- E3 S4 now restarts relayd after the revocation and asserts it still does
  not reconnect. S4 runs last, because revocation is terminal for that
  host's store.
