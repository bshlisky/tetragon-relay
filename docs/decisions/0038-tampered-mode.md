# ADR 0038: Tampered mode — a store found TAMPERED at startup is reported, not silent

## Status

Proposed (docs/prompts/step-07a.md A4; docs/reviews/step-06b-review.md R6B-5).
Amends ADR 0035 and architecture doc 8.3/8.4 (a new state, `TAMPERED`).

## Context

Through step 6b, `agent.Startup` returned `store.ErrTampered` when the store was
TAMPERED (index HMAC or schema failure, counter rollback, a persisted root that does not
parse, an LKG that does not re-verify), and relayd exited. systemd restarted it, it
failed again, and it never connected. To the controller that host looks exactly like an
unplugged one (LOST). Telling the two apart is worth the added complexity (R6B-5).

The catch is that the REVOKED marker (ADR 0035) lives in the same store, so whether the
host was revoked is unknown.

## Decision

relayd starts in **tampered mode** when `agent.Startup` fails with an error wrapping
`store.ErrTampered` (`cmd/relayd/tampered.go`, `internal/agent/tampered.go`):

1. **Never writes to Tetragon.** No apply engine, apply worker or reconcile scheduler is
   built, so no apply, reconcile, rollback or re-assert can run. Whatever Tetragon has
   loaded stays loaded, and Tetragon reloads `tp.d/relay` on its own restart.
2. **Rejects everything.** Every `PolicyBundle` is answered with
   `ApplyResult{REJECTED_TAMPERED}` (bundle_digest only; the envelope is never parsed).
   Every `TrustUpdate` raises `Alert{TRUST_UPDATE_REJECTED}`. `RotateIdentity` is refused
   and audited (`rotate_identity_refused`).
3. **Never writes to the store,** except the REVOKED marker below. The store is not kept
   open.
4. **Connects with the identity as it is.** The host signing key is loaded with
   `tpm.LoadHostSigner`, which never creates one. With no key or no persisted chain,
   relayd does not connect (audited) and only feeds the watchdog.
5. **Reports.** After every HelloAck it raises `Alert{TAMPER}` (rate-limited per kind like
   every alert; the first is always sent). The Outbox is drained right after HelloAck, so
   the alert goes out before the first heartbeat. Heartbeats and StateReports carry live
   `loaded_digest` and `health` and an **empty `epochs` map**; Hello carries no trust
   root and no LKG digest. A normal agent always reports one `epochs` entry per allowed
   scope, even when it is 0, so an empty map is distinguishable from "all epochs zero".
6. **The REVOKED marker is unknown, not "not revoked".** It is never read. Server-side
   revocation is authoritative: the gateway refuses a revoked SPIFFE ID at the mTLS layer
   (server-contract section 1). If the server sends `Terminate{REVOKED}`, relayd parks as
   in ADR 0035 and tries to persist the marker best-effort: it re-opens the store only to
   call `MarkRevoked`. If the index itself is what was tampered, the store does not open,
   the marker is not written, and `revocation_persist_failed` is audited. A restart then
   reconnects in tampered mode and the gateway refuses it.
7. **Its own state, `TAMPERED`.** Entered from `CONNECTING` by `EventStoreTampered`, once,
   at startup. It has no exit except a restart (and `Terminate{REVOKED}`, valid from every
   state). RunSession fires no connection transitions in it. It is liveness-normal: the
   session runner is the only registered component, so the watchdog keeps being fed
   while the session runner's own loop is healthy, whether or not the controller is
   reachable.
8. **Recovery is operator re-enrollment,** as today.

A store found TAMPERED **at runtime** is unchanged from step 6b: the running agent keeps
its state, raises `Alert{TAMPER}` and rejects with `REJECTED_TAMPERED` (ADR 0037).

### Amendments

- **ADR 0035:** a persisted REVOKED marker is read only when the store opens cleanly. In
  tampered mode it is unknown; persisting it is best-effort.
- **Architecture 8.3/8.4:** add the state

  | State | Entered when | Behavior | Exits to |
  | --- | --- | --- | --- |
  | `TAMPERED` | The store is TAMPERED at startup | Connect and report: `Alert{TAMPER}`, heartbeats with an empty epochs map, every bundle and trust update rejected; no Tetragon or store writes | `REVOKED` on `Terminate{REVOKED}`; otherwise none until restart (operator re-enrollment) |

- **Architecture 8.4, DEGRADED** (step 6b deviation 11, accepted in the step 6b review):
  an expired trust root raises `Alert{TRUST_EXPIRED}` but does not enter `DEGRADED`,
  because DEGRADED's only exit is a reconnect, which would keep blocking bundles after a
  successful TrustUpdate. Bundles are rejected while the root is expired anyway.

## Consequences

- A TAMPERED host is visible to the controller as TAMPER plus heartbeats instead of LOST.
- An attacker who can corrupt the store can force tampered mode, which only reduces what
  relayd will do; it never loosens enforcement.
- E3 scenario S13 covers it under the real unit: corrupt the store index with relayd
  stopped, start it, and check `Alert{TAMPER}`, empty-epochs heartbeats, a
  `REJECTED_TAMPERED` bundle, Tetragon's loaded set unchanged, and no SIGSYS.
