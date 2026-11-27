# ADR 0037: `ApplyResult.Status` starts at `STATUS_UNSPECIFIED`; explicit status and alert codes

## Status

Proposed (docs/prompts/step-07a.md A1; docs/reviews/step-06b-review.md R6B-1, R6B-2).

## Context

`control.proto` defined `enum Status { APPLIED = 0; ... }` inside `ApplyResult`. In
proto3 an unset enum field reads as its zero value, so an `ApplyResult` whose status was
never set, or a status number the controller's bindings do not know and default, reads
as **APPLIED**. The controller would record a bundle as applied that was not. Every
other enum in the proto starts at `*_UNSPECIFIED = 0`; this one failed open (R6B-1).

Step 6b also had to encode four outcomes and one alert the proto had no code for, and
put the distinction into `detail` text (step 6b report, deviation 4 and open question 2).
Controller logic must never branch on `detail` (R6B-2).

## Decision

1. **Wire break, accepted.** No controller is deployed, so the break costs nothing now.
   - `ApplyResult.Status`: `STATUS_UNSPECIFIED = 0`; `APPLIED` moves from 0 to **10**.
     Numbers 1–9 are unchanged.
   - New statuses: `SUPERSEDED = 11`, `REJECTED_TAMPERED = 12`,
     `REJECTED_AGENT_STATE = 13`, `ROLLBACK_FAILED = 14`.
   - New `Alert.Kind`s: `TRUST_UPDATE_REJECTED = 6`, `ROLLBACK_FAILED = 7`.
   - `PROTO_BASELINE` advances to the commit that lands this change. A commit cannot
     name its own SHA, so the baseline moves in the commit immediately after, and both
     are pushed together; this is how step 2 set the first baseline (`54e450a`, then
     `2b30036`).
2. **Agent mapping** (internal/agent):

   | Situation | Before | Now |
   | --- | --- | --- |
   | Pending bundle replaced before it started | `REJECTED_EPOCH`, detail `superseded` | `SUPERSEDED` (detail still `superseded`) |
   | Store TAMPERED | `REJECTED_EPOCH` | `REJECTED_TAMPERED` |
   | Verified, agent not in STEADY/SYNCING | `APPLY_FAILED` | `REJECTED_AGENT_STATE` |
   | Health window failed, LKG re-assert failed | `APPLY_FAILED`, detail `ROLLBACK_FAILED: …` | `ROLLBACK_FAILED`; alerts `ROLLBACK_FAILED` **and** `DRIFT` (the DRIFT alert stays, since the loaded set may differ from LKG) |
   | TrustUpdate (or a step of it) rejected | `Alert{KIND_UNSPECIFIED, "TRUST_UPDATE_REJECTED: …"}` | `Alert{TRUST_UPDATE_REJECTED, …}`, no prefix |
   | relayd built with no apply worker, TrustUpdate received | `Alert{KIND_UNSPECIFIED}` | `Alert{TRUST_UPDATE_REJECTED}` |

   Every other status is unchanged.
3. **No code path sends `STATUS_UNSPECIFIED`.** `applyResultMessage` (internal/agent,
   bundle.go) is the only place an `ApplyResult` is wrapped into an `AgentMessage`. A
   source-scan test (`TestApplyResult_OnlyWrappedByApplyResultMessage`) fails if any
   other non-test file under `internal/` or `cmd/` builds one. `applyResultMessage`
   sends a `STATUS_UNSPECIFIED` status, or any number this build does not define, as
   `APPLY_FAILED` with detail `internal error: ApplyResult status N was not set; not
   applied: …`. That is the interpretation that rejects more: the agent never claims
   success it did not record.
4. **Contract** (docs/server-contract.md 1.5, 6, 10.3–10.5): the controller treats
   `STATUS_UNSPECIFIED` and any status number it does not know as **not applied**, and
   an unknown `Alert.Kind` as an alert of unknown kind (log it and keep it; never drop
   it).

## Consequences

- Any controller built against the old proto would read the new `APPLIED = 10` as an
  unknown value, which the contract now says means not applied. It fails closed.
- `REJECTED_EPOCH` now means only what it says: the bundle's epoch is not ahead of the
  host's persisted epoch for its scope.
- `detail` remains human-readable context only.
