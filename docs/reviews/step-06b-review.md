# Architect review: step 6b (origin/main @ 24dfd7e, green run 45944569472 on 34dc023)

Reviewer: architect · Date: 2026-11-27 · Verdict: **Step 6b accepted.** S1–S12 pass under the
real unit. Five follow-ups are recorded (R6B-1 to R6B-5). They are Part A of step 7a; none of
them blocks acceptance.

## What was verified

- The report's evidence matches the scenarios the prompt asked for:
  - S7: enforcement kills the canary (rc 137), and epoch 2 survives a restart.
  - S8 and S9: rejected, and Tetragon's loaded set is unchanged.
  - S10: the trust root goes v1 → v3 and survives a restart (the only root on disk is v1).
  - S11: drift is detected, alerted and re-asserted, and the non-relay `e3-baseline` is
    never touched.
  - S12: ROLLED_BACK, with heartbeats continuing through the health window.
- The concurrency design in ADR 0036 and report section 11 is sound:
  - One worker owns every job, so a root never changes mid-verify and reconcile never
    overlaps an apply.
  - The stream loop never blocks.
  - The worker's liveness is bounded by `health_window + 120 s`.
  - State-machine ownership is decided under one mutex.
- Three of its decisions improve on the prompt; all three are adopted:
  - `CommitApplied` writes epoch, LKG and monitor history as one write.
  - `EnforceAllowed` has a zero value that rejects.
  - The engine refuses to act on a TAMPERED LKG.
- **The seccomp finding is exactly why E3 exists.** relayd would have died on its first
  apply in production, and no amount of unit testing would have shown it. Fixing it by
  removing `fchown` rather than widening `SystemCallFilter` was the right call.

## Findings

### R6B-1 [MEDIUM, pre-existing since step 1] `ApplyResult.Status` zero value is `APPLIED`

`enum Status { APPLIED = 0; ... }`. In proto3, an unset field reads as its zero value. Any
of these cases would make the controller record a bundle as applied when it was not:

- an agent bug that leaves the status unset;
- a future agent that sends a status this controller doesn't know (unknown enum values
  surface as the number, but some language bindings default them);
- any code path that builds `ApplyResult{}` and returns early.

Every other enum in the proto starts at `*_UNSPECIFIED = 0`. This one fails open on the
server side, and I missed it in the step 1 review.

**Fix:** add `STATUS_UNSPECIFIED = 0` and move `APPLIED` to a new number. This is a wire
break, so:

- write an ADR;
- advance `PROTO_BASELINE` in the same commit;
- update docs/server-contract.md: the controller must treat `STATUS_UNSPECIFIED` and any
  unknown status as **not applied**.

There is no deployed controller yet, so the break costs nothing now and much more later.

### R6B-2 [LOW] Status and alert codes the controller would otherwise have to parse out of `detail`

This answers open question 2: yes, extend the proto in the same ADR and commit as R6B-1.
Controller logic must never branch on `detail` text.

| Today | New |
| --- | --- |
| superseded → `REJECTED_EPOCH` + detail | `ApplyResult.SUPERSEDED` |
| TAMPERED store → `REJECTED_EPOCH` | `ApplyResult.REJECTED_TAMPERED` |
| agent not in STEADY/SYNCING → `APPLY_FAILED` | `ApplyResult.REJECTED_AGENT_STATE` |
| `APPLY_FAILED` + "ROLLBACK_FAILED: …" | `ApplyResult.ROLLBACK_FAILED` (the `Alert{DRIFT}` stays) |
| `Alert{KIND_UNSPECIFIED, "TRUST_UPDATE_REJECTED: …"}` | `Alert.TRUST_UPDATE_REJECTED` |
| — | `Alert.ROLLBACK_FAILED` |

### R6B-3 [LOW] Alerts can push ApplyResults out of the outbox

The outbox holds 64 messages and drops the oldest. During a long outage with a flapping
condition, alerts can evict an ApplyResult. ApplyResults are the controller's record of
what happened to a signed change, so they matter more than alerts. Fix it with two
bounds:

- ApplyResults are never evicted by alerts.
- ApplyResults have their own bound (16 is plenty: one apply runs at a time, plus one
  superseded result per replaced bundle). If that bound is ever exceeded, the oldest
  ApplyResult is dropped, counted and audited.
- Alerts keep oldest-dropped within the remainder.

### R6B-4 [LOW, contract] One pending slot is shared across scopes

Epochs are per scope, but the pending slot is per host, and it can't be keyed by scope:
the scope is only known after verification. A scope-A bundle can therefore be superseded
by a scope-B bundle, and scope A then gets nothing until the controller resends.

The agent behavior is correct; it is the price of verifying at dequeue. The contract must
say so explicitly. Add this rule to server-contract section 10.2:

> On `SUPERSEDED`, if the host's reported epoch for that bundle's scope is still below the
> bundle's epoch, resend the latest bundle for that scope.

Better still, add:

> A controller should keep at most one bundle in flight per host.

### R6B-5 [decision] TAMPER at startup: tampered mode is approved, with these limits

This answers open question 1. A host whose store is TAMPERED and that goes silent looks
the same as one that is unplugged. Telling the two apart is worth the added complexity.
relayd starts in **tampered mode**:

- **Never writes to Tetragon.** No apply, reconcile, rollback or re-assert. Whatever
  Tetragon has loaded stays loaded, and Tetragon reloads `tp.d/relay` on its own restart.
- **Rejects every `PolicyBundle`** with `REJECTED_TAMPERED`, and every `TrustUpdate`
  (alert `TRUST_UPDATE_REJECTED`). Never writes to the store, except as noted for
  REVOKED below.
- **Connects with the identity as it is.** After HelloAck, sends `Alert{TAMPER}`, then
  heartbeats. Heartbeats carry live `loaded_digest` and `health`, and an empty `epochs`
  map. An empty map is distinguishable from "all epochs zero", and the contract must say
  so.
- **Treats the REVOKED marker as unknown, not "not revoked".** Server-side revocation is
  authoritative: the gateway refuses a revoked SPIFFE ID at the mTLS layer. Confirm this
  is written in server-contract section 1, and add it if it isn't. If the server sends
  `Terminate{REVOKED}`, relayd parks as in ADR 0035, and tries to persist the marker on a
  best-effort basis.
- **Is its own state**, `TAMPERED`, with no exit except restart. It is a liveness-normal
  state: the watchdog keeps being fed while the session runner and its own loop are
  healthy.
- **Recovery is operator re-enrollment**, as today.

Record this in a new ADR that amends ADR 0035 and architecture 8.3 (the new state). Add
an E3 scenario: corrupt the store index with relayd stopped, start it, and check
`Alert{TAMPER}`, heartbeats with an empty epochs map, a `REJECTED_TAMPERED` bundle,
Tetragon's loaded set unchanged, and no SIGSYS. Run it after S12 and before S4, then
restore the store, or run it on a fresh store directory.

## Answers to the other open questions

- **Q3 usrmerge:** keep the check exactly as it is. Production is RHEL 9 only, and
  changing the CI runner was the right place to fix it. Add one line to the e3 job saying
  why the runner's symlink is re-pointed.
- **Q4 drift cadence:** re-assert once per episode, as implemented. If drift keeps coming
  back after a re-assert, something is actively fighting the relay. The controller
  quarantines on the second mismatched cycle (architecture 10.4), so a re-assert loop
  would only hide the attacker.

## Deviations accepted

All eleven in report section 6 are accepted. Numbers 4 and 6 are superseded by R6B-2's new
codes. On number 11, TRUST_EXPIRED staying out of DEGRADED is right, and the architecture
gets one sentence about it in the step 7a ADR (agents don't edit the architecture doc).

## Still outstanding (customer)

These are unchanged and the most important items not in code:

- Run scripts/e2e-rhel9.sh on the customer's RHEL 9 server.
- Choose SPIRE or IdM.
- Answer the TPM owner-auth question.
- Confirm the Hypershield quarantine API.

Production relayd stays UNENROLLED until there is an Enroller, so none of steps 6a–6b runs
outside the testca build until the customer chooses SPIRE or IdM.
