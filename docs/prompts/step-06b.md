# tetragon-relay — new session: Step 6b (policy and trust delivery over the stream, reconcile, alerts)

You are continuing an existing, security-critical project; the repository is the source of
truth. Repo: https://github.com/bshlisky/tetragon-relay (main).

## Binding context
- The working agreement in docs/prompts/step-04b.md (Part 0) applies, including the
  session-size rule, "never widen production privileges to make a test pass", and the
  progress-log rule (after every push, a dated line in this step's report).
- Read docs/architecture.md sections 6.3–6.5, 7.4–7.7, 8.3 and 10.4; docs/server-contract.md;
  docs/reports/step-06a.md (especially sections 9 and 14); ADRs 0023–0035; and the attached
  review.
- State: step 6a is accepted at 058462b. relayd runs as a sandboxed systemd service, connects,
  heartbeats, handles Terminate, REVOKED and DEGRADED, and is proven end to end by E3 (S1–S6).
  Today it answers PolicyBundle and TrustUpdate with "not yet processed". This step makes it
  process them.

## First actions
1. Two files are ATTACHED: this prompt and step-06a-final-review.md. Commit them verbatim in
   one commit, adding the deferred progress-log line for 058462b:
   - docs/reviews/step-06a-final-review.md
   - docs/prompts/step-06b.md
2. Run `make ci` (on macOS, lint with `GOOS=linux golangci-lint run ./...`); confirm green.
3. Acknowledge with ≤ 12 bullets: your plan for Parts A–F, in priority order.

## Part A — Cleanup
A1. R6A-5: relayd-e3 is built with `-tags testca` only; remove the unused testtpm TCP
    transport from relayd (and from testenroll if unused). Update the C4 list. E3 stays green.

## Part B — PolicyBundle delivery (highest priority)
B1. Pipeline: PolicyBundle.envelope (raw bytes, never re-encoded) → verify.Verify with the
    real dependencies, namely the current trust root, the store's EpochSource, the
    PolicyParser, and Guardrails with:
    - HostCapabilities from the host facts kept by R6A-2 (stale or missing facts mean no
      enforcement capability, so enforce bundles are rejected with REJECTED_CAPABILITY)
    - the store's PolicyHistory
    - the ML-DSA availability from the startup self-test
    On ACCEPT: state APPLYING, then apply.Engine.Apply, then the persistence ordering from
    step 4b D1 (epoch, LKG and monitor history committed only after APPLIED). Every outcome
    sends exactly one ApplyResult with the correct code, the bundle digest, the epoch and
    loaded_digest_after.
B2. Never block the stream loop. Apply, including the health window (up to 600 s), runs in its
    own goroutine. The stream loop keeps sending heartbeats and handling messages throughout.
    Otherwise the controller would mark the host SILENT and quarantine it. The apply worker
    is a registered liveness component; it touches liveness while it waits in the health
    window.
B3. One apply at a time. A bundle that arrives during an apply is held in a single pending
    slot; a newer bundle replaces it. When the slot is replaced, the superseded bundle gets
    ApplyResult REJECTED_EPOCH with detail "superseded". A pending bundle is verified when it
    is dequeued, not when it arrives (the epoch may have moved on). Document this in an ADR
    and add the behavior to docs/server-contract.md.
B4. Health-window reachability: replace noopReachability with the real control-stream state
    (connected and heartbeats acknowledged by the transport).
B5. States: APPLYING, ROLLBACK and STEADY transitions per 8.3. ROLLBACK_FAILED moves to
    DEGRADED with an alert. A store TAMPERED state rejects every bundle (step 4b C6) with a
    clear reason.

## Part C — TrustUpdate delivery
C1. TrustUpdate.signed_roots is an ordered list, N+1…M. Each root must verify against its
    predecessor (trust.Update). Persist after each successful step (atomic per step). On the
    first failure, stop, keep the last good root, and audit and alert. Apply the
    ML-DSA-availability refusal (R4B-6).
C2. While a bundle apply is in progress, a trust update waits for it to finish. Never swap
    roots in the middle of a verification.
C3. Expired current root: send Alert TRUST_EXPIRED once per connection, plus daily while it
    stays expired. Bundles are rejected as verify already does.

## Part D — Reconcile scheduling and drift
D1. A reconcile scheduler, a registered liveness component, runs apply.Reconcile every 60 s,
    and immediately when Tetragon's process start time changes (restart detected through
    GetHealth or GetVersion and the host facts). It never runs concurrently with an apply.
D2. Drift (Tetragon's loaded set differs from LKG): state DRIFT, Alert DRIFT with both
    digests, re-assert LKG once. Back to STEADY if the re-assert holds; if not, stay in DRIFT
    and alert on every cycle (rate-limited, below). Never unload anything that isn't
    relay-managed.

## Part E — Alerts
E1. The Alert kinds: DRIFT, TETRAGON_UNHEALTHY, TRUST_EXPIRED, TAMPER (store TAMPERED at
    startup, sent once connected) and GUARDRAIL_REJECT (with the rule ID). Each kind is
    rate-limited, at most one per kind per 5 minutes except the first. Alerts produced while
    disconnected are queued in a bounded queue (oldest dropped, with a counter), and sent
    after the next HelloAck. Every alert is also written to the audit log.
E2. Update docs/server-contract.md: alert semantics, rate limits and the pending-bundle rule.

## Part F — Tests
F1. Unit tests for every new path, including: superseded pending bundle; trust update during
    an apply; a partial trust chain; drift re-assert success and failure; alert rate
    limiting and the queue bound; heartbeats continuing during a 60 s health window (use an
    injected clock).
F2. E3 scenarios added to the existing harness (same rules: real unit, only the documented
    drop-ins). Bundles are signed in CI with test keys under the E3 test root (cmd/e3root
    plus cmd/bundlesign-test, test-only tags):
    - S7: monitor bundle, then enforce bundle, delivered over the stream. ApplyResult
      APPLIED both times; a canary binary is killed by the enforce policy; the store epoch
      persists across a restart.
    - S8: a bundle with a bad signature gets REJECTED_SIGNATURE, and nothing changes in
      Tetragon.
    - S9: replaying S7's bundle gets REJECTED_EPOCH.
    - S10: a trust update chain N+1, N+2 is applied, persisted, and survives a restart; a
      bundle signed under the new root is accepted.
    - S11: an out-of-band `tetra tracingpolicy delete` of a relay-managed policy leads to
      Alert DRIFT and a re-assert, and the policy is loaded again.
    - S12: an enforce bundle that kills an admin-path process inside the test's process tree
      rolls back over the stream (ApplyResult ROLLED_BACK), and heartbeats continue
      throughout the health window.
F3. Coverage gates unchanged (≥ 90% for internal/agent).

## Priority if the session runs short
B, then F2 S7–S9, then C with S10, then D and E with S11, then S12. Stop only after a
completed item with all workflows green, with the report updated.

## Definition of done
ci, integration and e3 green on GitHub for the final commit, with S1–S12 passing.

## Report: docs/reports/step-06b.md (also paste it in your final message)
Sections 1–10 as in previous steps, plus:
11. The concurrency design (stream loop, apply worker, reconcile scheduler, the pending
    slot, liveness registration), with a sequence diagram in Mermaid.
12. E3 evidence for S7–S12, per scenario.
13. The updated server-contract sections.
Progress log at the end, as in 6a.
