# Step 6b report

Prompt: docs/prompts/step-06b.md. Review it starts from: docs/reviews/step-06a-final-review.md.
Base: `058462b` (step 6a accepted). Working agreement: docs/prompts/step-04b.md Part 0.

## 1. Summary

**Definition of done met:** ci, integration and e3 are green on GitHub for `34dc023`
(run 45944569472), with S1–S12 passing. The commit adding this report is docs only; its
run is recorded in the next commit's progress log, as in 6a.

relayd now processes everything the controller can send it. A `PolicyBundle` is
verified and applied on its own worker goroutine while the stream loop keeps
heartbeating. A `TrustUpdate` chain is walked and persisted one version at a time.
Reconcile runs every 60 s and right after a Tetragon restart, re-asserting LKG on drift.
Alerts are rate-limited per kind and queued while the stream is down.

| Part | Status | Where |
| --- | --- | --- |
| A1 R6A-5: remove the testtpm TCP transport | done | `29def2e` |
| B1 bundle pipeline with the real dependencies; atomic post-APPLIED commit | done | `efb3bd0`, `ee93f6b`, `f89ffbd` |
| B2 apply worker; stream loop never blocks; worker is a liveness component | done | `ee93f6b` |
| B3 single pending slot, `superseded`, verified at dequeue; ADR 0036; contract | done | `ee93f6b`, `cf6649d` |
| B4 real health-window reachability (`agent.Link`) | done | `8217553`, `f89ffbd` |
| B5 APPLYING/ROLLBACK/STEADY; ROLLBACK_FAILED → DEGRADED + alert; TAMPERED rejects | done | `ee93f6b` |
| C1–C3 TrustUpdate chain, wait for apply, TRUST_EXPIRED | done | `81e0351`, `fa63f86` |
| D1–D2 reconcile scheduler, Tetragon-restart trigger, DRIFT handling | done | `17e94d7`, `10e8575`, `5185493`, `8dc9fe7`, `722c2e6` |
| E1 alert kinds, per-kind rate limit, bounded queue, audit | done except TAMPER **at startup** (open question 1) | `8217553`, `5185493` |
| E2 contract: alert semantics, rate limits, pending-bundle rule | done | `cf6649d`, `33ac160`, `c187ecc` |
| F1 unit tests | done | `016af02`, `418837c`, `484af7d` |
| F2 E3 S7–S12 | **done: S1–S12 PASS, run 45944569472** | `929efcd`, `f67f6d4`, `5d29c3e`, `08f45bf`, `33ac160`, `074dbc7`, `be3c97e`, `864c15c`, `3a083ac`; fixes found by E3: `0f0006f`, `722c2e6` |
| F3 coverage gates unchanged | internal/agent 94.1 % locally (section 3) | — |

Two design points the prompt left open, both decided the way that rejects more:

- **The post-APPLIED commit is one store write.** `store.CommitApplied` writes epoch,
  LKG and monitor history in a single index generation. Calling the three existing
  writers in turn would leave crash windows: for example, the LKG names the new bundle
  while the epoch still admits a replay of it. The engine's `LKGStore.Put` routes
  through it (`agent.CommitOnPut`). If the commit fails, the result is `APPLY_FAILED`
  and never `APPLIED`, because reporting `APPLIED` would claim an epoch the host never
  persisted.
- **Enforce bundles need fresh host facts.** Guardrail G8 only gates `Override`, so a
  `Sigkill` enforce bundle would have passed on a host whose facts were stale or
  missing. The prompt requires rejection, so `BundleDeps.EnforceAllowed` (fresh facts
  **and** usrmerge OK; its zero value rejects) gates every enforce bundle with
  `REJECTED_CAPABILITY`.

Five defects found along the way and fixed:

- Tetragon reports `v1.8.0`, but `verify` expects a bare semantic version, so every
  bundle would have failed verify step 10 (`ee93f6b`).
- A TAMPERED store makes the LKG read as empty. `apply.Engine.Reconcile` and `rollback`
  would then have re-asserted an empty set, unloading every relay-managed policy,
  against step 4b C6 (`10e8575`).
- **relayd was killed by seccomp on its first apply under the production unit.**
  `apply.PersistDir` called `fchown`, which is in `@chown` and therefore covered by the
  unit's `SystemCallFilter=~@privileged`. E3 run 45938361280 (S7) shows
  `status=31/SYS` right after `apply_plan`. Step 3 never ran the engine under the unit,
  and step 6a never applied anything. The call is removed rather than the filter
  widened: relayd is not root, so `chown` could only ever target itself, and the
  directory's setgid bit already sets the group.
- **Stream loss while in DRIFT had no state edge.** E3 run 45941496156 (S11) logged
  `stream_lost is not valid from state DRIFT`. Once the re-assert held, the agent would
  have sat in STEADY while disconnected. DRIFT is now worker-owned like APPLYING
  (`722c2e6`, ADR 0036 point 6).
- `testcontroller.WaitForAgentMessage` leaves a `Recv` goroutine behind on timeout,
  which swallows the next message. e3controller's new modes use a single reader
  instead (`5d29c3e`).

## 2. File tree of what was added or changed (since `058462b`)

```
cmd/bundlesign-test/e3bundle.go, main.go   e3-bundle subcommand (testtools tag)
cmd/e3controller/main.go, stream6b.go      bundles and state modes (e3 tag)
cmd/e3root/main.go                         --keys-out, --version/--prev-keys (e3 tag)
cmd/e3tetra/main.go                        --mode=delete (e3 tag)
cmd/relayd/main.go                         wiring: worker, outbox, link, alerter, trust state,
                                           trust-expiry monitor, reconcile scheduler
cmd/relayd/tpmdevice.go                    /dev/tpmrm0 only (R6A-5)
cmd/relayd/tpmdevice_const.go,
  tpmdevice_testtpm.go, _test.go           deleted (R6A-5)
cmd/testenroll/main.go                     build tag testca only (R6A-5)
docs/decisions/0036-...pending-bundle-slot.md   NEW, Proposed
docs/server-contract.md                    sections 1.5, 9, 10 (10.1-10.5)
internal/agent/alerts.go                   NEW Alerter
internal/agent/applyworker.go              NEW ApplyWorker, processBundle, outcome mapping
internal/agent/bundle.go                   NEW BundleDeps, TrustState, CommitOnPut, verifyBundle
internal/agent/link.go                     NEW Link (reachability, transition lock)
internal/agent/outbox.go                   NEW Outbox
internal/agent/reconcile.go                NEW reconcile job, ReconcileScheduler
internal/agent/trustupdate.go              NEW trust updates, TrustExpiryMonitor
internal/agent/controlloop.go              PolicyBundle/TrustUpdate -> JobSink
internal/agent/session.go                  Link up/down, outbox drain, hooks
internal/agent/applyworker_test.go,
  applyworker_internal_test.go             NEW tests
internal/apply/{doc,interfaces,reconcile,rollback}.go, tamper_guard_test.go
                                           TamperReporter guard, TetragonServing
internal/apply/persist.go, engine.go (+ tests)   PersistDir never chowns; PersistUID/GID removed
internal/limits/limits.go                  MaxOutboxMessages, AlertRateLimitInterval,
                                           MaxApplyResultDetailBytes, ApplyWorkerLivenessSlack,
                                           MaxPendingTrustUpdates, TrustExpiredAlertInterval
internal/store/applied.go, applied_test.go, fault_matrix_test.go   CommitApplied
internal/tetra/client.go, dial_linux.go, peer_test.go, peer_linux_test.go   Client.Peer
scripts/e3-run.sh, .github/workflows/ci.yml   S7-S12, /var/run symlink, tool builds
```

## 3. Command output

Local, on macOS (Linux-only code is linted with `GOOS=linux`; `internal/tetra`'s gate
reads 86–87 % on macOS because its Linux-only peer-check paths do not run there, and it is
gated on Linux in CI). Captured after `0f0006f`:

```text
$ GOOS=linux golangci-lint run ./...
0 issues.

$ go test -race -count=1 ./internal/agent/ ./internal/apply/ ./internal/store/ ./internal/tetra/
ok  	github.com/bshlisky/tetragon-relay/internal/agent	34.570s
ok  	github.com/bshlisky/tetragon-relay/internal/apply	51.184s
ok  	github.com/bshlisky/tetragon-relay/internal/store	20.473s
ok  	github.com/bshlisky/tetragon-relay/internal/tetra	1.526s

$ make coverage90 (internal/agent, internal/apply excerpt; macOS)
== internal/apply (>=90% gate; step 3 prompt Part E5) ==
total:										(statements)				90.9%
--
== internal/agent (>=90% gate; step 3 prompt Part E5) ==
total:										(statements)			94.1%

$ make coverage (internal/store excerpt)
== internal/store ==
total:									(statements)			96.3%
```

At the start of the session, `make ci` (all targets other than lint, run with `make -k`
because lint is run separately as above) was green except for that macOS-only
`internal/tetra` coverage reading. GitHub results for every push are in the progress log.


## 4. Mapping: item → functions → tests

| Item | Functions | Tests |
| --- | --- | --- |
| A1 | `openTPMDevice` (`cmd/relayd/tpmdevice.go`) | `go build -tags testca ./cmd/relayd ./cmd/testenroll`; E3 S1–S6 |
| B1 verify with real deps | `verifyBundle`, `verifierFor`, `verifyCodeToStatus` | `TestApplyWorker_Rejections`, `TestApplyWorker_GuardrailRejectRaisesAlert`, `TestVerifierFor`, `TestVerifyCodeToStatus` |
| B1 enforce gate | `processBundle` (`EnforceAllowed`) | `TestApplyWorker_Rejections` (enforce without facts) |
| B1 atomic commit | `store.CommitApplied`, `CommitOnPut` | `TestCommitApplied_*`, `TestCrashMatrix_CommitApplied`, `TestApplyWorker_MonitorThenEnforceAppliedAndCommitted`, `TestApplyWorker_CommitFailureIsNotReportedApplied`, `TestCommitOnPut_RefusesUnarmedPut` |
| B1 one ApplyResult per bundle | `processBundle` (deferred push), `SubmitBundle` | every `TestApplyWorker_*` |
| B2 never block; liveness | `ApplyWorker.Run`, `runJob`, `ControlLoop` Bundle case | `TestRunSession_HeartbeatsContinueDuringApply`, `TestApplyWorker_RunJobLivenessBound`, `TestControlLoop_BundleGoesToJobSink` |
| B3 pending slot | `SubmitBundle`, `takePending`, `drainJobs` | `TestApplyWorker_SupersededPendingAndVerifyAtDequeue` |
| B4 reachability | `Link.Reachable/Up/Down/Acked` | `TestLink_Reachability`, `TestRunSession_HeartbeatsContinueDuringApply` |
| B5 states | `processBundle`, `mapApplyOutcome`, `settle`, `fireConnected`, `fireStreamLost` | `TestApplyWorker_OutcomeMapping`, `TestApplyWorker_NotSteadyIsNotApplied`, `TestRunSession_StreamLostDuringApplyIsSettledByWorker`, `TestRunSession_ConnectDuringApplyLeavesState` |
| B5 TAMPERED | `processBundle`, `tamperAlert` | `TestApplyWorker_TamperedStoreRejectsEveryBundle` |
| C1 chain | `processTrustUpdate`, `TrustState.set` | `TestTrustUpdate_ChainAdoptedPersistedAndUsedForBundles`, `TestTrustUpdate_PartialChainKeepsLastGoodRoot`, `TestTrustUpdate_EmptyIsRejected`, `TestTrustUpdate_TamperedStoreRejects`, `TestProcessTrustUpdate_RefusesMLDSARootWithoutMLDSA`, `TestProcessTrustUpdate_PersistFailureKeepsCurrentRoot`, `TestSubmitTrustUpdate_QueueBound` |
| C2 wait for apply | `drainJobs` ordering | `TestTrustUpdate_WaitsForTheApplyInProgress` |
| C3 TRUST_EXPIRED | `TrustExpiryMonitor` | `TestTrustExpiryMonitor_OncePerConnectionAndDaily` |
| D1 scheduler | `ReconcileScheduler.Run`, `RequestReconcile`, `tetra.Client.Peer`, `recordPeer` | `TestReconcileScheduler_PeriodicRestartAndHealth`, `TestClientPeer`, `TestRecordPeer` |
| D2 drift | `processReconcile`, `driftDetail`, `fire` | `TestReconcileFire_SettlesStreamLostOutOfDrift`, `TestReconcile_DriftReassertHolds`, `TestReconcile_DriftReassertFailsStaysInDriftAndAlertsEachCycle`, `TestReconcile_DriftClearsOnItsOwn`, `TestReconcile_ErrorAndTamperedStore` |
| D2 never touch Tetragon on a TAMPERED LKG | `apply.Engine.lkgTampered` | `TestReconcileAndRollback_RefuseOnTamperedLKG` |
| Unit sandbox compatibility (found by S7) | `writePersistedFile` (no `fchown`) | `TestPersistDir_*`; E3 S7–S12 (no SIGSYS) |
| E1 alerts | `Alerter.Raise`, `Outbox` | `TestAlerter_RateLimitPerKind`, `TestOutbox_BoundDropsOldestAndCounts`, `TestRunSession_StreamLostDuringApplyIsSettledByWorker` (queued result sent first on the next stream) |

## 5. Invariants and threats addressed

- **No enforcement gap and no unauthorised unload.** Only relay-managed policies are
  ever added or removed (the engine's existing rule). Reconcile and rollback now refuse
  to act on an LKG the store reports as TAMPERED (C6); before `10e8575` that case read
  as an empty LKG.
- **Replay and rollback defence.** Epoch, LKG and monitor history move together
  (`CommitApplied`, crash matrix). A pending bundle is verified against the state the
  apply in front of it left (`REJECTED_EPOCH`).
- **Trust root integrity.** Each step of a TrustUpdate must pass the old and new
  thresholds, and is persisted before it becomes current. A version requiring
  `mldsa-87` is refused on a build without ML-DSA (R4B-6). A root never changes during a
  verification (C2: one worker).
- **Controller-driven liveness.** The stream loop never runs an apply, so heartbeats
  continue through a health window of up to 600 s (no false SILENT or LOST). The
  health window's reachability check is the real stream state.
- **Agent liveness.** The apply worker and the reconcile scheduler are liveness
  components. An apply running past `health_window + 120 s` stops feeding the
  watchdog, and systemd restarts relayd.
- **Fail closed on capability.** Stale or missing host facts, or a failed usrmerge
  check, refuse every enforce bundle. `EnforceAllowed`'s zero value rejects.
- **Production sandbox unchanged.** No unit directive was widened. The one apply-path
  syscall the filter forbids (`fchown`, `@chown` in `~@privileged`) was removed from
  the code, and S7–S12 apply, roll back and re-assert under the real unit.
- **Bounded memory.** The outbox holds 64 messages, the trust-update queue 4, and a
  `signed_roots` chain at most 64 entries. `detail` is at most 4 KiB.

## 6. Deviations from this prompt or the architecture

1. **TAMPER at startup is not sent** (E1). A TAMPERED store still stops relayd at startup
   (`agent.Startup` returns `ErrTampered`), so it never connects. Sending the alert
   needs relayd to run without a trustworthy store, and that changes the design (open
   question 1). A store found TAMPERED **at runtime** raises TAMPER.
2. **Tetragon restart detection** (D1). Tetragon's `GetHealth` and `GetVersion` report no
   process start time, and relayd cannot read another user's `/proc/<pid>` under
   `ProtectProc=invisible`. A restart is detected as a change of the Tetragon socket
   peer's `SO_PEERCRED` pid. internal/tetra already verifies that pid on every grpc
   (re)dial, and the scheduler's 5 s `GetHealth` probe forces the re-dial.
3. **S11 deletes through the RPC, not the `tetra` CLI.** relayd's policies live in
   Tetragon *domain* `relay-managed`, a field separate from namespace
   (`DeleteTracingPolicyRequest.domain`). I could not verify which `tetra tracingpolicy
   delete` flag sets it in v1.8.0 without the binary, and the working agreement forbids
   guessing. `e3tetra --mode=delete` issues the same `DeleteTracingPolicy` RPC over
   Tetragon's socket as root.
4. **Status and alert codes the proto lacks.** A TAMPERED store's rejection is
   `REJECTED_EPOCH`, since C6's rationale is that no epoch is trustworthy.
   ROLLBACK_FAILED is `APPLY_FAILED` with detail `ROLLBACK_FAILED: ...` plus
   `Alert{DRIFT}`. A rejected TrustUpdate raises `Alert{KIND_UNSPECIFIED,
   "TRUST_UPDATE_REJECTED: ..."}`. The proto was not changed.
5. **Exits from APPLYING.** Architecture 8.4 gives APPLYING two exits, "health pass" and
   "fail". `APPLY_FAILED` (nothing loaded, or this attempt's additions removed) leaves
   through `ROLLBACK -> STEADY`, because LKG is what is loaded.
6. **Bundles are applied only from STEADY or SYNCING.** In any other state (DEGRADED,
   DRIFT, CONNECTING, REVOKED) a verified bundle gets `APPLY_FAILED`, `not applied:
   agent state X does not allow APPLYING`. The table has no other edge into APPLYING,
   and DEGRADED/REVOKED mean "no new changes".
7. **Drift re-assert is once per episode.** In DRIFT, later cycles only check and alert;
   they do not re-assert again. A Tetragon restart opens a new episode with one more
   re-assert. Outside STEADY/DRIFT, drift is still re-asserted and alerted, but the
   state is left alone (DRIFT edges exist only from STEADY), so LKG keeps being
   enforced after a Tetragon restart while the controller is unreachable.
8. **E3 runner environment.** `/var/run` is re-pointed from `/run` (Ubuntu) to `../run`
   (RHEL 9) so relay-probe's usrmerge check passes; both name the same directory. The
   check was not relaxed (open question 3). E3 bundles declare
   `tetragon_min_version: 1.0.0`, since the version gate is covered by verify's own
   tests.
9. **Superseded bundles report `epoch: 0`**, because a superseded bundle is never
   verified (ADR 0036).
10. **Commit size.** `ee93f6b` (bundle pipeline and worker) and the two test commits
    exceed ~400 changed lines; the worker, pipeline and session changes do not build
    apart.
11. **TRUST_EXPIRED does not enter DEGRADED.** Architecture 8.4 lists expired trust
    metadata as a DEGRADED cause, and C3 asks only for the alert. I did not add the
    transition: DEGRADED has a single exit at reconnect, so it would also block
    bundles after a successful TrustUpdate until the next reconnect.

## 7. Dependencies added

None.

## 8. Known limitations

- A production build still has no Enroller, so production relayd stays UNENROLLED and
  starts neither the worker nor the scheduler (unchanged from 6a).
- An apply still running when relayd stops is interrupted (ctx canceled). LKG stays
  authoritative and the startup reconcile re-asserts it (ADR 0036).
- Files relayd persists to `/etc/tetragon/tetragon.tp.d/relay` are owned by
  `tetragon-relay:tetragon-relay` (the group comes from the directory's setgid bit),
  not `root`. relayd cannot create root-owned files, and the architecture specifies
  only the directory's ownership.
- The alert rate limit can suppress the per-connection TRUST_EXPIRED when reconnects
  come less than 5 minutes apart. The audit log still records it.
- The outbox is shared by ApplyResults and alerts. In a very long outage an ApplyResult
  could be dropped behind 64 newer messages; the controller then sees the result
  through Hello's epochs and loaded digest.

## 9. Open questions for the architect

1. **TAMPER at startup** (E1). Today relayd refuses to start on a TAMPERED store. To send
   `Alert{TAMPER}` "once connected", relayd would have to run in a *tampered mode*: no
   reconcile, every bundle and trust update rejected, connected only to report. The
   catch is the REVOKED marker (ADR 0035), which lives in the same store, so whether the
   host was revoked is unknown. Proposal: tampered mode treats an unknown revocation as
   *not revoked* only for sending TAMPER and heartbeats. Alternative: keep refusing to
   start and let the controller infer from LOST. Please decide before I implement.
2. **Alert kinds.** Should the proto gain `TRUST_UPDATE_REJECTED` and `ROLLBACK_FAILED`
   (alert kind and ApplyResult status), instead of `KIND_UNSPECIFIED` with a prefix and
   `APPLY_FAILED`/`DRIFT`?
3. **usrmerge on non-RHEL hosts.** relay-probe requires `/var/run -> ../run` exactly.
   Ubuntu's `/var/run -> /run` resolves identically. Should the check accept the
   absolute form? Production targets RHEL 9 only, so I changed the runner, not the
   check.
4. **Drift re-assert cadence.** Once per episode (as implemented), or on every cycle
   while in DRIFT?

## 10. Self-review: the 5 places a reviewer is most likely to find a bug

1. **State-machine ownership across goroutines** (`Link`, `fireConnected`,
   `fireStreamLost`, `ApplyWorker.settle`, `ApplyWorker.fire`). RunSession leaves
   APPLYING, ROLLBACK and DRIFT to the worker, and the worker fires StreamLost when it
   settles in STEADY while disconnected. Both
   decide under `Link`'s mutex. Covered by
   `TestRunSession_StreamLostDuringApplyIsSettledByWorker` and
   `...ConnectDuringApplyLeavesState`. Not covered: `CheckCertExpiry` firing
   `EventDegradedCondition` mid-apply. The worker's later HealthPass then fails from
   DEGRADED, which is audited (`apply_state_transition_failed`), and the ApplyResult is
   still sent.
2. **`CommitOnPut` arming** (`bundle.go`). It relies on the engine calling `Put` exactly
   once, only after a passed health window, with Apply single-flight. Any other `Put` is
   refused; it never persists an unarmed epoch.
3. **Outbox seq assignment** (`drainOutbox`). `msg.Seq` is mutated on a queued pointer
   and popped only after `Send` succeeds. A message sent but whose Pop lost a race with
   a full-queue drop is not resent; it was already sent.
4. **Reconcile against a TAMPERED store** (`processReconcile` plus
   `apply.Engine.lkgTampered`). Two guards: the worker skips when the store reports
   tamper, and the engine refuses if tamper is detected by its own LKG read. The second
   catches the TOCTOU case where the blob is corrupted between the two reads.
5. **Restart detection** (`ReconcileScheduler`). PID reuse by a restarted Tetragon would
   go unnoticed, but the periodic 60 s cycle still catches the drift. The first PID seen
   is never treated as a restart.

## 11. The concurrency design

Five goroutines touch the agent's control state. Each is listed with what it owns.

| Goroutine | Owns | Never does | Liveness component |
| --- | --- | --- | --- |
| **Stream loop** (`RunSession` → `runStreamLoop`) | the stream: `Recv` dispatch, `Send`, outbound `seq`, heartbeats every 15 s, draining the `Outbox` | verify, apply, reconcile, trust-root changes | `session_runner` (6a) |
| **Apply worker** (`ApplyWorker.Run`) | every job, one at a time: trust updates, then the pending bundle, then a requested reconcile cycle; `TrustState`; the state machine while APPLYING/ROLLBACK | touching the stream | `apply_worker`, max 20 s silent; during a job it keeps touching for at most `health_window + 120 s` |
| **Job goroutine** (`runJob`) | the running job itself (verify → `Engine.Apply` → commit, or `Engine.Reconcile`) | anything outside its own job | covered by the worker's bounded touching |
| **Reconcile scheduler** (`ReconcileScheduler.Run`) | requesting reconcile at start, every 60 s, and on a Tetragon restart (new socket-peer pid); the 5 s `GetHealth` probe | running reconcile itself | `reconcile_scheduler` |
| **Watchdog loop** (`runUntilSignal`, cmd/relayd) | `WATCHDOG=1`, withheld unless every component is fresh | — | — |

Hand-offs:

- **Stream loop → worker** goes through `JobSink` (`SubmitBundle`, `SubmitTrustUpdate`).
  Both copy their input and return at once.
  - The bundle slot holds one bundle. A newer one replaces it, and the replaced one is
    answered with `REJECTED_EPOCH`/`superseded` through the Outbox.
  - The trust-update queue holds 4 messages, oldest dropped.
- **Worker → stream** goes through the `Outbox` (64 messages, oldest dropped and counted).
  The stream loop drains it right after every HelloAck and whenever notified. It
  assigns `seq` when it sends, and pops a message only after `Send` succeeds, so a result
  produced while disconnected goes out first on the next stream.
- **State machine.** The architecture's table has no edge for "stream lost while
  APPLYING" (or ROLLBACK, or DRIFT), so in those three states the worker owns the
  transitions:
  - RunSession's connect and loss transitions skip those states;
  - when the worker settles in STEADY with the stream down, it fires StreamLost itself;
  - both sides decide under `agent.Link`'s mutex, so neither acts on a connection state
    the other is halfway through changing.
- **Reachability.** The health window's `Reachable` is `Link`: connected, and the
  transport accepted a message within the last two heartbeat intervals.
- **Trust root.** Only the worker calls `TrustState.set`, and only between jobs, so a
  verification and the apply that follows it always see one root (C2).
- **Reconcile vs apply.** Both are worker jobs, so they never run concurrently (D1).
  `apply.Engine`'s own `TryLock` stays as a second line of defence.

```mermaid
sequenceDiagram
    autonumber
    participant C as Controller
    participant S as Stream loop
    participant O as Outbox
    participant W as Apply worker
    participant J as Job goroutine
    participant T as Tetragon
    participant R as Reconcile scheduler

    C->>S: PolicyBundle (epoch N)
    S->>W: SubmitBundle(envelope) [returns at once]
    W->>J: runJob(processBundle)
    J->>J: verify.Verify (trust root, epochs, guardrails, host facts)
    J->>J: STEADY -> APPLYING (under Link lock)
    J->>T: add-before-remove, confirm
    loop health window (60-600 s)
        S->>C: Heartbeat (every 15 s)
        J->>T: GetHealth / GetEvents, Link.Reachable()
        W->>W: touch apply_worker (bounded)
    end
    C->>S: PolicyBundle (epoch N+1) while busy
    S->>W: SubmitBundle -> pending slot
    C->>S: PolicyBundle (epoch N+2) while busy
    S->>W: SubmitBundle -> replaces N+1
    W->>O: ApplyResult(N+1) REJECTED_EPOCH "superseded"
    O-->>S: notify
    S->>C: ApplyResult(N+1) superseded
    J->>J: health passed: CommitApplied(epoch, LKG, monitor history)
    J->>J: APPLYING -> STEADY (StreamLost too if disconnected)
    J->>O: ApplyResult(N) APPLIED
    S->>C: ApplyResult(N)
    W->>J: runJob(processBundle N+2), verified now, at dequeue
    R->>W: RequestReconcile (60 s / Tetragon restart)
    W->>J: runJob(processReconcile) after the bundle
    J->>T: ListTracingPolicies vs LKG; on drift: DRIFT, Alert, re-assert once
```

## 12. E3 evidence for S7–S12, per scenario

**Final green run: 45944569472 on `34dc023`.** ci ✓, integration ✓, e3 ✓; S1–S12 all
PASS, with no `status=31/SYS` anywhere in the job. The only two `Watchdog timeout`
records are S6's intended ones (05:33:48, 05:34:36). Same rules as 6a: the real unit
installed byte for byte, and the same two drop-ins (`e3.conf`: the testca build, and
`IPAddressAllow=127.0.0.1/32`); S7–S12 add no drop-ins. Bundles and roots are signed at
scenario time with the E3 test root's keys (`e3root --keys-out`,
`bundlesign-test e3-bundle`). Lines below are from that job's log: e3controller stdout
and relayd's audit records in the journal, trimmed to the relevant fields.

Order: S1, S2, testenroll, S3, S5, S6, **S7, S8, S9, S10, S11, S12**, S4 (S4 last,
because revocation is terminal).

**S7: monitor, then enforce, over the stream. PASS.**

```text
canary before any bundle: rc=0
e3controller: [05:34:51Z] sent bundle 1 (s7-monitor.json, digest 4adb4585…)
e3controller: [05:35:06Z] seq=2 heartbeat epochs=map[e3-scope:0]
e3controller: [05:35:21Z] seq=3 heartbeat …   [05:35:36Z] seq=4 …   [05:35:51Z] seq=5 …
e3controller: [05:35:52Z] seq=6 ApplyResult status=APPLIED epoch=1 bundle_digest=4adb4585… loaded_digest_after=0369908e…
e3controller: [05:35:52Z] sent bundle 2 (s7-enforce.json, digest 3a6277d7…)
e3controller: [05:36:06Z] seq=7 heartbeat epochs=map[e3-scope:1] … seq=8, seq=9, seq=10 (05:36:51Z)
e3controller: [05:36:53Z] seq=11 ApplyResult status=APPLIED epoch=2 bundle_digest=3a6277d7…
/usr/local/bin/e3-canary-sh: line 1:  5010 Killed                  /usr/bin/true
canary under the enforce bundle: rc=137
-- restart --
e3controller: [05:36:55Z] seq=2 StateReport epochs=map[e3-scope:2] loaded_digest=026853fe… policies=2
e3controller: StateReport epochs OK: map[e3-scope:2]
```

The journal shows `STEADY -> APPLYING (verified_bundle)`,
`bundle_accepted … epoch=1 mode=monitor`, `applied`, `APPLYING -> STEADY (health_pass)`,
`apply_result status=APPLIED epoch=1`, and then the same for epoch 2 in enforce mode.
There were four heartbeats while each health window ran. The canary (a private copy of
bash at `/usr/local/bin/e3-canary-sh`, the exec caller per ADR 0020) ran cleanly before
the bundles and was SIGKILLed under the enforce bundle. After the restart, the store's
epoch 2 is reported in a StateReport.

**S8: bad signature. PASS.**

```text
e3controller: [05:36:58Z] seq=2 ApplyResult status=REJECTED_SIGNATURE epoch=0 bundle_digest=f27e5917… loaded_digest_after= detail="REJECTED_SIGNATURE: signature verification failed"
journal: "step":"bundle_rejected","detail":"REJECTED_SIGNATURE: signature verification failed"
loaded before: e3-baseline,e3-canary-v1-6ca3d5c1
loaded after:  e3-baseline,e3-canary-v1-6ca3d5c1
```

**S9: replay of S7's enforce bundle. PASS.**

```text
e3controller: [05:37:01Z] seq=2 ApplyResult status=REJECTED_EPOCH epoch=0 bundle_digest=3a6277d7… detail="REJECTED_EPOCH: epoch not greater than current"
loaded before: e3-baseline,e3-canary-v1-6ca3d5c1
loaded after:  e3-baseline,e3-canary-v1-6ca3d5c1
```

`bundle_digest` is the same as S7's enforce bundle (`3a6277d7…`).

**S10: trust update chain v2, v3; persisted across a restart. PASS.**

```text
e3controller: [05:37:04Z] sent TrustUpdate with 2 root(s)
journal 05:37:04.733: "step":"trust_root_adopted","detail":"version 2 (from TrustUpdate)"
journal 05:37:04.751: "step":"trust_root_adopted","detail":"version 3 (from TrustUpdate)"
journal 05:37:04.751: "step":"trust_update_applied","detail":"trust root version 1 -> 3"
e3controller: [05:38:05Z] seq=6 ApplyResult status=APPLIED epoch=3 bundle_digest=0354598b…   (signed by root v3's targets key)
-- restart (RPM root.json is still version 1) --
e3controller: [05:39:08Z] seq=6 ApplyResult status=APPLIED epoch=4 bundle_digest=69d4f53f…   (root v3's targets key again)
```

The trust update was processed before the bundle sent right after it (C2 ordering).
The second bundle verifying after the restart proves version 3 was persisted and
restored: the only root on disk outside the store is version 1.

**S11: out-of-band delete leads to DRIFT and a re-assert. PASS.**

```text
loaded before the delete: e3-baseline,e3-s10-v1-369f9298; victim: e3-s10-v1-369f9298
e3tetra: deleted policy "e3-s10-v1-369f9298" (domain "relay-managed") out of band
loaded after the delete: e3-baseline
journal 05:40:11.020: STEADY -> DRIFT (digest_mismatch)
journal 05:40:11.020: alert kind=DRIFT detail=lkg_bundle_digest=69d4f53f… loaded_digest=e3b0c442… missing=[e3-s10-v1-369f9298] unexpected=[]
journal 05:40:11.020: drift_detected; reconcile_drift "re-asserting LKG once"
journal 05:40:11.639: rolled_back "rolled back: reconcile drift"
journal 05:40:11.639: drift_reasserted "LKG re-asserted; Tetragon matches LKG"
journal 05:40:11.640: DRIFT -> STEADY (reassert_holds)
journal 05:40:11.640: STEADY -> CONNECTING (stream_lost)      (the controller closed after PASS; settled by the worker)
e3controller: Alert DRIFT OK
loaded after the re-assert: e3-baseline,e3-s10-v1-369f9298
```

The drift was found by the periodic cycle 60 s after start. `lkg_bundle_digest` is S10's
second bundle (`69d4f53f…`), and `loaded_digest` is the digest of an empty
relay-managed set. The non-relay `e3-baseline` was never touched. The delete went
through Tetragon's `DeleteTracingPolicy` RPC as root (section 6, deviation 3).

**S12: an enforce bundle kills an admin-path process and is ROLLED_BACK; heartbeats
throughout. PASS.**

```text
S12 trigger shell pid: 5915            (/usr/bin/bash; policy: matchBinaries /usr/bin/bash, matchPIDs [5915] followForks)
e3controller: [05:40:15Z] sent bundle 1 (s12-monitor.json)
e3controller: [05:40:30Z] seq=2 heartbeat … [05:40:45Z] seq=3 … [05:41:00Z] seq=4 … [05:41:15Z] seq=5
e3controller: [05:41:15Z] seq=6 ApplyResult status=APPLIED epoch=5 loaded_digest_after=6aa08024…
e3controller: [05:41:15Z] sent bundle 2 (s12-enforce.json, digest fa4ea154…)
e3controller: [05:41:30Z] seq=7 heartbeat epochs=map[e3-scope:5] loaded_digest=389d29e4…
e3controller: [05:41:45Z] seq=8 heartbeat epochs=map[e3-scope:5] loaded_digest=389d29e4…
   (script: 35 s after bundle 2 was sent, the trigger shell is told to exec /usr/bin/true)
journal 05:41:51.601: health_window_failed "admin_path_enforcement_event"
journal 05:41:52.217: rolled_back "rolled back: admin_path_enforcement_event"
journal 05:41:52.217: APPLYING -> ROLLBACK (health_fail); ROLLBACK -> STEADY (lkg_reasserted)
e3controller: [05:41:52Z] seq=9 ApplyResult status=ROLLED_BACK epoch=6 bundle_digest=fa4ea154… loaded_digest_after=6aa08024…
S12 trigger shell exit status: 137 (137 = SIGKILL)
```

The stream stayed up with heartbeats every 15 s through the enforce bundle's health
window. `loaded_digest_after` (`6aa08024…`) equals the monitor bundle's digest, so the
rollback restored LKG. The store's epoch stayed at 5: the heartbeats show
`e3-scope:5`, and nothing was committed for epoch 6.

## 13. The updated server-contract sections

`docs/server-contract.md` is the source of truth. The changed and new sections:

- **1.5 `ApplyResult`**: exactly one per `PolicyBundle`, including superseded ones; may
  arrive after the health window or after a reconnect.
- **9**: the "not implemented yet" list no longer names the message loop, bundles, trust
  updates or reconcile.
- **10.1** what the agent does with a `PolicyBundle` (no immediate reply; heartbeats
  continue; commit only after the health window).
- **10.2** the pending-bundle rule (one slot; `REJECTED_EPOCH`/`superseded`/epoch 0;
  verified at dequeue).
- **10.3** `ApplyResult` fields (`bundle_digest` = SHA-256 of the envelope, `epoch`,
  `detail`, `loaded_digest_after`) and the status refinements (TAMPERED,
  REJECTED_CAPABILITY for stale facts, not-STEADY, commit failure, ROLLED_BACK,
  ROLLBACK_FAILED).
- **10.4** alerts: every kind, when it fires, what the controller should do; the
  5-minute per-kind rate limit (first always sent); suppressed alerts audited; queueing
  while disconnected (64, oldest dropped, sent first after HelloAck); startup TAMPER not
  yet sent.
- **10.5** `TrustUpdate`: processed after the apply in progress and before a pending
  bundle; versions at or below current skipped; old and new thresholds; persisted per
  step; stop at the first failure with `TRUST_UPDATE_REJECTED`; no reply on success; at
  most 4 queued.

## Progress log

One dated line per push: commit, what changed, the CI result observed.

- 2026-11-27 `da095c6` (with `83512c5` prompt/review, `29def2e` A1, `efb3bd0` atomic commit, `8217553`/`ee93f6b`/`016af02`/`f89ffbd`/`cf6649d` Part B): run 45935962231: ci ✓, integration ✓, e3 ✓. S1–S6 PASS with the apply worker, outbox and real reachability wired in (no S7+ yet).
- 2026-11-27 `77e5222` (with Part C `81e0351`/`418837c`/`fa63f86`/`33ac160`, Part D/E `17e94d7`/`10e8575`/`5185493`/`484af7d`/`8dc9fe7`/`074dbc7`/`c187ecc`, E3 tooling `929efcd`/`f67f6d4`/`5d29c3e`/`08f45bf`, `be3c97e`, runner `/var/run` fix): run 45938072565: ci ✗ at the gofmt check (`cmd/bundlesign-test/e3bundle.go`: a comment inserted into a struct literal broke field alignment); integration and e3 skipped. Fixed in the next commit.
- 2026-11-27 `8df6333` (with `2ac751b` gofmt): run 45938361280: ci ✓, integration ✓, e3 ✗. S1–S6, S8, S4 PASS. S7 FAIL: relayd verified the monitor bundle, entered APPLYING, logged `apply_plan` and loaded `e3-canary-v1-670120fc`, then systemd logged `Main process exited, code=dumped, status=31/SYS`. `apply.PersistDir`'s `fchown` was killed by the unit's `SystemCallFilter=~@privileged` (`@chown`). S9–S12 failed for the same reason (12 SIGSYS exits in the job; S9 got `REJECTED_GUARDRAIL: G5` because the monitor epoch was never committed). S8 PASS shows `REJECTED_SIGNATURE` over the stream. Fixed in the next commit by removing the chown, not by widening the filter.
- 2026-11-27 `846def8` (with `0f0006f` PersistDir chown removal): run 45941496156: ci ✓, integration ✓, e3 ✗. **S1–S10 and S12 PASS, no SIGSYS.** S7: both bundles APPLIED (4 heartbeats while waiting for each), canary killed (rc 137), StateReport `map[e3-scope:2]` after the restart. S8 REJECTED_SIGNATURE, S9 REJECTED_EPOCH, S10 both bundles under root v3 APPLIED, S12 monitor APPLIED then enforce ROLLED_BACK (2 heartbeats). S11 FAIL in the harness: Alert DRIFT received (`missing=[e3-s10-v1-369f9298]`), the policy was loaded again, but the script read the journal once, before relayd had written `drift_reasserted`. The journal also showed `stream_lost is not valid from state DRIFT` when the controller closed the stream mid-episode. Both fixed in the next commits.
- 2026-11-27 `34dc023` (with `722c2e6` DRIFT worker-owned, `3a083ac` S11 waits for its journal records): run 45944569472: ci ✓, integration ✓, e3 ✓. **S1–S12 all PASS**; no SIGSYS; S6's two intended watchdog timeouts only. Section 12 holds the per-scenario evidence.
- 2026-11-27 `24dfd7e` (full report, docs only): run 45947683837: ci ✓, integration ✓, e3 ✓. S1–S12 PASS again on the final commit.
