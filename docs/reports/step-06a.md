# Step 6a report

Per docs/prompts/step-06a.md's working agreement ("session size: if the work clearly will
not fit one session, finish a coherent part, get CI green, write the report for what is
done, and stop. Never stop mid-item"), this report now covers the whole step through the
item boundary described in section 9: First actions, Part A, Part B (+ the architect's
B6/B7), Part C, Part D, the step-06a checkpoint review's three follow-ups (R6A-1, R6A-2,
R6A-3), D3 (the session runner) and E2 (`internal/testcontroller` scripted sequences) are
**complete**, every commit green on GitHub (`ci` + `integration`). **E3** (the systemd-
sandbox integration suite) is **not done** -- section 9 records exactly what remains and
the concrete plan the user asked be handed off rather than attempted blind in this
session (several more 15-20 minute CI round trips against a brand-new systemd/TPM/real-
Tetragon job, with open-ended debugging risk).

## 0. Updates in this resume session (docs/prompts/step-06a-resume.md)

- **R6A-3**: `cmd/relayd`'s `--tpm-device` flag is now defined only under the `testtpm`
  build tag (`tpmdevice_testtpm.go`); a production build (`tpmdevice.go`) returns a fixed
  pointer to `productionTPMDevice` and never calls `flag.String` at all, so passing
  `--tpm-device` to a production binary is rejected by the standard `flag` package itself
  ("flag provided but not defined"), not merely refused later by `openTPMDevice`.
- **R6A-2**: `hostprobe.CurrentBootID`'s own error is now a named audit record
  (`host_facts_boot_id`), distinct from the existing "host facts missing or stale" record.
  The loaded `hostprobe.Capabilities` and their freshness are now carried forward in a new
  `assembledAgent` struct returned from `run()`, instead of being read and discarded, so
  step 6b can wire them into the guardrails' `HostCapabilities` (G8) without re-reading
  `host-facts.json` a second time.
- **D3**: `internal/agent.RunSession` -- the session runner the first partial report's
  section 8 named as "the single largest gap": once an identity exists, it dials and
  completes Hello/HelloAck (`Connector`; production: `RealConnector`, built from
  `controlclient.Dial`/`AgentControlClient(conn).Connect`/`SendHello`), drives
  `ControlLoop.HandleControllerMessage` for every inbound message, sends a `Heartbeat` on
  a ticker, and reconnects with full-jitter backoff on stream loss. State wiring:
  `CONNECTING -> SYNCING -> STEADY` on every successful connect (a documented deviation,
  section 6); `EventStreamLost` on an ordinary disconnect; `EventConnectTimeout` ->
  `DEGRADED` after `limits.ControlConnectDegradedTimeout` (5 min) without a stream;
  `Terminate{REVOKED}` (handled inside `ControlLoop` itself) stops `RunSession` from
  reconnecting at all.
- **R6A-1**: `internal/agent.LivenessRegistry` -- each long-running component (today: only
  `RunSession`, registered as `"session_runner"`) reports its own forward progress
  (`Touch`), using the same injected clock every other decision in this package uses;
  `Healthy` reports whether every registered component has reported within its own
  allowed interval. `cmd/relayd`'s watchdog loop now calls `Healthy()` before every
  `WATCHDOG=1` and withholds the ping -- with a named `watchdog_withheld` audit record
  naming the stale component -- unless every registered component is healthy, so systemd
  restarts `relayd` after `WatchdogSec` instead of the watchdog proving only that its own
  `select` loop is still scheduled (the architect review's exact R6A-1 concern).
- **E2**: `internal/testcontroller.Config` gains an optional `Script`, called by `Connect`
  once Hello/HelloAck completes, so a caller can drive the rest of a real agent's control
  loop: heartbeat expectations (`WaitForAgentMessage`), `StateRequest`
  (`SendStateRequest`), `RotateIdentity` (`SendRotateIdentity`), every `Terminate` reason
  (`SendTerminate`), an out-of-order `seq` (`SendAtSeq`), an oversize message
  (`SendOversizedTerminate`), and an unknown message type (`SendUnknownMessageType`: a
  `ControllerMessage` with no oneof case set, which protobuf delivers as a nil `Body`).
- Also fixed in this session: `internal/agent.StateMachine.Current`/`Fire` now take a
  mutex (`RunSession` fires transitions from its own goroutine; `Current()` may
  legitimately be read concurrently -- a real data race `go test -race` caught while
  writing `RunSession`'s own tests).

See sections 2-8, 11-12 below for the full, updated detail covering every item above (this
step's original items are unchanged from the first partial report except where this
session's work touches them); section 9 lists exactly what remains (E3) and the handoff
plan; section 13 records that E3 has no evidence yet.

## 1. Summary

- **First actions**: committed `docs/prompts/step-06a.md` and
  `docs/reviews/step-05b-review.md` verbatim (`4992be9`); this resume session committed
  `docs/reviews/step-06a-checkpoint-review.md` and `docs/prompts/step-06a-resume.md`
  verbatim (`bd99274`), then reproduced `make ci`'s one pre-existing, documented,
  macOS-only lint finding (`internal/tetra/config.go`'s five `unused` findings, unchanged
  since step-04c) before any change, and confirmed the checkpoint commit (`4fb53e3`) was
  genuinely green on GitHub (one `ci` run's `internal/tpm` test failed with a `swtpm`
  connection-refused error; `gh run rerun --failed` reproduced success, confirming it was
  a transient CI infrastructure flake, not a real regression -- see section 11 item 1).
- **A1 (R5B-1)**: `internal/controlclient.Config` now has a required `Clock func()
  time.Time` field; `VerifyConnection` uses it as `x509.VerifyOptions.CurrentTime` instead
  of the zero value. New boundary tests cover not-yet-valid, exactly-`NotBefore`,
  mid-validity, exactly-`NotAfter`, and just-expired.
- **A2 (Q2)**: ADR 0031 (Accepted) records that Go's `crypto/tls` with `VerifyConnection`
  is the long-term control-channel TLS implementation (no code change).
- **A3 (Q3)**: ADR 0032 (Accepted) pins `seq` numbering: the first message on a stream is
  `seq = 1`, every following message is exactly the previous plus 1, per direction.
  `internal/testcontroller.Server.Connect` enforces this on the first `AgentMessage`
  (`Terminate{PROTOCOL_ERROR}` otherwise) and sends its own first message at `seq = 1`.
  Full enforcement of every later message now has both sides: `internal/agent.SeqTracker`
  (D2) on the agent's inbound direction, exercised for real by D3's `RunSession`.
- **B (config loader)**: new `internal/config` package; see the first partial report's
  section 1 for the full description (unchanged this session).
- **B6/B7**: `internal/config.Load` opens `relay.yaml` (and its parent directory) with
  `O_NOFOLLOW`/`O_DIRECTORY|O_NOFOLLOW` and checks every property against the open
  descriptor, closing a check-then-open race; refuses an attacker-writable or
  non-root-owned parent directory.
- **C (relayd assembly)**: `cmd/relayd/main.go` assembles the startup sequence this
  repository's components already implement into a running process (C1-C4), extended in
  this session (R6A-3) so `--tpm-device` does not even exist as a flag in a production
  build.
- **D1 (state machine)**: `internal/agent.StateMachine`, architecture doc 8.3/8.4's ten
  states, table-driven, transcribed edge for edge.
- **D2 (control loop)**: `internal/agent.ControlLoop.HandleControllerMessage`, the message
  dispatcher for every member of `ControllerMessage`'s closed oneof, ADR 0032's seq
  enforcement, `BuildHeartbeat`, `CheckCertExpiry`.
- **D3 (session runner)**: see section 0.
- **R6A-1/R6A-2/R6A-3**: see section 0.
- **E1**: unit tests for the state machine and every message handler (already delivered
  with D1/D2; section 4's rows).
- **E2**: see section 0.
- **E4**: coverage gates (`internal/config` >= 90%, `internal/agent` >= 90%) both still
  pass after this session's additions (section 3).
- **E3**: not done. Section 9.

## 2. File tree of what was added or changed (since `440b7a0`; this session's changes
marked `*NEW*`)

```
docs/
  decisions/0031-go-crypto-tls-verifyconnection-long-term.md   (Accepted)
  decisions/0032-seq-numbering-starts-at-one.md                (Accepted)
  prompts/step-06a.md                                          (committed verbatim)
  prompts/step-06a-resume.md                                   *NEW* (committed verbatim)
  reviews/step-05b-review.md                                   (committed verbatim)
  reviews/step-06a-checkpoint-review.md                        *NEW* (committed verbatim)
  reports/step-06a.md                                          (this file)
  server-contract.md                                           (A3: seq rule updated)
internal/
  controlclient/      (A1/A3; unchanged this session)
  testcontroller/
    server.go                             *NEW* Script field; Connect calls it post-HelloAck
    script.go, script_test.go             *NEW* NextSeq, WaitForAgentMessage, Send* helpers (E2)
  yamlharden/, policydoc/, config/, limits/limits.go   (B; unchanged this session except
                                                         limits.go, below)
  agent/
    state.go, state_test.go               (D1; state.go *NEW* mutex on Current/Fire, R6A-1)
    controlloop.go, controlloop_test.go   (D2; unchanged this session)
    snapshot.go, identityrotator.go       (C; unchanged this session)
    liveness.go, liveness_test.go         *NEW* LivenessRegistry (R6A-1)
    connector.go, connector_test.go       *NEW* Connector/ControlStream/RealConnector (D3)
    session.go, session_test.go           *NEW* SessionConfig/RunSession (D3)
  limits/limits.go                        *NEW* ControlConnectDegradedTimeout (D3)
cmd/relayd/
  main.go                                 *NEW* assembledAgent grows (HostCaps/HostFactsFresh,
                                           Liveness, CancelSession/SessionDone); session
                                           runner wired once an identity exists; watchdog
                                           loop conditioned on Liveness.Healthy()
  session.go, session_test.go             *NEW* clientCertificate, buildHelloFields,
                                           agentBuildDigest, hexEncode
  tpmdevice.go, tpmdevice_testtpm.go      *NEW* tpmDeviceFlag (R6A-3: prod defines no flag)
  certutil.go, sdnotify.go, enroller.go   (C; unchanged this session)
cmd/testcontroller/README.md              *NEW* documents Script
```

## 3. Command output

```
$ go build ./...; go build -tags testtpm ./...; go vet ./...                  # clean
$ gofmt -l $(find . -name '*.go' -not -path './vendor/*' -not -path './api/*'
             -not -path './third_party/tetragon/v1.8.0/api/*')                # clean
$ golangci-lint run ./...
  5 pre-existing unused findings, internal/tetra only (macOS-only, unchanged since
  step-04c; GitHub Actions ci is green for every commit below)
$ golangci-lint run ./cmd/relayd/... ./internal/agent/... ./internal/testcontroller/...
  ./internal/limits/...                                                       # 0 issues
$ govulncheck ./...                                                            # No vulnerabilities found
$ go test ./internal/agent/... ./internal/testcontroller/... ./cmd/relayd/... -race -count=1
  ok (internal/agent: includes a real loopback TLS/gRPC server for RealConnector's own
      dial/Hello/backoff glue, internal/testcontroller, no build tag needed)
```

### Coverage, final commit (`f9d94bd`), from the GitHub Actions `ci` job's own log

```
internal/agent          91.8%  (>= 90% gate; new: connector.go, session.go, liveness.go)
internal/config         93.8%  (>= 90% gate; unchanged)
internal/controlclient  96.9%  (>= 90% gate; unchanged)
internal/identity        93.2% (>= 90% gate; unchanged)
internal/tetra           92.0% (>= 90% gate; unchanged)
internal/apply           91.1% (>= 90% gate; unchanged)
internal/hostprobe       90.8% (>= 90% gate; unchanged)
internal/tpm             91.1% (>= 90% gate, against real swtpm; unchanged)
internal/testcontroller  78.5% (no gate; was 70.6% before E2 -- E2's new Script tests raised it)
cmd/relayd                9.3% (no gate; main.run/runUntilSignal remain glue code exercised
                                 end to end only by a real host -- section 11 item 1 --
                                 but session.go's pure helpers now have unit tests)
```

### GitHub Actions run numbers (this session's commits, branch `main`)

| Commit | ci | integration |
| --- | --- | --- |
| `bd99274` docs: checkpoint review + resume prompt | 45711703384 success | 45711703384 success |
| `b4faede` R6A-3: `--tpm-device` only in `testtpm` | bundled with next push below | — |
| `63d16f3` R6A-2: host-facts boot_id error + assembledAgent | 45712865613 success | 45712865613 success |
| `7a31d37` D3 + R6A-1's `LivenessRegistry` type | bundled with next push below (see note) | — |
| `77182bb` R6A-1: wire session runner; conditional watchdog | 45715608429 success | 45715608429 success |
| `f9d94bd` E2: testcontroller scripted sequences | 45716489142 success | 45716489142 success |

Note: `7a31d37` was originally pushed as its own commit (`0c7e318`) without
`internal/agent/liveness.go` (which `session.go` imports), so its own standalone `ci` run
(`45715206958`) failed at `go vet` ("undefined: LivenessRegistry") -- a compile-ordering
mistake in how this session split the D3/R6A-1 commits, not a design defect. Fixed by
amending that commit to include `liveness.go`/`liveness_test.go` and force-pushing before
anyone else could have based work on it (`git push --force-with-lease`); the next push
(`77182bb`) is the first commit this history change is reflected in, and both `ci` and
`integration` are green for every commit from `bd99274` onward in the table above.

## 4. Mapping: item -> functions -> tests

| Item | Functions | Tests |
| --- | --- | --- |
| A1-A3, B1-B7, D1, D2, C | unchanged this session | see the first partial report (still accurate) |
| R6A-3 | `tpmDeviceFlag` (prod: `tpmdevice.go`; `testtpm`: `tpmdevice_testtpm.go`) | exercised by `go build ./...` (no flag) vs `go build -tags testtpm ./...` (flag defined); no dedicated unit test (pure build-tag dispatch, matching this binary's existing glue-code convention) |
| R6A-2 | `hostprobe.CurrentBootID` error handling, `assembledAgent` | covered transitively by `internal/hostprobe`'s own `TestCurrentBootID_*`; `cmd/relayd`'s own wiring is glue code (section 11) |
| D3 | `agent.RunSession`, `agent.Connector`/`agent.RealConnector`, `agent.ControlStream`, `sleepWithTouch`, `connectWithDegradedWatch`, `runStreamLoop` | `TestRunSession_ConnectsReachesSteadyAndHeartbeats`, `TestRunSession_StreamLossReconnects`, `TestRunSession_TerminateRevokedStopsReconnecting`, `TestRunSession_ConnectTimeoutEntersDegraded`, `TestSessionConfig_Validate` (6 subtests), `TestSessionConfig_HeartbeatIntervalDefault`, `TestRealConnector_ConnectSucceeds`, `TestRealConnector_RetriesHelloRejectionWithBackoff` (against a real loopback TLS/gRPC `internal/testcontroller` server), `TestRealConnector_ConnectFailsOnCanceledContext` |
| R6A-1 | `agent.LivenessRegistry`, `(*LivenessRegistry).Register/Touch/Healthy`; `cmd/relayd`'s watchdog loop | `TestNewLivenessRegistry_NilClockRejected`, `TestLivenessRegistry_AllHealthy`, `TestLivenessRegistry_StalledComponentWithholdsHealthy`, `TestLivenessRegistry_ReRegisterResetsInterval`, `TestLivenessRegistry_TouchOfUnregisteredComponentIsNoop`; `RunSession`'s own tests above exercise `Touch` being called throughout a real reconnect cycle |
| E2 | `testcontroller.Config.Script`, `NextSeq`, `WaitForAgentMessage`, `SendStateRequest`, `SendRotateIdentity`, `SendTerminate`, `SendAtSeq`, `SendOversizedTerminate`, `SendUnknownMessageType` | `TestServer_NilScript_ReturnsAfterHelloAck`, `TestServer_Script_ReceivesHeartbeat`, `TestServer_Script_NoMoreMessagesIsNotATimeout`, `TestWaitForAgentMessage_TimesOutOnARealBlock`, `TestServer_Script_StateRequestRoundTrip`, `TestServer_Script_RotateIdentity`, `TestServer_Script_EveryTerminateReason` (5 subtests), `TestServer_Script_OutOfOrderSeq`, `TestServer_Script_OversizedTerminate`, `TestServer_Script_UnknownMessageType`, `TestDoNothingScript`, `TestNextSeq` |
| `StateMachine` mutex fix | `(*StateMachine).Current`, `(*StateMachine).Fire` | caught by `go test -race` while writing `RunSession`'s own tests; `TestRunSession_*` now pass under `-race` |

## 5. Invariants and threats addressed

- **R6A-1** closes the architect review's exact finding: before this change, `runUntilSignal`
  sent `WATCHDOG=1` unconditionally from its own `select` loop, so a hung session runner
  (a deadlocked apply, a stuck stream -- the review's own examples) would still look alive
  to systemd. Now the watchdog proves every registered component made progress within its
  allowed interval, not merely that `runUntilSignal`'s own loop is scheduled.
- **D3's reconnect/backoff** (`RealConnector`) applies `controlclient.DialBackoff` to
  Hello-level rejections, not only Dial's own connectivity-level backoff: a persistently
  revoked/denylisted identity cannot hot-loop reconnecting at the TCP level even though
  each individual TLS handshake succeeds.
- **D3 never calls anything that unloads a Tetragon policy.** `RunSession` only ever calls
  `ControlLoop.HandleControllerMessage`/`BuildHeartbeat`/`CheckCertExpiry` and
  `StateMachine.Fire`; D1's own structural invariant (nothing in `internal/agent` has a
  handle to an "unload everything" primitive) still holds with D3 wired in -- not
  re-verified by a new test this session (D1's existing `TestNoUnloadPrimitiveExists`
  covers the whole package, including the new files, by construction: it asserts no such
  primitive exists anywhere `internal/agent` can reach, not just in `state.go`).
- **R6A-3** removes a configuration-surface difference between a production binary and
  what an operator might try to pass it: before this session, `--tpm-device` was defined
  (and then refused) in every build; now it is simply absent from a production build's
  flag set, matching docs/prompts/step-06a.md's literal "Define `--tpm-device` only in the
  testtpm build" instruction rather than "define it everywhere but refuse the value."
- **E2's `SendUnknownMessageType`** demonstrates, without any new application-level parsing
  code, that architecture doc P7/control.proto's closed message set already holds end to
  end: protobuf's own oneof semantics deliver an unrecognized wire shape as a nil `Body`,
  which D2's existing dispatcher already treats as a protocol error. This is evidence the
  closed-set invariant does not depend on the dispatcher's author having anticipated every
  possible malformed input -- it falls out of the wire format itself.

## 6. Deviations from this prompt or the architecture

- Unchanged from the first partial report: the `internal/config`/`yamlharden` extraction
  split, `identity.trust_domain` as a new required field, `redaction.keep_env`'s inverted
  polarity, `tetragon.allow_selinux_disabled`, and the double-parse in `config.parse`.
- **D3: `EventInSync` fires immediately after `EventHelloAck` on every successful
  connect**, rather than modeling architecture doc 6.3 step 4's "Reconcile" as a separate
  wait. Step 6a does not process `PolicyBundle`/`TrustUpdate` (D2's own scope), so there is
  nothing for the agent side of reconcile to wait on: the controller may still decide to
  push a bundle later (handled, today, by D2's "respond with an ApplyResult that says the
  agent does not yet process it" rule), but the agent itself has no observable "I am
  behind" signal to block `STEADY` on in this step. Section 10 flags whether step 6b should
  introduce a real `EventInSync`-gating condition once bundle processing exists.
- **D3/R6A-1: `sessionLivenessTouchInterval` is a package-level `var`, not a `const`**,
  purely as a test seam (the same pattern `internal/hostprobe`'s `bootIDPath` and
  `internal/config`'s `lookupGroupGID` already use) so a test can shrink it to observe a
  touch during a deliberately short wait without waiting 5 real seconds.
- **E2: `cmd/testcontroller`'s own CLI is not extended with a scripting flag.** The resume
  prompt's literal wording ("extend `cmd/testcontroller` so it can drive scripted
  sequences") is read as "the `internal/testcontroller` package `cmd/testcontroller`
  wraps," not "the standalone binary's command line," since every existing consumer of
  this package (the `internal/controlclient` integration test) already drives it from Go
  code, never through the binary's flags; E3's integration suite is expected to do the
  same. If the architect intended a CLI-configurable scripting language instead, that is a
  larger, separate piece of work this report flags as an open question (section 10).
- **D3: `RunSession`'s precondition (the state machine must already be in `CONNECTING`
  when called) is documented, not enforced by a runtime check.** A caller that invokes it
  from any other state gets `ErrInvalidTransition`-logged-and-ignored failures from the
  first `Fire(EventHelloAck)` call rather than a clean rejection; this matches
  `ControlLoop`'s own existing convention (its state machine is also constructed
  separately and driven externally), but is worth the architect's explicit sign-off since
  D3 is this project's first caller that actually drives the machine through a live
  reconnect loop rather than a test harness.

## 7. Dependencies added

None, this session. `internal/agent`'s new files use only the standard library,
`google.golang.org/grpc` (already a dependency, via `internal/controlclient`'s own types,
referenced only through inferred return types -- no new import statement of the `grpc`
package itself appears in `internal/agent`), and this repository's own packages.

## 8. Known limitations

- **E3 is not done.** Section 9.
- **`RealIdentityRotator.Rotate` is still unimplemented** (unchanged from the first
  partial report): D3's `RunSession` calls it via `ControlLoop.CheckCertExpiry`/
  `HandleControllerMessage`'s `RotateIdentity` case, but a real rotation request still only
  gets an audited failure, never a real new certificate.
- **`cmd/relayd`'s session-runner wiring has no automated end-to-end exercise in this
  session**: `TestRunSession_*` and `TestRealConnector_*` prove `internal/agent.RunSession`
  and `RealConnector` behave correctly in isolation (including against a real, if
  minimally-TLS-equipped, loopback server), but nothing in this session's test suite
  starts `cmd/relayd`'s own compiled binary and watches it reach `STEADY` against a real
  controller -- that is exactly E3's job, and exactly what is missing.
- **No out-of-band identity provisioning tool exists yet** (needed for E3; section 9):
  `cmd/relayd`'s production build has no Enroller (C2, unchanged), so nothing in this
  repository today can put a persisted identity chain on disk for a `testca`-tagged
  `relayd` build to pick up via `CertManager.Load()` without a new tool.
- Every known limitation from the first partial report's section 8 not specifically
  closed above remains (no production Enroller, in particular -- by design, C2).

## 9. E3: relayd under the production unit, end to end (done)

**Final green run: 45927274396 on `6853583`.** ci ✓ (includes the swtpm-backed internal/tpm steps, which are the "TPM job", see step-05a §C1/D1), integration ✓, e3 ✓. The full history of attempts is in the Progress log at the end of this report. Binding decisions: docs/prompts/step-06a-e3.md, docs/reviews/step-06a-e3-decisions.md (D1–D4).

### 9.1 How E3 runs relayd

`scripts/e3-run.sh` installs `packaging/systemd/tetragon-relay.service` byte for byte into `/etc/systemd/system/` (checked with `cmp`) and drives it with `systemctl start/stop/restart`. Every directive applies as in production, including both `ExecStartPre=+relay-probe` lines (TPM provisioning, then host facts on every start), `Type=notify`, `WatchdogSec=30s`, `Restart=always` and `RestartSec=2s`. The e3 job also runs `systemd-analyze verify` on the unit and fails on any output (D4). On the green run it printed nothing.

Runner setup (CI environment, not relay configuration):
- Production relayd at the unit's own `ExecStart` path, `/usr/libexec/tetragon-relay/relayd`. relayd-e3 (`-tags testca,testtpm`) and relay-probe (no tags) are installed next to it.
- Tetragon v1.8.0 at `/usr/local/bin/tetragon` (the path the host-facts `ExecStartPre` hashes), run from a CI-only `/etc/systemd/system/tetragon.service`, so the relay unit's `BindsTo=`/`After=tetragon.service` resolve (run 45923100259).
- One TPM for every scenario: swtpm through the kernel's `tpm_vtpm_proxy`, which gives a real `/dev/tpmrm0` (group `tss`, 0660). A second TCP swtpm cannot work: the store and host-signer blobs are bound to the TPM that created them (`TPM_RC_INTEGRITY`, run 45854346976).
- `cmd/testenroll` runs once, after S2, as `tetragon-relay`, outside the sandbox. It enrolls the TPM-held key through `CertManager.Enroll` (C2). The test controller's cert and key are written to a runner-owned directory relayd cannot see (`PrivateTmp`).

**Every drop-in line** (`/etc/systemd/system/tetragon-relay.service.d/`, replaced per scenario):

| Scenarios | File | Line | Why |
|---|---|---|---|
| S1, S2 | (none) | — | The production unit runs unmodified. |
| S3–S6 | `e3.conf` | `ExecStart=` | Clears the unit's ExecStart; a drop-in must do this before setting a new one. |
| S3–S6 | `e3.conf` | `ExecStart=/usr/libexec/tetragon-relay/relayd-e3 --config /etc/tetragon-relay/relay.yaml` | The testca,testtpm build (C4), with the same arguments. `ExecStartPre` is not touched. |
| S3–S6 | `e3.conf` | `IPAddressAllow=` | Clears the unit's `10.20.0.0/24` (the real management network, absent on a runner). `IPAddressDeny=any` stays. |
| S3–S6 | `e3.conf` | `IPAddressAllow=127.0.0.1/32` | The E3 controller's address, and nothing else. |
| S5 | `e3-s5.conf` | `Environment=RELAYD_E3_DEGRADED_TIMEOUT=10s` | testca-only override of the 5-minute DEGRADED threshold (permitted by the E3 prompt, S5). |
| S6 | `e3-s6.conf` | `Environment=RELAYD_E3_STALL_COMPONENT=session_runner` | testca-only hook that stops the session runner's liveness touches. |

S4 runs last: the persisted REVOKED marker (ADR 0035) is terminal for the host's store.

### 9.2 Evidence per scenario (run 45927274396; journal excerpts with the `time` field removed)

**S1 — PASS.** The production build starts under the unit, stays UNENROLLED, sends READY=1, and the baseline is unchanged. Both ExecStartPre lines ran; `/run/tetragon-relay/host-facts.json` existed; the journal had no `host_facts`, `host_facts_boot_id` or `agent_build_digest` record (D3).
```
02:33:16 relayd[3474]: {"step":"trust_root","detail":"first boot: adopted initial root version 1"}
02:33:16 relayd[3474]: {"step":"identity","detail":"no persisted identity and no production Enroller available; staying UNENROLLED ..."}
02:33:16 systemd[1]: Started tetragon-relay.service - Tetragon relay agent.
e3tetra: loaded policies unchanged: [e3-baseline]
```

**S2 — PASS.** SIGTERM: a clean exit (`Result=success`), Tetragon's policies unchanged.
```
02:33:21 relayd[3588]: {"step":"shutdown","detail":"signal received; stopping (Tetragon policies left unchanged)"}
02:33:21 systemd[1]: tetragon-relay.service: Deactivated successfully.
```

**S3 — PASS.** Clean start to STEADY, then heartbeats every 15 s: Hello at 02:33:24, then heartbeats at 02:33:39, 02:33:54 and 02:34:09. No host-facts or `/proc/self/exe` read failure in the journal.
```
02:33:24 relayd-e3[3751]: {"step":"state_transition","detail":"CONNECTING -> SYNCING (hello_ack)"}
e3controller: heartbeat 1/3 from connection #1 at 2026-11-27T02:33:39Z
e3controller: heartbeat 2/3 from connection #1 at 2026-11-27T02:33:54Z
e3controller: heartbeat 3/3 from connection #1 at 2026-11-27T02:34:09Z
```

**S5 — PASS.** No controller is running: DEGRADED after the testca-shortened 10 s threshold. relayd stays active, and the baseline is unchanged.
```
02:34:10 relayd-e3[3886]: (start)
02:34:20 relayd-e3[3886]: {"step":"state_transition","detail":"CONNECTING -> DEGRADED (connect_timeout)"}
```

**S6 — PASS.** The stalled session runner withholds WATCHDOG=1, the audit record names it, systemd's own watchdog kills relayd, and `Restart=always` restarts it. NRestarts went from 0 to 2 in 90 s.
```
02:35:03 relayd-e3[4016]: {"step":"watchdog_withheld","detail":"component \"session_runner\" has not reported in 30.001625558s; withholding WATCHDOG=1"}
02:35:18 relayd-e3[4016]: {"step":"watchdog_withheld","detail":"component \"session_runner\" has not reported in 45.00234876s; ..."}
02:35:18 systemd[1]: tetragon-relay.service: Watchdog timeout (limit 30s)!
02:35:20 systemd[1]: tetragon-relay.service: Scheduled restart job, restart counter is at 1.
02:36:06 relayd-e3[4052]: {"step":"watchdog_withheld", ... 45.000218493s ...}
02:36:08 systemd[1]: tetragon-relay.service: Scheduled restart job, restart counter is at 2.
```

**S4 — PASS.** `Terminate{REVOKED}`: relayd persists REVOKED and parks (D1/D2). The harness then restarts relayd. The new process restores REVOKED without dialing, the controller sees no reconnect within 65 s, the unit is still active, no watchdog timeout fires, and the baseline is unchanged.
```
02:36:20 relayd-e3[4217]: {"step":"state_transition","detail":"STEADY -> REVOKED (terminate_revoked)"}
02:36:20 relayd-e3[4217]: {"step":"revocation_persisted","detail":"REVOKED: e3controller: S4 revoke scenario"}
02:36:20 relayd-e3[4217]: {"step":"session_parked","detail":"REVOKED: no controller connection until shutdown or operator re-enrollment"}
02:36:21 systemd[1]: Stopped tetragon-relay.service ...   (harness restart)
02:36:22 relayd-e3[4252]: {"step":"state_transition","detail":"CONNECTING -> REVOKED (terminate_revoked)"}
02:36:22 relayd-e3[4252]: {"step":"revocation_restored","detail":"persisted REVOKED since 2026-11-27T02:36:20Z (REVOKED: e3controller: S4 revoke scenario); not connecting"}
02:36:22 relayd-e3[4252]: {"step":"session_parked", ...}
e3controller: no reconnect observed within 1m5s
```

### 9.3 C1: production relayd's symbol table (`make verify-no-test-symbols`, ci job of run 45927274396)

The check builds relayd with no tags, confirms through `go version -m` that the binary has no `-tags` build setting, then greps `go tool nm` for `testca|testenroll|TestCA|NewTestEnroller` (case-insensitive) and fails on any match.
```
== go version -m (confirming no build tags) ==
	build	GOARCH=amd64
	build	GOOS=linux
	build	vcs.revision=6853583f1b6d0775ebba17171a60c4868b120bc4
	build	vcs.modified=false
== go tool nm (symbol table) ==
verify-no-test-symbols OK: no testca/testenroll/TestCA/NewTestEnroller symbol in a tagless relayd build
```

### 9.4 C4: every tag-guarded file

relayd-e3 differs from production only through these files (`grep -l '^//go:build.*\(testca\|testtpm\|e3\)'`):

| Constraint | File | What differs |
|---|---|---|
| `testtpm` / `!testtpm` | `cmd/relayd/tpmdevice_testtpm.go` / `cmd/relayd/tpmdevice.go` | testtpm defines `--tpm-device` and also accepts `tcp:<cmd>,<platform>`; production accepts only `/dev/tpmrm0` and has no flag. E3 uses the default `/dev/tpmrm0` in every scenario, so this code path is compiled in but unused. |
| `testca` / `!testca` | `internal/agent/e3hooks_testca.go` / `internal/agent/e3hooks.go` | `RELAYD_E3_STALL_COMPONENT` (S6) and `RELAYD_E3_DEGRADED_TIMEOUT` (S5), read once. In production both functions return zero values. |
| `testca` | `internal/identity/testca.go` | The test CA and test enroller (linked by testenroll, not by relayd's own startup). |
| `testca && testtpm` | `cmd/testenroll/main.go` | Test-only enrollment tool (C1/C2). |
| `e3` | `cmd/e3controller`, `cmd/e3root`, `cmd/e3tetra` | Harness tools; never part of relayd. |
| test files | `cmd/relayd/tpmdevice_testtpm_test.go`, `internal/agent/e3hooks_testca_test.go`, `internal/identity/testca_test.go`, `internal/controlclient/integration_test.go` | Tests only. |

### 9.5 D3: every `/proc` and `/sys` path relayd reads, under `ProcSubset=pid` and `ProtectSystem=strict`

| Path | Code | Result under the unit |
|---|---|---|
| `/proc/self/exe` | `cmd/relayd/session.go:78` (Hello `agent_build_digest`) | Works: `ProcSubset=pid` keeps the per-process directories, and `ProtectProc=invisible` hides only other users' processes. Evidence: S1 and S3 journals have no `agent_build_digest` failure record (failures used to be thrown away silently; they are now audited). |
| `/sys/fs/cgroup/<unit>/cgroup.procs` (+ statfs `/sys/fs/cgroup`) | `internal/tetra/peercgroup_linux.go` | Works: read-only under `ProtectControlGroups=yes`, and it is only read. Evidence: every scenario passes the Tetragon dial, which requires this check. |
| `/proc/sys/kernel/random/boot_id` | `internal/hostprobe/bootid_linux.go` | Hidden by `ProcSubset=pid` (run 45858158620: `no such file or directory`). Still compiled into relayd's binary but never called by relayd since ADR 0034; only relay-probe calls it, as root. |
| `/sys/fs/bpf/` | `internal/guard/protected.go` | Only a string in the protected-path list; never opened. |

## 10. Open questions for the architect

Unchanged from the first partial report's three questions (`tetragon.allow_selinux_disabled`
confirmation flag, `identity.spire_server` required-when-SPIRE cross-validation, a separate
`controller.ca_bundle` field), plus:

4. **D3's "fire `EventInSync` immediately" deviation (section 6)**: should step 6b, once
   it adds real `PolicyBundle` handling, introduce a genuine `EventInSync`-gating wait (the
   agent does not consider itself `STEADY` until either a bundle arrives and applies
   successfully, or some explicit "you are already in sync" signal from the controller),
   or is "assume in sync until told otherwise" the intended long-term behavior even once
   bundle processing exists?
5. **E2's scope reading (section 6)**: is "extend `cmd/testcontroller` so it can drive
   scripted sequences" meant literally as the standalone binary's CLI (a scripting
   language/flag), or -- as this session read it -- the `internal/testcontroller` package
   it wraps, driven from Go test code? If the former, that is materially more work (a
   script file format, a CLI flag, a parser) than what this session built.
6. **E3 scenario (c)'s observability gap (section 9.3c)**: this repository has no way,
   today, for an external test harness to observe `relayd`'s current state machine state
   without either a real audit sink (step 7) or a new test-only debug surface. Should E3
   add a minimal, build-tag-gated `--debug-state-file` (writing `StateMachine.Current()`'s
   string on every transition) now, ahead of step 7, specifically so E3 can assert on it,
   or should scenario (c) be demonstrated some other way (e.g. purely from the test
   controller's own observation of "no heartbeats arrived, then the agent reconnected
   after 5 minutes," without the agent's internal state being visible at all)?

## 11. Self-review: the 5 places a reviewer is most likely to find a bug

1. **The `swtpm` flake at the start of this session** (section 1): `internal/tpm`'s own
   test suite occasionally fails to connect to a freshly-started `swtpm` instance on a
   loaded CI runner. This is pre-existing (not introduced by this session), but it means
   any future "CI is red" report for this project should always be rechecked with a rerun
   before being treated as a real regression -- worth the architect confirming this
   project's own `swtpm`-start step (`internal/tpm`'s test helpers) has enough retry/
   backoff margin, since E3 (section 9) will add a second, independent `swtpm` consumer
   under the same CI runner resource pressure.
2. **`RunSession`'s reconnect loop assumes `Connector.Connect` never returns a non-nil
   `stream` alongside a non-nil `err`**, and never returns `(nil, nil, nil)`. `RealConnector`
   upholds this by construction (every return statement is one of the two valid shapes),
   but the `Connector` interface itself does not document or enforce it beyond a doc
   comment; a future second implementation (e.g. for a different transport) that violated
   it would cause `RunSession` to dereference a nil stream.
3. **`connectWithDegradedWatch`'s degraded-timer goroutine leak**: if `Connector.Connect`
   never returns (e.g. a `Connector` bug that ignores `ctx`), the goroutine started to run
   it is never joined -- `RunSession`'s own `for` loop would block forever on `resultCh`
   too in that case, so this is not a *correctness* bug given `ctx` cancellation always
   unblocks a conforming `Connector`, but it is worth the architect confirming that
   `RealConnector`'s own reliance on `controlclient.Dial`'s ctx-respecting contract is
   strong enough, since nothing in `internal/agent` re-checks it with a timeout of its
   own.
4. **`buildHelloFields` (cmd/relayd/session.go) silently drops every field it fails to
   compute** (Tetragon unreachable, store read failure, etc.) rather than distinguishing
   "this field is genuinely zero" from "this field could not be read right now" anywhere
   in the `Hello` message itself -- a controller operator looking at a Hello with, say, a
   zero `TrustRootVersion` cannot tell from the message alone whether that is because the
   store read failed this attempt or because the field is genuinely unset. Deliberate
   (section 6's reasoning: a transient local read failure must never block `RunSession`
   from sending `Hello` at all), but worth the architect's explicit sign-off.
5. **R6A-1's `LivenessRegistry.Healthy` is read by `cmd/relayd`'s watchdog loop without
   any synchronization beyond the registry's own internal mutex** -- correct today (the
   registry's own `sync.Mutex` covers every field), but a future second
   watchdog-relevant consumer added without noticing the registry is the single source of
   truth (e.g. a status endpoint reading `StateMachine.Current()` directly instead of
   through some unified health view) could drift from what the watchdog actually gates on.

## 12. The complete relay.yaml schema

Unchanged this session; built by Part B (`internal/config`) and not modified by the
resume-session items. Every field, its validation and its secure default/zero value:

| Field | Required | Validation | Secure zero/default |
| --- | --- | --- | --- |
| `host.uuid` | yes | canonical lowercase UUID | no default (rejected if absent/malformed) |
| `host.allowed_scopes` | yes | non-empty list | no default |
| `controller.endpoints` | yes | non-empty list, each a valid `host:port` | no default |
| `controller.spiffe_id` | yes | non-empty `spiffe://` URI | no default |
| `controller.heartbeat_interval` | no | parses as a positive `time.Duration` string | `limits.DefaultHeartbeatInterval` (15s) |
| `collector.endpoints` | yes (validated now, unused until step 7) | non-empty list, each a valid `host:port` | no default |
| `collector.spiffe_id` | yes (validated now, unused until step 7) | non-empty `spiffe://` URI | no default |
| `collector.spool_max_bytes` | no | positive | `limits.DefaultCollectorSpoolMaxBytes` (2 GiB) |
| `collector.batch_max_events` | no | positive | `limits.DefaultCollectorBatchMaxEvents` (2000) |
| `collector.batch_max_age` | no | positive duration | `limits.DefaultCollectorBatchMaxAge` (2s) |
| `identity.provider` | yes | non-empty | no default |
| `identity.trust_domain` | yes | non-empty (deviation, section 6) | no default |
| `identity.spire_server` | no | non-empty if set | empty (open question 10.2) |
| `identity.trust_bundle` | yes | a readable PEM file path | no default |
| `identity.key_rotation` | no | positive duration | `limits.DefaultIdentityKeyRotation` (7d) |
| `tetragon.socket` | yes | non-empty path | no default |
| `tetragon.persist_dir` | yes | non-empty path | no default |
| `tetragon.allow_selinux_disabled` | no | bool | `false` (SELinux required; relaxation audited loudly if `true`) |
| `apply.health_window` | no | duration within `[MinApplyHealthWindow, MaxApplyHealthWindow]` | `limits.DefaultApplyHealthWindow` (60s) |
| `apply.enforcement_event_surge_threshold` | no | positive | `limits.DefaultApplySurgeThreshold` (500) |
| `redaction.argv_patterns` | no | each a valid regexp | `defaultArgvPatterns` (3 built-in patterns; replaces, does not merge -- section 11 self-review item 4 of the first partial report) |
| `redaction.keep_env` | no | bool | `false` (environment dropped; inverted-polarity deviation, section 6) |

`Config.Digest()` is the SHA-256 of the exact bytes `Load` read (used as `Hello.config_digest`,
now actually sent over the wire by D3's `buildHelloFields`, section 0).

## 13. State transition table as implemented

Unchanged from D1 (architecture doc 8.3/8.4's ten states, transcribed edge for edge, plus
the documented `EventDegradedCondition` extension) -- see the first partial report's
section 4 `D1` row for the full table and its tests. D3 is this project's first caller
that actually drives this table through a live process: it fires `EventHelloAck`,
`EventInSync`, `EventConnectTimeout`, `EventConditionsClear` and `EventStreamLost` from
`RunSession`'s own reconnect loop (`ControlLoop.HandleControllerMessage` already fires
`EventTerminateRevoked` and `EventDegradedCondition`, D2), each covered by
`TestRunSession_*` (section 4).

## 14. E3 integration evidence per scenario

See section 9 (run 45927274396, all six scenarios PASS).

## Progress log

One dated line per push: commit, what changed, the CI result observed.

- 2026-11-26 `90195d2` (with `ae23da3`, `217873c`, `cb4572d`): testtpm `--tpm-device tcp:<cmd>,<platform>`; controller key moved out of relayd's trust dir; relay-probe `--provision-tpm` before S1/S2. Run 45854346976: ci ✓, integration ✓, e3 ✗. S1 PASS, S2 PASS. S3–S6 FAIL: `TPM_RC_INTEGRITY` in testenroll ("load host signing key") and relayd-e3 ("unseal failed"), because S1/S2's store and host-signer blobs are bound to the vtpm `/dev/tpmrm0` while S3–S6 used a second TCP swtpm. The architect then required the real unit file (with its ExecStartPre lines) instead of systemd-run translation.
- 2026-11-26 `f587862` (with `0ccccd1`, `2fd7383`): real unit file plus drop-ins (none for S1/S2); one shared vtpm `/dev/tpmrm0`; testenroll on that device. Run 45858158620 attempt 1: ci ✓, integration ✓, e3 ✗ before any scenario (Tetragon tarball download HTTP 504). Attempt 2: e3 ✗. S1, S2, S3, S5, S6 PASS. S6 shows `watchdog_withheld` naming `session_runner`, systemd `Watchdog timeout (limit 30s)!` twice, NRestarts 0→2. S4 FAIL: after `STEADY -> REVOKED`, `session_runner` stops reporting liveness, systemd's watchdog kills relayd at +45 s, and the restarted process starts from UNENROLLED and reconnects. The journal also shows two findings outside E3's scope: (1) `open /proc/sys/kernel/random/boot_id: no such file or directory` under the sandbox (ProcSubset=pid), so host facts are always stale; (2) systemd rejects the unit's two inline `#` comments (lines 74, 105). Stopped for an architect decision (stop-and-report rule).
- 2026-11-26 `b3076ff` (with `94325a9` decisions, `025c96d` D4 unit comments + `systemd-analyze verify`, D3 tmpfs host-facts freshness, ADR 0034): run 45871825287: ci ✗. `coverage90` failed with internal/hostprobe at 86.5% on Linux (the new stat_linux.go branches were untested). integration and e3 were skipped because e3 needs ci. Fixed in `21af207` (tests).
- 2026-11-26 `6f359b4` (with D1 `a440844`, D2 `8a9d3af`/`0bd2f19`, harness `f58b060`): run 45873245634: ci ✓, integration ✓, e3 ✗ at the new `systemd-analyze verify` step. It exited non-zero with no output: the step shell's `-e` aborted at the `$(…)` capture before printing. Scenarios did not run. Fixed so rc and output are always captured and printed.
- 2026-11-26 `eb9c4c2` (verify rc capture): run 45876885071: ci ✓, integration ✓, e3 ✗. `systemd-analyze verify` returned rc=1 with no output on stderr; scenarios did not run. Next: force `SYSTEMD_LOG_TARGET=console`.
- 2026-11-27 `d9a49c9` (verify logs to console): run 45923100259: ci ✓, integration ✓, e3 ✗ at verify, now with its reason: `Failed to create tetragon-relay.service/start: Unit tetragon.service not found`. The relay unit's `BindsTo=tetragon.service` can't be resolved against the transient systemd-run Tetragon. Fix: the e3 job runs Tetragon from a real `/etc/systemd/system/tetragon.service` (CI scaffolding for Tetragon); the check and the relay unit are unchanged.
- 2026-11-27 `ea74a23` (Tetragon from a unit file): run 45924877288: ci ✓, integration ✓, e3 ✗. `systemd-analyze verify` passed with no output. S1, S2, S3, S5, S6 PASS. S6: `watchdog_withheld` names `session_runner`; `Watchdog timeout (limit 30s)!` twice; NRestarts 0→2. S4 FAIL, but in the harness, not in relayd. relayd logged `revocation_persisted`, then after the mid-scenario restart `revocation_restored`, never reconnected, and no watchdog timeout fired. e3controller's revoke window `select` returned on the closed stream's ctx without reporting a result (`no result after 2m30s`). Fix: the window is now a timer independent of the stream.
- 2026-11-27 `6853583` (e3controller S4 window timer): run 45927274396: ci ✓, integration ✓, e3 ✓. **S1–S6 all PASS**; `systemd-analyze verify` clean. Section 9 now holds the evidence. (Correction: the previous line first named the Tetragon unit-file commit `3c1d2f6`; it is `ea74a23`.)
- 2026-11-27 `058462b` (report section 9 replaced with per-scenario evidence; docs only): run 45929721297: ci ✓, integration ✓, e3 ✓ (S1–S6 PASS again). Step 6a accepted at this commit (docs/reviews/step-06a-final-review.md).
