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

## 9. What remains: E3

**Not started.** docs/prompts/step-06a.md Part E3: integration (CI) running `relayd` as a
real process under the production systemd unit's sandbox settings (`User=`, empty
capabilities, `ProtectSystem=strict`, `ReadWritePaths`, `ProtectProc=invisible`), with
swtpm via the `testtpm` build tag, against real Tetragon and the test controller, plus the
step-06a-resume.md R6A-1 addition (a sixth scenario: a stalled session runner, via an
injected test hook, causes the watchdog ping to be withheld and systemd restarts `relayd`).

This was deliberately not attempted in this session (the user's own choice, offered three
options: attempt E3 now, a partial E3 covering only the non-enrollment scenarios, or stop
and report -- "stop and report" was chosen) given the realistic cost: a brand-new CI job
combining systemd, a real TPM (swtpm), real Tetragon and a from-scratch identity-
provisioning step has meaningful open-ended debugging risk, at ~15-20 minutes per GitHub
Actions round trip, with no way to iterate faster from this environment.

### The concrete blocker and its resolution, worked out in this session

Three of E3's scenarios (controller-unavailable -> DEGRADED, clean-start-to-STEADY,
Terminate{REVOKED}) need `relayd` to actually hold an enrolled identity, which production
builds never do (C2: no production Enroller exists). `internal/identity.TestCA`/
`NewTestEnroller` (build tag `testca`) already provide exactly the in-process enrollment
primitive `internal/controlclient`'s own integration test uses, but `relayd` runs as a
**separate OS process** under E3 (not an in-process test), and `TestCA.issue` needs the
CA's private key, which cannot reasonably be handed to `relayd` itself (that would make
`relayd` its own CA, a different and more confusing test shortcut than this project's
existing ones).

The resolution (not yet built): a new **out-of-band provisioning tool**,
`cmd/testenroll` (build tags `testca && testtpm`), run by the E3 CI job *before* starting
`relayd`, not by `relayd` itself:

1. Opens the **same** TPM device (the `tcp:host:port` swtpm transport
   `cmd/relayd/tpmdevice_testtpm.go` already supports) `relayd` will use.
2. Calls `tpm.NewOrLoadHostSigner(tp, storeDir+"/host-signer.json")` -- the exact same
   function and path `cmd/relayd/main.go`'s own `run()` calls -- to obtain (and persist)
   the host's TPM-backed signer, so `relayd`, started afterward, loads the identical key.
3. Constructs an `identity.NewTestCA(ttl)`, writes its certificate to the path
   `relay.yaml`'s `identity.trust_bundle` will point at, and issues the test controller's
   own server certificate from the same CA (the documented test-only simplification
   section 6/the first partial report's section 6 already records: one CA for both agent
   and controller certificates in tests).
4. Issues a one-time join token (`ca.IssueJoinToken()`) and calls
   `identity.NewCertManager(...).Enroll(ctx, now)` with `identity.NewTestEnroller(ca,
   token)` as the enroller -- the **same** `CertManager.Enroll` code path
   `docs/reports/step-05b.md` already built and tested, just invoked from this new tool
   instead of from inside `relayd`. `Enroll` already calls `persistChain(cfg.StoreDir,
   chain)` internally, writing the chain to the exact `storeDir` constant `cmd/relayd/
   main.go` passes to its own `identity.Config.StoreDir`.
5. `relayd` (built with `testca,testtpm` tags for this job only -- a production build is
   never touched by this tool or given a way to invoke it) is started *after* this tool
   exits 0. Its own `certManager.Load()` call (already unconditional in `cmd/relayd/
   main.go`, today only ever finding `ErrNoPersistedChain`) finds the chain this tool
   persisted, and D3's `RunSession` goroutine starts for real, exactly as this session's
   `cmd/relayd/main.go` wiring already does when `len(certManager.Chain()) > 0`.

This needs **no new network protocol, no new wire format, and no change to any production
code path** -- `cmd/testenroll` is purely new test infrastructure, calling existing,
already-tested library functions out of process order relative to where they are normally
called. The two scenarios that need no identity at all (SIGTERM leaves Tetragon's policies
unchanged; a production build starts, stays UNENROLLED, still enforces LKG) do not need
this tool and could be built first.

### Remaining E3 work, in the order a fresh session should tackle it

1. `cmd/testenroll` (above).
2. A CI job (new, or an addition to `.github/workflows/ci.yml`'s existing `integration`
   job) that: installs `swtpm` (already done for the `tpm`/`internal/tpm` coverage job --
   reuse that step); starts it; provisions the SRK and NV counter (`relay-probe
   --provision-tpm`, already exists); writes `relay.yaml`, the TPM-backed host-facts file,
   and the RPM-shipped initial trust root to the paths `cmd/relayd/main.go`'s constants
   expect; runs `cmd/testenroll` for the scenarios that need it; starts the real Tetragon
   binary (the existing `integration` job's own steps already do this, reusable almost
   verbatim); starts `internal/testcontroller`'s server (via a small new test-only driver
   binary or a Go test's own `grpc.Serve` call, with an E2 `Script` per scenario) listening
   on the address `relay.yaml`'s `controller.endpoints` names; starts `relayd` itself as a
   **transient systemd unit** (`systemd-run` with every directive
   `packaging/systemd/tetragon-relay.service` declares, matching how the existing
   `integration` job already starts Tetragon itself as a transient unit, step-03a-review.md
   R3-1's own precedent) built with `-tags testca,testtpm`.
3. The six scenarios themselves, each asserted from the CI job's own shell/Go steps:
   a. Clean start to STEADY with heartbeats arriving (`internal/testcontroller`'s `Script`
      calls `WaitForAgentMessage` in a loop and asserts at least two `Heartbeat`s arrive).
   b. `Terminate{REVOKED}` (`Script` calls `SendTerminate(..., controlv1.Terminate_REVOKED,
      ...)`) stops reconnecting -- assert no new TCP connection arrives at the test
      controller's listener for some bounded window afterward.
   c. Controller unavailable (close the test controller's listener, or never start it for
      this scenario) leads to `DEGRADED` after the threshold -- needs a way to observe
      `relayd`'s own state from outside the process (not built yet; an operator-facing
      status surface does not exist in this repository at all today -- the simplest
      option is almost certainly reading `relayd`'s own structured audit log once a real,
      non-`FakeAuditor` sink exists, step 7 scope, or a new, test-only `--state-file` debug
      flag gated behind a build tag, which would need its own small design) -- while
      confirming Tetragon's own `ListTracingPolicies` output is unchanged throughout
      (the existing `integration` job's own pattern for "nothing unexpected is loaded").
   d. SIGTERM leaves Tetragon's loaded policies unchanged -- `systemctl stop` the unit,
      then run the existing `apply.itest`'s `TestZZZFinalCheck_NoTracingPoliciesLeftLoaded`-
      style check.
   e. A production build (no test tags) starts, stays `UNENROLLED`, still enforces LKG --
      needs no `cmd/testenroll` step at all; can be built and verified first,
      independently of the rest.
   f. (R6A-1's addition) A stalled session runner, via an injected test hook, causes the
      watchdog ping to be withheld and systemd restarts `relayd` -- needs a new,
      test-only hook into `LivenessRegistry` (e.g. a build-tag-gated environment variable
      `relayd` checks once at startup to skip calling `Liveness.Touch` from a specific
      component, or a SIGUSR1-triggered pause) that a production build can never reach;
      not designed yet.
4. Update this report's section 13 with the evidence per scenario and the run numbers,
   per docs/prompts/step-06a.md's own report instructions.

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

None. E3 is not done (section 9).

## Progress log

One dated line per push: commit, what changed, the CI result observed.

- 2026-11-26 `90195d2` (with `ae23da3`, `217873c`, `cb4572d`): testtpm `--tpm-device tcp:<cmd>,<platform>`; controller key moved out of relayd's trust dir; relay-probe `--provision-tpm` before S1/S2. Run 45854346976: ci ✓, integration ✓, e3 ✗. S1 PASS, S2 PASS. S3–S6 FAIL: `TPM_RC_INTEGRITY` in testenroll ("load host signing key") and relayd-e3 ("unseal failed"), because S1/S2's store and host-signer blobs are bound to the vtpm `/dev/tpmrm0` while S3–S6 used a second TCP swtpm. The architect then required the real unit file (with its ExecStartPre lines) instead of systemd-run translation.
- 2026-11-26 `f587862` (with `0ccccd1`, `2fd7383`): real unit file plus drop-ins (none for S1/S2); one shared vtpm `/dev/tpmrm0`; testenroll on that device. Run 45858158620 attempt 1: ci ✓, integration ✓, e3 ✗ before any scenario (Tetragon tarball download HTTP 504). Attempt 2: e3 ✗. S1, S2, S3, S5, S6 PASS. S6 shows `watchdog_withheld` naming `session_runner`, systemd `Watchdog timeout (limit 30s)!` twice, NRestarts 0→2. S4 FAIL: after `STEADY -> REVOKED`, `session_runner` stops reporting liveness, systemd's watchdog kills relayd at +45 s, and the restarted process starts from UNENROLLED and reconnects. The journal also shows two findings outside E3's scope: (1) `open /proc/sys/kernel/random/boot_id: no such file or directory` under the sandbox (ProcSubset=pid), so host facts are always stale; (2) systemd rejects the unit's two inline `#` comments (lines 74, 105). Stopped for an architect decision (stop-and-report rule).
- 2026-11-26 `b3076ff` (with `94325a9` decisions, `025c96d` D4 unit comments + `systemd-analyze verify`, D3 tmpfs host-facts freshness, ADR 0034): run 45871825287: ci ✗. `coverage90` failed with internal/hostprobe at 86.5% on Linux (the new stat_linux.go branches were untested). integration and e3 were skipped because e3 needs ci. Fixed in `21af207` (tests).
- 2026-11-26 `6f359b4` (with D1 `a440844`, D2 `8a9d3af`/`0bd2f19`, harness `f58b060`): run 45873245634: ci ✓, integration ✓, e3 ✗ at the new `systemd-analyze verify` step. It exited non-zero with no output: the step shell's `-e` aborted at the `$(…)` capture before printing. Scenarios did not run. Fixed so rc and output are always captured and printed.
