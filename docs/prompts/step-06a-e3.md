# tetragon-relay — new session: Step 6a E3 (relayd under the production sandbox, end to end)

You are continuing an existing, security-critical project; the repository is the source
of truth. Repo: https://github.com/bshlisky/tetragon-relay (main). Clone it fresh.

## Binding context
- The working agreement in docs/prompts/step-04b.md (Part 0) applies unchanged, including
  the session-size rule and "never widen production privileges to make a test pass".
- This session completes step 6a. Read docs/prompts/step-06a.md (Part E3),
  docs/prompts/step-06a-resume.md, and docs/reports/step-06a.md section 9. Section 9 is
  the plan, and the architect approved it with the constraints below.
- State: everything in step 6a except E3 is done and accepted at 56ac243.

## Architect review of the 56ac243 work (accepted; one low item)
- R6A-1 is accepted: liveness is touched from inside runStreamLoop's own select loop, so a
  hung message handler or blocked send stops the touches and withholds the watchdog. The
  D3 session runner, the R6A-2/R6A-3 fixes, E2, and the StateMachine data-race fix are
  accepted.
- R6A-4 [LOW], do it first: in the connect phase, the liveness touches come from the
  waiting loop while Connect runs in its own goroutine, so a Connect that never returns
  still looks healthy. Give each Connect attempt an overall deadline (dial plus TLS plus
  Hello/HelloAck; constant in internal/limits, well under the 20 s liveness interval or
  with touches only after measurable progress), so a stuck attempt fails, backs off and
  retries. Test with a Connector that blocks forever.

## First actions
1. Commit this prompt verbatim as docs/prompts/step-06a-e3.md ("docs: add step 6a E3 prompt").
2. Run `make ci`; confirm green. Acknowledge with ≤ 10 bullets.

## Constraints on the E3 design (from section 9's plan)
C1. cmd/testenroll is test-only by construction: build tags `testca && testtpm`; never in
    production relayd or the RPM. Add a CI check that builds production relayd (no tags)
    and fails if its symbol table contains any testca/testenroll/TestCA/NewTestEnroller
    symbol (`go tool nm` or `go version -m` plus nm; cite which).
C2. testenroll certifies the TPM-held key from a CSR through the existing
    CertManager.Enroll path (ADR 0030). It never generates or writes a software private
    key. It writes only the certificate chain (and the CA certificate for the trust
    bundle) where relayd expects them.
C3. testenroll runs as a separate, earlier CI step, outside relayd's sandbox. relayd
    itself runs as a transient systemd unit (systemd-run) with every directive from
    packaging/systemd/tetragon-relay.service (same User=, empty capability sets,
    ProtectSystem=strict, ReadWritePaths, ProtectProc=invisible, DeviceAllow and the
    rest). The R3-3 unit-file test's expectations must not change. If the sandbox blocks
    something relayd legitimately needs, stop and report; do not loosen it.
C4. relayd for E3 is built with `-tags testca,testtpm` only because swtpm replaces
    /dev/tpmrm0 and the test CA replaces the enroller. No other behavior may differ
    between that build and production; list every tag-guarded file in the report.
C5. Do the two identity-free scenarios first (SIGTERM; production build stays
    UNENROLLED), then build testenroll, then the identity scenarios.

## Scenarios (all must pass on GitHub Actions)
S1. Production build (no tags): starts under the sandbox, stays UNENROLLED, sends
    READY=1, and Tetragon's loaded set (a pre-applied LKG) is unchanged.
S2. SIGTERM: relayd exits cleanly; Tetragon's loaded policies are unchanged.
S3. Clean start to STEADY: the test controller observes Hello, then heartbeats roughly
    every 15 s (at least 3).
S4. Terminate{REVOKED}: relayd stops reconnecting (the test controller sees no new
    connection for at least 60 s), and Tetragon keeps enforcing.
S5. Controller unavailable: relayd reaches DEGRADED after the 5-minute threshold. You may
    shorten the threshold only through a testca-tagged constant override, documented
    under C4. Tetragon keeps enforcing.
S6. Stalled session runner (a test-tagged hook that blocks the session loop): the
    WATCHDOG=1 ping is withheld, the audit record names the stale component, and systemd
    restarts relayd (the unit's restart counter increases).

## Definition of done
Step 6a complete: ci, integration and TPM jobs, plus the new E3 job, green on GitHub for
the final commit.

## Report
Update docs/reports/step-06a.md: section 9 replaced with E3 evidence per scenario (run
numbers, the observed state transitions and timings, journal excerpts), the C1 symbol-check
output, and the C4 list of tag-guarded files.
