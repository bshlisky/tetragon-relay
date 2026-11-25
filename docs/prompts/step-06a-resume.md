# tetragon-relay — new session: Step 6a resume (session runner, watchdog, E2/E3)

You are continuing an existing, security-critical project; the repository is the source
of truth. Repo: https://github.com/bshlisky/tetragon-relay (main). Clone it fresh.

## Binding context
- The working agreement in docs/prompts/step-04b.md (Part 0) applies unchanged, including
  the session-size rule.
- This session finishes docs/prompts/step-06a.md. Read that prompt, docs/reports/step-06a.md
  (especially section 9) and the attached checkpoint review. First actions, Parts A, B
  (B6/B7 too), C and D1–D2 are done at 4fb53e3; do not redo them.

## First actions
1. Two files are ATTACHED: this prompt and step-06a-checkpoint-review.md. Commit them
   verbatim in one commit ("docs: add step 6a checkpoint review and resume prompt"):
   - docs/reviews/step-06a-checkpoint-review.md
   - docs/prompts/step-06a-resume.md
2. Run `make ci`; confirm green. Acknowledge with ≤ 10 bullets: the plan below.

## Work, in order (push after each; ci, integration and TPM jobs green before the next)
1. R6A-3: --tpm-device only in the testtpm build.
2. R6A-2: host-facts error surfaced; facts kept in the assembled agent for 6b.
3. D3 plus the missing wiring: a session runner (internal/agent) that, once an
   identity exists, dials with controlclient, runs Hello/HelloAck, then drives
   ControlLoop (inbound dispatch), the 15 s heartbeat ticker and the state machine
   (CONNECTING → SYNCING → STEADY; stream loss → CONNECTING with full-jitter backoff;
   DEGRADED after 5 minutes without a stream; Terminate{REVOKED} stops reconnecting).
   Production builds still have no enroller, so they never reach it (stay UNENROLLED).
   The testca build uses the test enroller so CI can exercise it.
4. R6A-1: the liveness registry and conditional watchdog, with the session runner as
   its first registered component.
5. E2: extend cmd/testcontroller to drive scripted sequences, per step-06a Part E2.
6. E3: integration in CI running relayd as a real process under the production systemd
   unit's sandbox settings (same User=, empty capabilities, ProtectSystem=strict,
   ReadWritePaths, ProtectProc=invisible), built with the testca and testtpm tags,
   against real Tetragon and the test controller. All five scenarios from step-06a E3,
   plus one more: a stalled session runner (injected test hook) causes the watchdog ping
   to be withheld and systemd restarts relayd.

## Definition of done
Step 6a complete: ci, integration and TPM jobs green on GitHub for the final commit, with
E3 passing.

## Report
Update docs/reports/step-06a.md to cover the whole step (sections 1–13 of the step 6a
prompt), including E3 evidence per scenario and the run numbers.
