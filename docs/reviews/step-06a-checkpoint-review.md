# Architect review: step 6a checkpoint (origin/main @ 4fb53e3)

Reviewer: architect · Date: 2026-11-25 · Verdict: **Checkpoint accepted.** Parts A, B
(including B6/B7), C and D1–D2 are accepted. Step 6a is not complete: D3 (the session
runner with reconnect and backoff), E2 and E3 remain, plus three follow-ups (R6A-1 to
R6A-3). All are done in the step 6a resume session.

## Verified by reading

- B6/B7: relay.yaml is opened with O_NOFOLLOW and checked on the open descriptor, and the
  parent directory must be root-owned and not group- or other-writable.
- Production builds: the TPM transport is `/dev/tpmrm0` only (swtpm only under the
  `testtpm` tag), and the enroller is a no-op that never falls back to the test CA, so a
  production agent stays UNENROLLED while LKG keeps enforcing.
- Shutdown: SIGTERM records an audit event and returns without touching Tetragon's
  loaded policies.
- Startup order: config, TPM, store and trust root (including LKG re-verification),
  host facts, Tetragon client (peer verification), apply engine, identity. Each failure
  is fail-closed.

## R6A-1 [MEDIUM] The watchdog proves only that a timer fires

`runUntilSignal` sends `WATCHDOG=1` every 15 s from its own select loop, unconditionally.
Once the session runner, apply engine and reconcile run in their own goroutines, a hung
component (a deadlocked apply, a stuck stream) will still look alive to systemd, so the
watchdog will never restart a wedged agent.

Required:
- Each long-running component (session runner; later the reconcile scheduler, 6b; the
  telemetry shipper, 7) reports progress through a liveness registry: a last-progress
  timestamp per component, using the injected clock.
- `WATCHDOG=1` is sent only when every registered component has reported within its
  allowed interval. Otherwise the ping is withheld and an audit record names the stale
  component, so systemd restarts relayd after WatchdogSec.
- Blocking waits (backoff sleeps, health windows) count as progress only if the
  component reports before and after them; make their maximum durations shorter than
  the watchdog interval, or have them report while waiting.
- Tests: a stalled component causes the ping to be withheld; all-healthy pings.

## R6A-2 [LOW] Host facts: surface errors and keep the result for 6b

`hostprobe.CurrentBootID()`'s error is discarded. Record it in the audit event. Also keep
the loaded host facts and their freshness in the assembled agent, so step 6b can wire them
into the guardrails' HostCapabilities (G8) without re-reading them. Add a comment pointing
to that.

## R6A-3 [LOW] No --tpm-device flag in production builds

The step 6a prompt allows only `--config` and `--version`. Define `--tpm-device` only in
the `testtpm` build. Production builds hard-code `/dev/tpmrm0` and reject the flag as
unknown.
