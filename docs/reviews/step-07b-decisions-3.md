# Architect decisions: step 7b, after session 3 (origin/main @ d9681e8)

Reviewer: architect · Date: 2026-11-28

**Session 3 is accepted, and its central finding is the most important one of the
project so far.** Under an exec flood, an enforce bundle that killed an admin-path process
was committed as `APPLIED`, because the health window saw no events and treated that
silence as health. Two things went right here:

- P5's enforce case (E1.1) was added to test exactly this, and it caught the problem
  three runs out of three.
- Claude Code held the gate instead of explaining the failure away.

The supporting work is also good:

- T-S6 proves that Tetragon drops events for a slow client **with no signal on the
  stream**.
- V2 proves the secret-token check isn't vacuous: a client with no filter does see the
  token.
- The aggregation check (E1.5) was reported, not built on.

## F0 [CRITICAL] The health window must fail closed when observation is unverifiable

**The principle.** In the health window, the absence of events counts as evidence only
when the observation path has been proven current for the whole window. Otherwise the
window's result is **unverifiable**, and an unverifiable window never commits.

This bug is the same class as the step 1 fail-open findings: missing input read as
success.

### F0.1 Freshness sentinel (this answers Q1: approved, with this design)

- **A sentinel policy**, `relay-sentinel`:
  - relay-managed, loaded at startup and re-asserted by reconcile like LKG, but kept out
    of the LKG set and `loaded_digest` (its own documented exception, recorded in an
    ADR);
  - it hooks one harmless operation that **relayd itself** performs, with `Post` only
    and no enforcement action.
- **Proposed hook.** Verify it on the real v1.8.0; don't guess. Use a kprobe or LSM hook
  on file open, with:
  - `matchBinaries` = the relayd binary path;
  - `matchArgs` with a path prefix of `/var/lib/tetragon-relay/sentinel/` (already in
    `ReadWritePaths`; no unit change).

  relayd opens `/var/lib/tetragon-relay/sentinel/<nonce>`, and the event carries the
  path, which carries the nonce. If a better hook exists that needs no extra privilege,
  propose it.
- **The window's stream subscribes to the new policies plus `relay-sentinel`.**
  - relayd fires a sentinel at the window's start and every 2 s after.
  - Each sentinel must arrive within `limits.SentinelMaxLatency` (proposed 3 s).
  - The window may pass only after the sentinel fired **at or after the window's
    nominal end** has arrived, plus a 1 s settling margin for per-CPU ring-buffer
    reordering.
- **A sentinel that is late or missing makes the window unverifiable:**
  1. Extend the window, re-firing sentinels, until the observation path is current
     again for a full nominal window, up to the bundle's maximum (600 s).
  2. If it never recovers, roll back with a new status `ROLLED_BACK_UNVERIFIABLE`
     (proto, ADR, contract) and `Alert{HEALTH_UNVERIFIABLE}`, carrying the measured
     sentinel latencies.
- **Accepted consequence:** a sustained flood can delay an enforce rollout. A delayed
  rollout is recoverable and visible to the controller. A silent admin lockout
  committed as `APPLIED` is neither. The monitor-first rule (G5) already limits what an
  enforce bundle can surprise us with.
- **Ordering caveat for the ADR:** a sentinel arriving proves Tetragon's pipeline has
  caught up to that point. It does **not** prove that no earlier event was dropped. That
  is what F0.2 covers.

### F0.2 Don't let our own load starve the window's stream; measure before shedding

- Sessions 2 and 3 show two different bottlenecks: relayd at its quota (the telemetry
  receive) and Tetragon's own backlog (about 1 core, 4–5 GB). The sentinel detects
  both, but only relayd's is ours to fix.
- Instrument the window: sentinel latency, relayd's cgroup throttling during the
  window, and the window stream's receive rate.
- If P5 shows that the window's stream is late **because relayd is throttled**, then:
  - during a health window, re-open the telemetry stream with a `deny_list` for
    `process_exec`/`process_exit` (filtered at the source);
  - declare it in the chain as `dropped{reason: health_window_shed, estimated count}`;
  - restore the stream when the window ends.

  If the lateness is Tetragon's own backlog, shedding won't help, and F0.1's
  extend-then-roll-back is the answer. **Decide from the P5 data; record it in
  ADR 0041.**

### F0.3 P5 is the acceptance test

P5's enforce case must end in `ROLLED_BACK` (the kill was observed once the path caught
up) or `ROLLED_BACK_UNVERIFIABLE`. **It must never end in `APPLIED`.** Add a monitor case
under the same flood: it must end `APPLIED` after the extension, or
`ROLLED_BACK_UNVERIFIABLE`. Report which it was and the sentinel latencies.

Add a unit-level mutation test: the health window with a stub stream that delivers
nothing must never pass.

## F1 [HIGH, new] Under an exec flood, Tetragon's memory can bring down enforcement

Tetragon's memory grew 4–5 GB in 60 s. On a production host, this can OOM-kill Tetragon,
or the host can OOM-kill something else. If Tetragon dies, enforcement is off until it
restarts and reloads `tp.d`. An attacker who can exec in a loop could use this to switch
enforcement off. This is a Tetragon deployment issue, not a relayd one, but it belongs to
us because we specify Tetragon's configuration (architecture 9.1).

- **In session 4 (measurement only):**
  - extend T-S6 to record Tetragon's RSS against time over a 3-minute flood, and
    whether it plateaus;
  - from the v1.8.0 binary's `--help`, list the flags that bound its internal queues
    and caches (event queue size, process cache size, or whatever exists);
  - re-run with each one set to a small value, and record the effect on RSS and
    whether enforcement (the S7 canary kill) still works. Report only.
- **In step 8 (packaging):** pin Tetragon's memory-bounding flags in the
  `tetragon.conf.d` drop-ins we ship, decide on the "keep sensors on exit" setting
  (9.1), and give `tetragon.service` a `MemoryHigh`. I'll write those decisions from
  your data.

## F2 (Q2) Drop estimation by pairing exec and exit: yes, as an estimate, clearly labelled

- Pair exec and exit events on `exec_id`, only for processes whose start time is after
  the stream's start; older processes can't be paired.
- An exit whose exec was never seen counts as one dropped exec. Exits that are never
  seen can't be counted reliably (long-lived processes), so don't count them.
- Every 60 s, emit `dropped{reason: tetragon_unsignalled, estimated: true, count}` when
  the count is above zero, and raise `Alert{TELEMETRY_LOSS}` (rate-limited) when the
  estimate exceeds 1 % of received events.
- The contract must say plainly that this is a lower bound.
- **Also check, and report:** can Tetragon v1.8.0 serve its metrics on a unix socket?
  Its drop counter is the authoritative number. relayd can't reach `127.0.0.1:2112`
  under `IPAddressDeny=any`, and I won't widen that without a design (a scoped
  `IPAddressAllow` plus an SELinux `name_connect` restriction). Report what's possible;
  don't change the unit.

## F3 (Q4) Keep the chunked handoff; remove the gRPC buffer settings

- **The chunked handoff stays.** Its local gain is real (about 25 %), and E3 can't show
  it only because Tetragon is the bottleneck there. Its tests must cover the partial
  chunk and the shutdown drain.
- **Remove the gRPC buffer settings.** A setting with no measured effect is an
  unexplained knob that someone will "tune" later. Revert them, and note why in
  ADR 0041.

## F4 (Q3) Production Tetragon runs **without** `--enable-process-environment-variables`

Environment variables are the commonest place for secrets. Even though relayd drops
them, Tetragon would collect them for every exec, hold them in memory, and hand them to
any other client of its socket or file exporter. Collecting nothing is the only safe
setting.

- The field filter and redaction stay, as defense in depth.
- **`keep_env` is removed from Part S (D3).** With the flag off it can do nothing, and
  an unused relaxation is a liability.
- **relay-probe reports the flag's presence in the host facts**, and `Hello` reports it.
  If it's present, enforce bundles still apply (it's a privacy issue, not an
  enforcement one), but relayd raises a new alert kind, `TETRAGON_ENV_COLLECTION`,
  once per connection. Step 8 packaging ships the configuration without the flag.
- T-S1 keeps using the flag in E3, because that's how it proves redaction works.

## Session 4 scope and order

1. Progress line for d9681e8.
2. **F0** (sentinel, extend then roll back, the new status and alert, unit mutation
   test, P5 enforce and monitor cases). e3 must be green with P5 passing.
3. **F0.2** instrumentation, and the shed-or-not decision from P5 data.
4. F3 (revert the buffer settings).
5. Part S without `keep_env`, plus E1.4 `deny_list` guardrails, then T-S7.
6. F2, and F4's host fact and alert.
7. D2's contract and heartbeat field, S6's contract additions, ADRs 0039 and 0041
   Accepted.
8. F1 measurement (report only).

Stop at a green boundary after item 3 if the session runs long. F0 must not be split
across sessions in a non-green state.

**Definition of done for 7b:** as in decisions-2, plus:

- P5's enforce case never `APPLIED`;
- the sentinel ADR Accepted;
- the F1 measurements in the report.
