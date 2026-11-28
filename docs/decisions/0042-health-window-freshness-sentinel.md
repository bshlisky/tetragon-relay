# ADR 0042: The health window fails closed when observation is unverifiable

## Status

Proposed (docs/reviews/step-07b-decisions-3.md F0). Amends architecture 7.7 steps 6–8
(the health window) and step 3 Part D5. Retires `limits.HealthWindowDeadlineTolerance`
(step-03b-review.md R3B-2). Accepted once P5 shows the enforce case never `APPLIED`.

## Context

Step 7b session 3 (P5, E1.1) ran an enforce bundle during an exec flood of about 10k
events/s. Its policy killed an admin-path shell (exit 137), but the kill event never
reached relayd's health window, which saw no events, read that silence as health, and
committed epoch 8 as `APPLIED`. It failed the same way in three runs (46121973985,
46126491257, 46131312207). Tetragon ran at about one core; its drop counters stayed flat
while its RSS grew by about 5 GB, so its own processing was behind the kernel. No kprobe
event of any kind reached relayd during the flood.

This is the step 1 fail-open class again: missing input read as success.

## Decision

**In the health window, the absence of events counts as evidence only while the
observation path is proven current. Otherwise the window is unverifiable, and an
unverifiable window never commits.**

### The sentinel policy

- `relay-sentinel-<8 hex>`: one kprobe on `security_file_open` with the `file` argument,
  `matchBinaries In <relayd's own executable>` and `matchArgs Prefix
  /var/lib/tetragon-relay/sentinel/`. No `matchActions`: the default action is `Post`,
  so it never enforces anything (`internal/apply/sentinel.go`).
- relayd fires a sentinel by opening `<dir>/<32 hex nonce>` with `O_CREAT|O_EXCL`, then
  closing and removing it. The event carries the path, so it carries the nonce. Other
  processes can't produce our events (matchBinaries), and can't guess a nonce.
- The directory is inside the unit's `ReadWritePaths=/var/lib/tetragon-relay`, so the
  unit doesn't change. The hook needs no privilege beyond loading a policy, which relayd
  already does.
- The executable path is `/proc/self/exe` resolved through symlinks
  (`apply.NewSelfSentinel`), which is what Tetragon reports as `process.binary`.
- Verified on the real v1.8.0 by `TestIntegration_SentinelArrives`:
  - the policy loads `TP_STATE_ENABLED`;
  - an open by the test binary arrives with action `POST` and the nonce;
  - an open of a sentinel-shaped path by `/usr/bin/cat` does not arrive.
- An LSM hook (`file_open`) was not chosen: it needs BPF LSM enabled in the kernel's
  `lsm=` list, which the CI runners and many RHEL 9 hosts don't have. A kprobe needs
  nothing extra.

### Relay-managed, but outside LKG

- **Name.** The 8 hex digits are the first 8 of sha256 over the policy without its name.
  A policy built for another binary or directory therefore has another name.
- **Not LKG-managed.** The name never matches the LKG loaded-name pattern
  (`<name>-v<N>-<8 hex>`). So:
  - `isRelayManaged` ignores it;
  - it is never in the LKG set, the persisted `tp.d` directory, `loaded_digest`, Apply's
    removals, or the drift comparison.
- **Loaded in `relay-managed`.** It is loaded at startup and re-asserted:
  - by `Reconcile` (a failure is audited, not fatal);
  - before every Apply, where a failure is `APPLY_FAILED` before anything changes.
- **Stale copies.** `EnsureSentinel` removes any other `relay-sentinel-*` in the
  relay-managed domain, and touches no other policy.
- **Not persisted.** It isn't written to `tp.d`, so after a Tetragon restart it's absent
  until relayd's reconcile (run at once on restart) or the next Apply loads it again.
  Nothing needs it outside a health window.
- **Visible.** It appears in `StateReport.policies`, which lists everything loaded.
- **Telemetry.** Its events also reach the telemetry stream: one `ProcessKprobe` from
  relayd every 2 s, and only during a health window.

### The window (`internal/apply/health.go`)

- **Subscription.** The window's GetEvents stream subscribes to the bundle's policies
  plus the sentinel's.
- **Firing.** A sentinel fires at the start and every `limits.SentinelInterval` (2 s).
  Each must arrive within `limits.SentinelMaxLatency` (3 s).
- **Passing.** The window passes only when all of these hold:
  - a sentinel fired at or after `cleanStart + Window` has arrived;
  - every sentinel fired since `cleanStart` arrived in time;
  - `limits.SentinelSettleMargin` (1 s) has passed since that arrival, to allow for
    per-CPU ring-buffer reordering;
  - GetHealth stayed serving;
  - the control plane was reachable at least once.
- **Extending.** A sentinel later than 3 s, or one that can't be fired, restarts the
  clean span at the next firing: the window extends. It can extend up to `MaxWindow`
  from the start (`limits.MaxApplyHealthWindow`, 600 s, never less than the nominal
  window).
- **Unverifiable.** If the window reaches `MaxWindow` first, relayd rolls back:
  - `ApplyResult.ROLLED_BACK_UNVERIFIABLE` (15) and `Alert{HEALTH_UNVERIFIABLE}` (8),
    both carrying the measured sentinel latencies;
  - the agent leaves `APPLYING` through `ROLLBACK` to `STEADY`, as for `ROLLED_BACK`.
- **Failing at any point.** These fail the window at any time, extension included, as
  before:
  - an admin-path enforcement event;
  - a surge;
  - GetHealth not serving;
  - the stream ending.
- **No deadline on the stream.** The window cancels its own stream once it reaches a
  verdict. So a close, an error or a timeout before that is always Tetragon's doing,
  and always a failure. That replaces the deadline-race rules of step-03a R3-4 and
  step-03b R3B-2: there is no deadline left to race, and their tolerance constant is
  gone.
- **No sentinel configured.** With no sentinel the window can't pass. The engine refuses
  to load anything (`APPLY_FAILED`) rather than load something it could never verify.
- **Canceled context.** relayd shutting down mid-window is never a pass.
- **Recorded every time.** Every window writes `health_window_stats`:
  - sentinels fired, arrived, late and failed to fire, plus restarts;
  - maximum, p50, p90 and the last 24 latencies;
  - events received and the receive rate;
  - relayd's own cgroup `usage_usec` and `nr_throttled` deltas (F0.2), from
    `/proc/self/cgroup` and the read-only `/sys/fs/cgroup`.

### Ordering caveat

A sentinel that arrives proves that Tetragon's pipeline has caught up to the moment it
was fired. It does **not** prove that no earlier event was dropped:

- Tetragon drops for a slow client with no signal (T-S6);
- the per-listener queue is the place it drops.

Step-07b-decisions-3.md F0.2 covers relayd's share of that (measure, then shed
telemetry during the window if relayd's throttling is the cause), and F2 covers drop
estimation. The sentinel turns "delayed" into "unverifiable"; it can't turn "dropped"
into "seen".

## Consequences

- **A sustained flood can delay an enforce rollout,** by up to 600 s and then a rollback.
  That is recoverable and visible to the controller. A silent admin lockout committed as
  `APPLIED` is neither. The monitor-first rule (G5) already limits what an enforce bundle
  can surprise us with.
- **Healthy windows run a little longer:** nominal + up to 2 s (the next firing) + the
  closing sentinel's latency + 1 s.
- **The engine has a new hard dependency.** Every `apply.Config` needs a `Sentinel`; unit
  tests use a fake that delivers through the fake stream, and integration tests use the
  real `FileSentinel` for the test binary.
- **New wire values** (additive, `buf breaking` clean): `ApplyResult.ROLLED_BACK_UNVERIFIABLE
  = 15` and `Alert.HEALTH_UNVERIFIABLE = 8` (server-contract 10.3, 10.4).

## Evidence

- Unit:
  - `TestRunHealthWindow_StubStreamDeliversNothing_NeverPasses` (F0.3's mutation test:
    a stream that delivers nothing ends unverifiable at `MaxWindow`);
  - `_NoSentinel_NeverPasses`, `_FireErrors_`, `_AlwaysLate_`, `_IntermittentLoss_`
    (all unverifiable);
  - `_LateThenRecovers_ExtendsAndPasses`;
  - `_WaitsForOutstandingEarlierSentinel`;
  - `_AdminPathEventDuringExtension` (`ROLLED_BACK`, not unverifiable);
  - `_ForeignSentinelEventsIgnored`;
  - `TestApply_StalledPath_RolledBackUnverifiable` (LKG re-asserted, epoch unchanged);
  - `TestApply_NoSentinel_ApplyFailedNothingLoaded`;
  - `TestApplyWorker_RolledBackUnverifiable`.
- Integration (real v1.8.0): `TestIntegration_SentinelArrives`, plus every existing apply
  and agent integration test, now passing only through real sentinels.
- E3 P5: see the step 7b report, session 4.
