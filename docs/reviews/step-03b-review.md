# Architect review: step 3 final (origin/main @ 2a1e602)

Reviewer: architect · Date: 2026-11-24 · Verdict: **Step 3 accepted.** Four follow-ups
(R3B-1 to R3B-4) are carried into step 4 as Part A. None blocks step 4. The RHEL 9 run
(R3B-5) blocks shipping, not development.

## Verified by the architect

- **No step 2 regressions.** All G1 lockout probes from reviews 02b–02d (empty, relative
  and look-alike `NotIn`/`NotPrefix` values; trailing-slash, `//` and `/./` spellings)
  are rejected. The exact canonical `NotIn` list is accepted (control). G3 (unscoped
  `sys_execve` denial) and G10 (uprobe `Override`) still reject.
- **R2D-1 closed.** `Prefix "/\0anything"`, `"/\tx"`, `In "/opt/app\u0000/usr/sbin/sshd"`
  and `Prefix "/‮"` are all rejected at `policydoc.Parse`.
- **R3-4 closed.** `TestApply_HappyPath_Enforce` ran 60 times with 0 spurious rollbacks
  (was 3 of 40 before the fix).
- **R3-1 and R3-3 closed.** The unit file has empty `CapabilityBoundingSet=` and
  `AmbientCapabilities=`, keeps `ProtectProc=invisible`, and `ReadWritePaths` is exactly
  the three section 8.6 paths.
- **R3-2 closed.** Staging lives in `relay/.staging/`, below Tetragon's `tpMaxDepth := 1`,
  and the update order (rename new files, then remove stale ones) never leaves fewer
  policies on disk than before.
- **R3-E3 closed.** The caller-vs-new-image semantics of `security_bprm_check` is a good
  find (ADR 0020). The E1 and E2 measurements and the E3 citation (`AddTracingPolicy` is
  synchronous through the sensor-manager goroutine) are the right evidence.

## R3B-1 [MEDIUM] `SELinuxRequired` fails open at its zero value

`internal/tetra/config.go`: `SELinuxRequired bool`, documented as "When true (the
default) … the zero value is the safer (fail-closed) choice". A Go bool's zero value is
`false`, which is the fail-open setting. Any future caller (relayd's config loading in
step 6, or a test) that forgets the field silently skips the SELinux peer check. The
comment says the opposite of what the code does.

Required:
- Invert the field so the zero value is secure: `AllowSELinuxDisabled bool` (zero value
  = SELinux required). Update every caller, the config key name and the docs.
- In `verifyPeerSELinux`, if host facts (internal/hostprobe) report SELinux enforcing
  or permissive, an `SO_PEERSEC` label that is not an SELinux context is a verification
  failure, regardless of `AllowSELinuxDisabled`. The AppArmor fallback (ADR 0018
  addendum) applies only when host facts say SELinux is disabled or absent.
- Tests: zero-value `Config` refuses on a host without SELinux; an enforcing host with a
  bare (AppArmor-style) label refuses.

## R3B-2 [MEDIUM] Any stream timeout ends the health window early as healthy

`internal/apply/health.go` (errc branch): `errors.Is(err, tetra.ErrTimeout)` is treated
as "the window completed" even when `windowCtx` has not expired. The comment's reasoning
(GetEvents uses `windowCtx` directly, so a `DeadlineExceeded` can only be the window's
own deadline) assumes the server returns that status only for the propagated deadline. A
Tetragon (or anything at the other end of the socket) that returns `DeadlineExceeded`
early makes a 60 s window end after, say, 2 s and report healthy. That shortens the
safety window without anyone noticing.

Required:
- Accept a timeout as the window's end only if `time.Until(windowDeadline)` is at most a
  small tolerance (e.g. 2 s, constant in internal/limits). Otherwise return
  `reasonHealthNotServing`. Apply the same rule to the events-closed branch's
  `pendingErrIsTimeout` path.
- Deterministic tests: a timeout at the deadline passes; a timeout 10 s before the
  deadline fails.

## R3B-3 [MEDIUM, QUESTION] Is there a hook-inactive gap after AddTracingPolicy returns?

E1 reports the first matching event **778 ms** after `AddTracingPolicy` returned, with
triggers every 100 ms. That is either event-delivery latency (harmless) or a period of
about 0.7 s in which the new BPF program is not yet acting. If it is the latter, the
apply engine has a real enforcement gap during version upgrades: it confirms through
`ListTracingPolicies` and then removes the old version almost immediately.

Required (measurement first, no design change yet):
- Re-run E1 with every trigger's wall-clock time recorded. Report, for each trigger
  after `AddTracingPolicy` returned, whether a matching event exists, using the event's
  own kernel timestamp (`time` field), not its delivery time.
- If every trigger has an event: record "delivery latency only" in step-03.md and close
  this item.
- If early triggers have no event: stop and report the numbers. The likely fix is that
  removal of the old version must wait for positive proof that the new version is
  acting, with an upper time limit. That is an architect decision (ADR), not a quick fix.

## R3B-4 [LOW] ADR 0019 overstates its argument

ADR 0019 says the engine "never races" Tetragon's startup read against an in-progress
`PersistDir`. Tetragon can restart (crash, OOM, `systemctl restart`) at any moment,
including mid-update. The conclusion still holds, for different reasons: `.staging` sits
below `tpMaxDepth`; the rename-then-remove order means a mid-update read sees a superset
of the old set; and reconcile converges afterwards. Correct the ADR text to give those
reasons, and add a test that simulates a Tetragon restart (directory read) at each step
of `PersistDir` and asserts the loaded set is always a superset of the old or new set.

## R3B-5 [SHIP-BLOCKING, CUSTOMER ACTION] RHEL 9 validation not yet run

Every real run so far is on ubuntu-24.04. The following have never executed on RHEL 9:
- the SELinux branch of the `SO_PEERSEC` check
- usrmerge detection
- the kernel capability matrix (V13)
- the systemd sandbox under SELinux

`scripts/e2e-rhel9.sh` must run on at least one host per RHEL 9 kernel build in the
customer's fleet before any production deployment. Not required before step 4.

## Process notes

- Good: Devin stopped and asked at both design-changing points (the `ProtectProc` and
  attach-latency questions), used throwaway PRs for diagnostics, and reported measured
  evidence rather than expectations.
- Keep: CI must run under production's restrictions (R3-3). It caught R3-1/R3-2-class
  problems once already.
