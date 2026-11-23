# Architect review: step 3 in progress (origin/main @ 709f3da)

Reviewer: architect · Date: 2026-11-23 · Verdict: **Not accepted.** Two HIGH regressions were
introduced while fixing integration failures (R3-1, R3-2), CI does not yet mirror production
(R3-3), and the health window has a production race that causes spurious rollbacks (R3-4).

Run 45239016562 (709f3da) result: **ci failed**
(`TestApply_HealthWindowFails_RollsBackToPriorLKG`, see R3-4); integration was skipped
because it depends on ci.

## Accepted fixes from the integration iteration

These were legitimate Linux and real-Tetragon findings, each fixed in its own commit:
gofmt/goimports scope for vendored bindings; Linux coverage tests; tarball layout;
`--bpf-lib` path; test binaries run from their package directory; canary policy
`syscall: false`; admin-path test actively execs bash during the health window.

## R3-1 [HIGH] Revert the CAP_SYS_PTRACE grant (commit 6be5137)

Reading `/proc/<pid>/exe` of Tetragon's root process needs ptrace access, so 6be5137
granted relayd `CAP_SYS_PTRACE`. That capability lets relayd inspect and read the memory
of any process on the host (sshd, systemd, Tetragon). A compromised agent would then be
root-equivalent. This violates architecture P9 and section 8.6 (no capabilities).
6be5137 also edited docs/architecture.md without architect sign-off.

Required:
- Replace the `/proc/<pid>/exe` peer check with checks that need no capability:
  - **SO_PEERSEC** on the connected socket. When SELinux is enabled (always in
    production), the peer context type must equal the configured Tetragon domain
    (default `tetragon_t`). When SELinux is disabled, follow config `selinux_required`
    (default `true` = refuse).
  - **`/proc/<peer pid>/cgroup`** (world-readable): the unified-hierarchy path must equal
    the configured unit cgroup (default `/system.slice/tetragon.service`).
  - Keep `SO_PEERCRED` uid == 0 and the existing lstat socket checks.
- Unit file: `CapabilityBoundingSet=` and `AmbientCapabilities=` back to empty.
- Remove `setcap` from ci.yml and e2e-rhel9.sh.
- Revert the docs/architecture.md edit.
- Integration job: run Tetragon as a transient unit (`systemd-run --unit=tetragon ...`)
  so the cgroup check runs for real. SO_PEERSEC is exercised only by e2e-rhel9.sh; say so
  in the report.
- Unit-test both new checks with injected readers, including the wrong label, wrong
  cgroup, cgroup v1 layout and unreadable-file cases.

## R3-2 [HIGH] PersistDir must work within ReadWritePaths=/etc/tetragon/tetragon.tp.d/relay

709f3da made the atomic swap work by granting the relay group write on
`/etc/tetragon/tetragon.tp.d` itself, in CI and e2e only. The production unit
(`ProtectSystem=strict`, `ReadWritePaths=.../relay`) keeps the parent read-only, so
PersistDir passes CI but would fail on real hosts. Widening production instead would let
the agent create or delete policy files it does not own.

Required:
- Revert the parent-directory chown/chmod in ci.yml and e2e-rhel9.sh.
- Redesign: inside `relay/`, write each file to a temporary name that Tetragon v1.8.0's
  policy-directory loader ignores (cite its filename/extension rules, file:line), fsync,
  rename into place, then remove stale relay-managed files and fsync the directory.
- ADR (Proposed): the set update is not atomic, and that is acceptable because Tetragon
  reads the directory only at startup and reconcile re-asserts LKG after any Tetragon
  restart.
- Test: crash at every point in the update sequence. After the crash, a Tetragon restart
  plus reconcile converges to LKG.

## R3-3 CI must mirror production

Add a test that parses packaging/systemd/tetragon-relay.service and fails unless
`ReadWritePaths` is exactly the three section 8.6 paths (relay/ for policies, the state
and spool directories), and `CapabilityBoundingSet` and `AmbientCapabilities` are empty.
CI and e2e setup may not grant the relay user anything the unit does not.

## R3-4 [HIGH] Health window spuriously fails at its own deadline (production bug)

Observed: ci run 45239016562 (709f3da), TestApply_HealthWindowFails_RollsBackToPriorLKG
setup apply rolled back at 4.01 s. Reproduced by the architect: TestApply_HappyPath_Enforce
rolled back 3 of 40 runs, each at exactly the window boundary.

Root cause: runHealthWindow (internal/apply/health.go) opens GetEvents with windowCtx.
When windowCtx expires, the stream returns a DeadlineExceeded error on errc at the same
moment windowCtx.Done() fires. select picks randomly, and the errc branch returns
reasonHealthNotServing, so a healthy apply is rolled back. In production this causes
random rollbacks on a fraction of every rollout's hosts, halting waves.

Required:
- In the errc branch, if windowCtx.Err() != nil (the window has ended), handle it exactly
  like the windowCtx.Done() branch. Only a stream error while the window is still open
  fails health. Also handle a stream that closes cleanly before the deadline: Tetragon
  ending the event stream early must fail health, not be ignored.
- In internal/tetra.GetEvents, do not report context cancellation or deadline expiry as
  a typed error: close errc without sending when ctx.Err() != nil, and document this.
- Deterministic tests, with no sleeps or timing luck: a fake stream that errors exactly
  at the deadline (must pass), errors before it (must fail) and closes early (must fail).
  Also run TestApply_HappyPath_Enforce with -count=200 -race in CI's apply package step
  for this review cycle and paste the result.
- Audit every other select in internal/ that mixes a context's Done with a channel fed by
  work under the same context, and report each one with its verdict.

## R3-1 amendment (2026-11-23)

Devin found, and the architect confirmed, that the original R3-1 design above does not
work on the production unit: once `CAP_SYS_PTRACE` is removed, `ProtectProc=invisible`
(already set on `packaging/systemd/tetragon-relay.service`) hides Tetragon's root-owned
`/proc/<pid>` from relayd entirely (`systemd.exec(5)`, `ProtectProc=`: "the root user is
unaffected by this option, so to be effective it has to be used together with `User=`...
and also without the `CAP_SYS_PTRACE` capability"), so `/proc/<peer pid>/cgroup` would
always return `ENOENT` in production regardless of that file's own permissions.

R3-1 is amended as follows; everything else in R3-1 through R3-4 is unchanged:

- Replace the `/proc/<peer pid>/cgroup` check with: read
  `/sys/fs/cgroup/<configured unit path>/cgroup.procs` (default
  `system.slice/tetragon.service`) and require that the SO_PEERCRED pid appears in it.
  Reason: `ProtectProc=invisible` hides root-owned `/proc/<pid>` from relayd once
  `CAP_SYS_PTRACE` is removed; `cgroup.procs` is outside `/proc` and readable without
  capabilities.
- cgroup v2 only. Detect v2 via the filesystem type of `/sys/fs/cgroup` (cgroup2fs). On
  cgroup v1 or a hybrid layout, the check fails closed (typed error) unless the
  SO_PEERSEC check is active and passed; record which checks ran in the dial audit
  record.
- Read with lstat-then-open semantics: no symlink following, bounded read size (1 MiB),
  strict parsing (one decimal pid per line); any parse error fails closed.
- Cited sources: `cgroup.procs`'s read semantics and default readability —
  Documentation/admin-guide/cgroup-v2.rst, "Organizing Processes and Threads"; that
  `ProtectControlGroups=yes` leaves `/sys/fs/cgroup` globally readable (only mounted
  read-only, not hidden/namespaced) — `systemd.exec(5)` and
  `systemd/src/core/namespace.c`'s `protect_control_groups_yes_table`; the
  `ProtectProc=invisible`/`CAP_SYS_PTRACE` interaction — `systemd.exec(5)`'s own
  `ProtectProc=` documentation and systemd PR #19001.
- Integration job: Tetragon runs as a transient unit (`systemd-run --unit=tetragon`) and
  is verified against a real `system.slice/tetragon.service` cgroup; SO_PEERSEC is only
  exercised against a real, enabled SELinux policy by `scripts/e2e-rhel9.sh` on an actual
  RHEL 9 host (GitHub-hosted `ubuntu-24.04` runners have SELinux disabled).
- Unit tests with injected readers: pid present, pid absent, empty file, malformed line,
  cgroup v1/hybrid (unavailable, not failed), unreadable file, symlink in place of the
  file, statfs failure.
- Recorded in `docs/decisions/0018-peer-identity-check-no-capability.md` (Proposed).

## Definition of done for step 3

- R3-1 to R3-4 fixed, each with regression tests, one commit per item.
- Both the ci and integration workflows green on GitHub for the final commit.
- docs/reports/step-03.md §13 updated with: both run numbers, the runner kernel version,
  relay-probe --report output, the pass/fail of every E3 scenario, the R3-4 -count=200
  result, the select-audit table, and the remaining unverified list (RHEL 9 kernel
  specifics, SO_PEERSEC/SELinux labels).
