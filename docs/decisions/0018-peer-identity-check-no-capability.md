# ADR 0018: Tetragon socket peer identity check without CAP_SYS_PTRACE

## Status

Proposed.

## Context

Commit 6be5137 added a post-connect check in `internal/tetra` (`verifyPeerCredAndExe`)
that resolved the connected peer pid's `/proc/<pid>/exe` and compared it against the
configured Tetragon binary path, to confirm the socket peer is actually Tetragon and not
some other root-owned process that happened to connect to the same unix socket path.
Since Tetragon runs as root and relayd does not (`packaging/systemd/tetragon-relay.service`
`User=tetragon-relay`), reading another uid's `/proc/<pid>/exe` requires `CAP_SYS_PTRACE`
(Yama/commoncap ptrace permission check, not the symlink's own file mode).

The architect's review of 709f3da (`docs/reviews/step-03a-review.md`, R3-1) rejected this:
`CAP_SYS_PTRACE` lets relayd inspect and read the memory of any process on the host, so a
compromised agent becomes root-equivalent, violating architecture doc P9 and section 8.7
("no capabilities"). It also violates `ProtectProc=invisible` on the production unit:
`systemd.exec(5)`'s `ProtectProc=` documentation states "the root user is unaffected by
this option, so to be effective it has to be used together with `User=`... and also
without the `CAP_SYS_PTRACE` capability, which also allows a process to bypass this
feature" (confirmed by systemd PR #19001's commit message and reproduction). Granting
`CAP_SYS_PTRACE` therefore also silently disabled `ProtectProc=invisible`'s intended
protection for the whole unit, not just this one check.

R3-1 directed replacing the exe check with two checks that need no capability:
`SO_PEERSEC` (the peer socket's own SELinux security context, via `getsockopt`) and the
peer pid's cgroup membership, originally specified as reading `/proc/<peer pid>/cgroup`
("world-readable").

### Why `/proc/<peer pid>/cgroup` does not work here either

Once `CAP_SYS_PTRACE` is removed, `ProtectProc=invisible` becomes active again for this
unit (`User=tetragon-relay`, no `CAP_SYS_PTRACE`): it hides every `/proc/<pid>` directory
owned by another uid, including Tetragon's, regardless of that directory's own nominal
file-mode permissions (this is a `hidepid=2` / `fs/proc/base.c` `has_pid_permissions()`
kernel-level restriction, not a DAC check the target file's mode can satisfy). Reading
`/proc/<tetragon-pid>/cgroup` from relayd would therefore return `ENOENT` on the real
production unit, as confirmed by `systemd.exec(5)`'s own documentation above.

## Decision

Implement the cgroup check against `/sys/fs/cgroup/<Config.UnitCgroupPath>/cgroup.procs`
(cgroup v2, cgroupfs) instead of `/proc/<peer pid>/cgroup` (procfs):

- `cgroup.procs` (Documentation/admin-guide/cgroup-v2.rst, "Organizing Processes and
  Threads": "Each cgroup has a read-writable interface file `cgroup.procs`. When read, it
  lists the PIDs of all processes which belong to the cgroup one-per-line.") gives the
  same membership fact `/proc/<pid>/cgroup` would have, read from the opposite direction
  (the cgroup's member list, not the process's own cgroup pointer).
- It is under `/sys/fs/cgroup`, not `/proc`, so `ProtectProc=invisible` does not apply to
  it at all.
- `ProtectControlGroups=yes` (already set on the production unit) only remounts
  `/sys/fs/cgroup` read-only (`systemd/src/core/namespace.c`,
  `protect_control_groups_yes_table`: `{ "/sys/fs/cgroup", MOUNT_READ_ONLY, false }`); it
  does not hide or namespace it the way `ProtectProc=invisible` does to `/proc`, so the
  global path and its normal DAC-readable files stay reachable.

Detect cgroup v2 via `statfs("/sys/fs/cgroup")` and check `f_type == CGROUP2_SUPER_MAGIC`
(`internal/tetra/peercgroup_linux.go`). On cgroup v1 or a hybrid layout (not expected on
RHEL 9, architecture doc 9.2), the cgroup check is treated as unavailable rather than
failed, and the connection is accepted only if the SO_PEERSEC check actively ran and
passed; if neither check is available, verification fails closed.

`cgroup.procs` is read with `os.Lstat` first (refuse a symlink) and bounded to 1 MiB
(`maxCgroupProcsBytes`), parsed strictly as one decimal pid per line; any parse or read
error is a hard verification failure, not a fallback to "unavailable".

## Consequences

- `packaging/systemd/tetragon-relay.service` grants no capabilities
  (`CapabilityBoundingSet=`/`AmbientCapabilities=` empty), matching architecture doc
  section 8.7 exactly, and `ProtectProc=invisible` is fully effective again.
- `.github/workflows/ci.yml`'s integration job and `scripts/e2e-rhel9.sh` run Tetragon as
  a transient systemd unit (`systemd-run --unit=tetragon`) so the cgroup check has a real
  `system.slice/tetragon.service` cgroup to verify against, rather than a bare
  backgrounded process with no unit cgroup at all.
- SO_PEERSEC is only exercised against a real, enabled SELinux policy by
  `scripts/e2e-rhel9.sh` on an actual RHEL 9 host; GitHub-hosted `ubuntu-24.04` runners
  have SELinux disabled, so the CI integration job only exercises the
  `selinux_required=false`/disabled-SELinux branch of that check.
- `internal/tetra.Config.TetragonBinaryPath` is no longer read by the peer verification
  path at all; it remains on `Config` only because other callers (`cmd/relay-probe`,
  `internal/hostprobe`) still need the configured binary path for host-fact collection.

## Addendum: SO_PEERSEC is not SELinux-specific (found via real CI, run 45277523718)

The integration job's first real run surfaced that `SO_PEERSEC` is not an SELinux-only
mechanism: AppArmor implements it too (Ubuntu launchpad bug 1235478, "In 13.10, AppArmor
added the ability to get the AppArmor label of the peer on the other end of a UNIX domain
socket"), returning its own bare label (no colons, e.g. `"unconfined"`) instead of
SELinux's `user:role:type:level` format. GitHub-hosted `ubuntu-24.04` runners default to
AppArmor, so `getsockopt(SO_PEERSEC)` there succeeds (not `ENOPROTOOPT` as assumed) and
returns `"unconfined"`, which `verifyPeerSELinux` initially tried to parse as an SELinux
context and rejected as a type mismatch, failing every integration test.

`verifyPeerSELinux` (`internal/tetra/dial_linux.go`) now treats a successfully-returned
label that does not parse as an SELinux context (fewer than 3 `:`-separated fields) the
same as SELinux being unavailable (the `cfg.SELinuxRequired` disabled-SELinux fallback),
rather than as a type mismatch. This does not weaken the check on a real SELinux-enforcing
RHEL 9 host (architecture doc 9.2): a genuine SELinux context always has the
`user:role:type:level` shape, so this path is never reached there.
