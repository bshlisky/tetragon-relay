# ADR 0034: host-facts freshness comes from the file's tmpfs location, not relayd's own boot_id read

## Status

Accepted (docs/reviews/step-06a-e3-decisions.md D3).

## Context

`hostprobe.Load` used to treat the host-facts file as fresh only if its
`boot_id` equalled the value relayd read itself from
`/proc/sys/kernel/random/boot_id`. relayd's unit sets `ProcSubset=pid`,
which leaves only the per-process directories in relayd's `/proc`. E3 run
45858158620 (the first run under the real unit file) logged, on every
start:

    "step":"host_facts_boot_id", ... "err":"open /proc/sys/kernel/random/boot_id: no such file or directory"

So in production relayd could never see its host facts as fresh, and once
step 6b processes bundles it would reject every enforcement bundle
(REJECTED_CAPABILITY). The old harness, which turned the unit into
systemd-run properties, hit the same failure, but nothing checked for it.

The architect ruled out changing the unit or the sandbox (for example a
`BindReadOnlyPaths=` for that one file).

## Decision

1. relayd never reads `/proc/sys/kernel/random/boot_id`.
   `hostprobe.CurrentBootID` stays, used only by `cmd/relay-probe`. It runs
   as root through the unit's `ExecStartPre=+` line on every start, outside
   the sandbox, and records `boot_id` in the host-facts file as before.
2. `hostprobe.Load(path)` (it no longer takes a boot_id argument) accepts
   the file as fresh only if all of the following hold. Each failure has its
   own typed error (`ErrHostFacts*`), and every failure returns fail-closed
   Capabilities:
   - opened with `O_NOFOLLOW`, so a symlink is never followed;
   - fstat on the open descriptor shows a regular file, owned by uid 0,
     with mode exactly 0640 (the mode `WriteAtomic` writes; any setuid,
     setgid or sticky bit fails);
   - fstatfs on the same descriptor shows `TMPFS_MAGIC`;
   - it parses strictly, `schema_version` matches, and `boot_id` is not
     empty.
3. relayd uses the facts' `boot_id` as the current boot_id (Hello,
   telemetry). If the facts are not fresh, relayd has no trustworthy boot_id
   and Hello's `boot_id` is empty. The audit record `host_facts` carries the
   typed reason.

## Why this is equivalent

The boot_id comparison answered one question: was this file written during
the current boot? The new rule answers it this way:

- `/run` is a tmpfs, so it is empty at every boot. Every file on it was
  created during the current boot.
- relayd runs as `tetragon-relay` with no capabilities. It can delete or
  rename files in its own RuntimeDirectory, but it cannot create a
  root-owned file. A root-owned file there can only come from the root
  `ExecStartPre` (relay-probe) or from some other root process, and root is
  already outside this threat model.
- `RuntimeDirectory=` is removed when the unit stops. So the file is not
  only from this boot but from this unit start, which is stricter than
  before.

A file on a persistent filesystem, for example after someone points
`HostFactsPath` at `/var`, fails `ErrHostFactsNotTmpfs`. That covers the one
case the old boot_id comparison caught that `/run`'s semantics alone would
not.

## Consequences

- Freshness can only be established on Linux. `Load` always fails closed
  elsewhere (`ErrHostFactsUnsupported`), which matches the old behavior:
  `CurrentBootID` always errored off Linux.
- `HostFacts`' schema is unchanged. `boot_id` is still written and is now
  the boot_id relayd reports.
- E3 (S1 and S3) fails if relayd's journal contains a `host_facts`,
  `host_facts_boot_id` or `agent_build_digest` record under the real unit.
