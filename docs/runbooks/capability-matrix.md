# Runbook: RHEL 9 kernel capability matrix (architecture doc section 15.2, Q1)

## Purpose

Architecture doc section 15.2's Q1 ("Does the production RHEL 9 kernel enable
`CONFIG_BPF_KPROBE_OVERRIDE`, and is `bpf` in the active LSM list?") must be answered per
kernel build actually running in the fleet, not assumed from a single reference host.
`relay-probe --report` (step 3 prompt Part C5) prints the exact facts `internal/hostprobe`
would otherwise write to `/run/tetragon-relay/host-facts.json`, without requiring the
agent or Tetragon to be installed, so it can be run standalone on each candidate kernel
build.

## Procedure

1. Build or obtain `relay-probe` for the target architecture (it is a single static Go
   binary with no runtime dependencies beyond the Linux kernel interfaces it reads):

   ```
   GOOS=linux GOARCH=amd64 go build -o relay-probe ./cmd/relay-probe
   ```

2. On each RHEL 9 kernel build to validate, as root (every fact this command reads
   requires root: `/proc/config.gz` or `/boot/config-$(uname -r)`,
   `/sys/kernel/debug/error_injection/list`, `/sys/firmware/efi/efivars/...`):

   ```
   sudo ./relay-probe --report --tetragon-binary /usr/local/bin/tetragon
   ```

   If Tetragon is not yet installed on this host, point `--tetragon-binary` at any
   readable file (the hash is recorded but not otherwise consulted by `--report`); note
   in the matrix row that the binary hash is not meaningful for that entry.

3. Record, per `uname -r`:

   | Field | What it tells you |
   | --- | --- |
   | `kernel_release`, `rhel_release` | Which exact build this row is for |
   | `kprobe_override` | Whether `Override` is usable on kprobes at all on this kernel (Q1's first half; also requires `CONFIG_BPF_KPROBE_OVERRIDE` **and** `CONFIG_FUNCTION_ERROR_INJECTION` **and** a readable debugfs error-injection list — see architecture doc 9.3's table and step 2c's G10/review notes on why kconfig bits alone are not sufficient) |
   | `lsm_bpf` | Whether `CONFIG_BPF_LSM` is set and `bpf` is in the active LSM list (Q1's second half) |
   | `error_injection_source` | `"debugfs"` if the list was actually read, `"unknown"` if debugfs was not mounted (in which case `kprobe_override` is always `false` regardless of kconfig, per step 3 prompt Part C1) |
   | `usrmerge_ok` | Whether this build has the usrmerge layout the guardrails' protected-path spellings assume (step 3 prompt Part C2); `false` means enforcement bundles must stay rejected on this host even if every other capability is available |
   | `secure_boot`, `lockdown_mode` | Context for why `kprobe_override`/`lsm_bpf` might be `false` even with the right kconfig (kernel lockdown can disable BPF-based overrides independent of kconfig) |
   | `selinux_mode` | Confirms the RHEL 9 baseline (architecture doc 9.2: SELinux enforcing) actually holds on this build |

4. Append the row to the fleet capability matrix (tracked outside this repository, per
   customer environment); do not enable `Override`-using or LSM-BPF-using policies for a
   kernel build until its row shows both capabilities `true` **and** `usrmerge_ok: true`.

## Example output

```json
{
  "schema_version": 1,
  "generated_at": "2026-11-23T00:00:00Z",
  "boot_id": "4b1f...",
  "kernel_release": "5.14.0-503.14.1.el9_5.x86_64",
  "rhel_release": "Red Hat Enterprise Linux release 9.5 (Plow)",
  "kprobe_override": true,
  "lsm_bpf": true,
  "error_injection_source": "debugfs",
  "error_injection_list": ["security_file_open", "..."],
  "usrmerge_ok": true,
  "secure_boot": true,
  "lockdown_mode": "integrity",
  "selinux_mode": "enforcing",
  "tetragon_binary_path": "/usr/local/bin/tetragon",
  "tetragon_binary_sha256": "..."
}
```

## Notes

- `relay-probe --report` never writes `/run/tetragon-relay/host-facts.json`; it is
  read-only with respect to the host (beyond whatever ephemeral file descriptors it
  opens to read `/proc`, `/sys`, and the Tetragon binary). It is safe to run repeatedly
  and on hosts that do not yet have the relay agent installed.
- `boot_id` in `--report` output reflects the boot this specific invocation ran under; it
  is informational here (the staleness check in `internal/hostprobe.Load` only matters
  for the real, non-`--report` invocation systemd runs via `ExecStartPre=+`).
