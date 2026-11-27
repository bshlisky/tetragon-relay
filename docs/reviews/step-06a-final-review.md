# Architect review: step 6a final (origin/main @ 058462b)

Reviewer: architect · Date: 2026-11-26 · Verdict: **Step 6a accepted.** E3 passes: S1–S6 green
on run 45927274396 (6853583), and again on 45929721297 (058462b). One cleanup (R6A-5) and
two packaging notes for step 8 are recorded.

## Verified

- Report section 9 replaces the old plan completely. It covers the real unit installed byte
  for byte, every drop-in line with its reason, per-scenario journal evidence, the C1
  symbol check, the C4 tag-guarded file list and the D3 /proc and /sys list.
- D1–D4 decisions are implemented and proven:
  - S4: REVOKED is persisted, restored after a restart, and relayd never re-dials.
  - S6: systemd's own watchdog timeout and restart do the work.
  - D3: no boot_id read failures under `ProcSubset=pid`.
  - D4: `systemd-analyze verify` is clean.
- Claude Code (standing in for Devin) stopped and asked at every decision point and corrected
  its own mis-cited commit hash in the progress log. This is the process working.

## R6A-5 [LOW] Remove the unused testtpm transport from the E3 relayd build

Every scenario now uses `/dev/tpmrm0` (swtpm through `tpm_vtpm_proxy`). Build relayd-e3
with `-tags testca` only. Delete `cmd/relayd/tpmdevice_testtpm.go` and its test if no
remaining build needs them, and drop the `testtpm` tag from `cmd/testenroll` if it no longer
needs a TCP transport. Keep internal/tpm's own swtpm test helpers for the TPM job. Update the
C4 tag-guarded file list.

## Notes for step 8 (packaging), not actionable now

1. **Management subnet:** the unit hard-codes `IPAddressAllow=10.20.0.0/24` (the example
   management network from the architecture). Production must set the customer's real
   management subnet per site. Packaging should ship this as a drop-in generated at
   install from configuration, not as a constant in the unit.
2. **Tetragon unit name:** the relay unit's `BindsTo=tetragon.service` requires the
   installed Tetragon package to provide a unit named exactly `tetragon.service`.
   Packaging must check this (RPM `Requires:` plus an install-time check) and document it.

## Progress log

Leave the line for 058462b to the next commit, as proposed.
