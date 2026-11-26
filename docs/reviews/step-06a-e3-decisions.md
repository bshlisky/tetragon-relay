Architect decisions (commit this message verbatim as docs/reviews/step-06a-e3-decisions.md
first). Excellent stop; all four are real findings.

D1. REVOKED liveness: do NOT unregister the session runner. When RunSession reaches
    REVOKED it parks: stays running in an idle loop (select on ctx.Done and the liveness
    touch ticker; no network activity) until shutdown or operator re-enrollment. A hung
    park loop is still caught by the watchdog. Unit test: REVOKED keeps the registry
    healthy; a blocked park loop goes stale.

D2. Persist REVOKED: yes. Add a revoked marker (with time and reason) to the store's
    versioned schema; bump the schema version in place (the store has never been
    deployed, so no migration; say so in an ADR). At startup, a persisted REVOKED puts
    the agent straight into REVOKED (parked, no dialing, LKG enforced). Only the
    Reenroller path (ADR 0023) clears it. Tests: revoke, restart, still REVOKED and never
    dials.

D3. boot_id: no unit or sandbox change. relayd stops reading /proc/sys/kernel/random/
    boot_id. relay-probe (root ExecStartPre, every start) already records boot_id in the
    host-facts file; relayd takes boot_id from there, for freshness, Hello and telemetry.
    Freshness rule replacing the boot_id comparison: the host-facts file must be on a
    filesystem whose statfs type is tmpfs (TMPFS_MAGIC), root-owned, mode as today; /run
    is cleared each boot, so a file there was written this boot. Write an ADR. Also: grep
    every /proc and /sys path relayd reads and confirm each works under ProcSubset=pid
    and ProtectSystem=strict (E3 journal is the evidence); report the list.

D4. Unit-file comments: approved. Move the inline comments on lines 74 and 105 to their
    own lines; no directive changes. Add a CI step running `systemd-analyze verify` on
    packaging/systemd/tetragon-relay.service that fails on any warning or error, and
    update the R3-3 unit-file test if it depends on the old text.

Then re-run E3 until S1–S6 pass, progress log after each push.
