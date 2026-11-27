# Architect review: step 7a (origin/main @ eaa6c0b; final code green on ba4ae68, run 46008210639)

Reviewer: architect · Date: 2026-11-27 · Verdict: **Step 7a accepted.** Part A (the 6b
close-out) and the telemetry pipeline are done, with S1–S13 and T-S1 to T-S5 green. The
telemetry scenarios passed on their first E3 run. Performance misses architecture 8.13
by a wide margin. That isn't a defect in 7a, whose prompt made performance non-gating, but
it is now the top item for 7b (R7A-1).

## What was verified

- ADRs 0037 (explicit ApplyResult codes, `STATUS_UNSPECIFIED = 0`), 0038 (tampered mode)
  and 0039 (wire format and chain) all exist.
- `PROTO_BASELINE` was advanced in the following commit. Deviation 1 is accepted: a
  commit can't name its own SHA.
- The batch hash is `SHA-256(BE32(len(header)) || header || payload)`, as specified.
  Headers are re-checked against `payload_sha256` on read.
- Ack validation (`ackState.check`) is per stream and per chain, rejects an unknown chain,
  a seq above the highest sent and an ack that goes backwards, and accepts an ack equal to
  the last one. T-S5 shows the hostile ack being rejected, a reconnect within about 1 s,
  the batch resent, and nothing deleted early.
- The depguard rule is stricter than asked and was probed in both directions
  (deviation 9). Accepted.
- Tampered mode:
  - S13 shows TAMPER first, heartbeats with an empty epochs map, `REJECTED_TAMPERED`,
    `TRUST_UPDATE_REJECTED`, the loaded set unchanged, and `NRestarts=0`.
  - Refusing `RotateIdentity` in tampered mode (deviation 4) is right.
  - So is never creating a key (`LoadHostSigner`).

## Deviations

All fourteen are accepted. Three of them become 7b work:

- **12:** how Tetragon behaves toward a slow `GetEvents` client is unverified (R7A-3).
- **14:** the flag that populates `environment_variables` is unverified (R7A-4).
- **8:** the environment can only be kept through signed metadata (R7A-5).

## Findings

### R7A-1 [HIGH for production, not a 7a defect] CPU is about 8× over target; spool capacity is about 9× under

- **CPU:** the benchmark measures 16.8 µs of CPU per event, about 8.4 % of a core at
  5k events/s, against a target of < 1 % (2 µs per event).
- **Spool:** 2 GiB holds about 55 minutes at 5k events/s uncompressed, against a target
  of about 8 hours.

The measurement is honest, but it was taken on an M2 and includes the benchmark harness and
GC. The < 1 % target is probably unrealistic anyway: decoding and re-marshaling a 1 KiB
protobuf costs about that much on its own. So 7b does two things:

1. **Measure on Linux,** on the CI runner, with pprof. Profile the pipeline only, without
   the harness, and split the cost into ingest decode, classify and redact, marshal, and
   spool (fsync plus HMAC).
2. **Optimize the obvious costs:**
   - field-specific redaction instead of a reflection walk;
   - reused buffers and `sync.Pool` for marshal output;
   - one HMAC and fsync per batch (confirm that this is already the case);
   - no per-event allocations in classify.

   Then replace the target with a measured number in an ADR that amends 8.13. The
   **gate for 7b** is ≤ 3 % of one core at 5k events/s (≤ 6 µs of pipeline CPU per
   event) on the CI runner, enforced as a CI check with headroom. If 3 % turns out to be
   unreachable, stop and bring me the profile; don't lower the gate on your own.

3. **Compression (closes the spool gap):**
   - zstd at a fast level, using `github.com/klauspost/compress/zstd` (pure Go, vendored,
     dependency ADR required).
   - The header gains `enc: "zstd"`, and `payload_sha256` and the batch hash cover the
     **compressed bytes as sent**, so the collector verifies before it decompresses.
   - The contract must state a maximum decompressed size per batch, and the decoder must
     enforce it (`WithDecoderMaxMemory`), against decompression bombs in both directions.
   - Report the measured compression ratio and the resulting hours per 2 GiB. A stale
     2 GiB figure in 8.13 is fine if the ADR states the measured figure.

### R7A-2 [LOW] Answer to Q2: no telemetry before enrollment is correct

A host with no identity has nothing to bind a chain to and no collector it may talk to.
Spooling before enrollment would mean shipping events whose origin can't be proven.
Keep it. Add one sentence to the contract: the controller should treat a host that is
enrolled but sends no telemetry as a signal, the same way it treats silence on the
control stream.

### R7A-3 [MEDIUM] How Tetragon treats a slow `GetEvents` client is unverified

This determines whether a slow relay loses events silently, makes Tetragon's memory grow,
or slows Tetragon down. It must be observed on the real v1.8.0, not guessed. Add an E3 (or
integration-job) experiment:

- Throttle the builder, using a test-only hook behind the e3 tag, to about 100 events/s.
- Generate about 2k exec/s for 60 s.
- Record Tetragon's RSS, its own drop counters (`RateLimitInfo` and its metrics endpoint,
  if enabled in the test), and how many generated execs reached the collector.

Write the observed behavior into ADR 0039, and make sure the loss is visible either way.
If Tetragon drops silently for a slow client, relayd must at least count the gap and send
it as an `Alert` and a `dropped` record, for example from a sequence or timestamp
discontinuity if the API offers one.

### R7A-4 [LOW] The environment flag is unverified

The integration and e3 jobs already install the real Tetragon v1.8.0 binary. Find the flag
from that binary (`tetragon --help`), in CI, and cite the output in the report. Then make
T-S1 actually populate the environment and prove it is dropped: run the canary with
`SECRET_TOKEN=...` in its environment, and check that the token never reaches the
collector.

### R7A-5 [MEDIUM] Redaction rules and event types belong in signed metadata (architecture 10.5)

Today they come from relay.yaml, which only lets an operator *add* redaction. A
compromised controller can't touch them, but a local root can, and the policy for the
whole fleet should be set centrally anyway. Design, to record in an ADR:

- **A new signed document type**, `telemetry-policy`, signed by the **targets** role, the
  same keys as bundles. It goes in its own DSSE payload type and is delivered over the
  control stream as a new `TelemetryPolicy{envelope}` message.
- **Its own epoch, with replay protection:** a new scope, `telemetry`, in the existing
  epoch store.
- **Contents:**
  - the event-type allow-list;
  - extra argv patterns;
  - a `keep_env` allow-list of variable *names* (never values, default empty);
  - the `.ssh` hashing rule, which stays mandatory.
- **Verification** reuses the 7.4 algorithm's steps 1–9 and 11–12, and needs a new
  guardrail set:
  - patterns must compile as RE2 and stay under size limits;
  - the built-in redaction set can't be removed (only added to);
  - the allow-list can't drop `process_kprobe` or `process_lsm`, because security events
    can't be turned off by policy.
- **Applied atomically between batches.** The batch header gains a
  `telemetry_policy_epoch` field so the collector can see which rules applied.
- **relay.yaml keeps only local additions** (patterns), as today.

### R7A-6 [LOW, backend] Q3 needs numbers from the backend team

Collector-side pruning and the gap grace period are the backend team's numbers to choose.
I'd propose: grace of 2× `batch_max_age` plus the reconnect backoff maximum, so
2 × 2 s + 30 s ≈ 35 s, and prune chain state 24 h after a chain's last batch or after a
newer `boot_id` has been seen for that host. Put these in the contract as *proposed
defaults* for the backend team to confirm.

## Not in 7b (tracked)

- **TPM-signed checkpoints** (10.3, optional). Defer until the customer asks for
  non-repudiation.
- **Step 8, packaging:**
  - RPM and SELinux module;
  - journald FSS;
  - the management-subnet drop-in generated at install;
  - the `tetragon.service` name check;
  - IMA appraisal guidance.
- **Customer items, unchanged:** RHEL 9 e2e run, SPIRE or IdM, TPM owner auth,
  Hypershield API.
