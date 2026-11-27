# tetragon-relay — new session: Step 7a (6b close-out, then the telemetry pipeline)

You are continuing an existing, security-critical project; the repository is the source of
truth. Repo: https://github.com/bshlisky/tetragon-relay (main).

## Binding context
- The working agreement in docs/prompts/step-04b.md (Part 0) applies, including the
  session-size rule, "never widen production privileges to make a test pass", the rule
  against guessing about external behavior (stop and ask), and the progress-log rule.
- Read these before you start:
  - docs/architecture.md sections 8.10, 10 (all of it) and 6.4
  - docs/server-contract.md
  - docs/reports/step-06b.md (sections 6, 9 and 11)
  - ADRs 0031–0036
  - the attached review, step-06b-review.md
- State: step 6b is accepted at 24dfd7e, with S1–S12 green. relayd verifies and applies
  bundles, walks trust updates, reconciles, and sends alerts over the control stream.
  Nothing has been built for telemetry yet. The config already parses a `collector:`
  section (internal/config), and the heartbeat already has `telemetry_last_seq` and
  `telemetry_backlog`.

## First actions
1. Two files are ATTACHED: this prompt and step-06b-review.md. Commit them verbatim in one
   commit, with the deferred progress-log line for 24dfd7e:
   - docs/reviews/step-06b-review.md
   - docs/prompts/step-07a.md
2. Run `make ci` (on macOS, `GOOS=linux golangci-lint run ./...`) and confirm it is green.
3. Acknowledge with ≤ 12 bullets: your plan, and anything in Part T's design that you
   think is wrong. Raise it now, not halfway through.

## Part A — Step 6b close-out (do this first; it changes the wire contract)
A1. R6B-1 and R6B-2, in one ADR and one commit:
    - `STATUS_UNSPECIFIED = 0`, with `APPLIED` on a new number.
    - The new status codes: `SUPERSEDED`, `REJECTED_TAMPERED`, `REJECTED_AGENT_STATE`,
      `ROLLBACK_FAILED`.
    - The new alert kinds: `TRUST_UPDATE_REJECTED`, `ROLLBACK_FAILED`.
    - Advance `PROTO_BASELINE`, map every agent path to the new codes, and update the
      contract: unknown or unspecified status means not applied.
    - Add a unit test proving that no code path sends `STATUS_UNSPECIFIED`.
A2. R6B-3: separate outbox bounds; ApplyResults are never evicted by alerts.
A3. R6B-4: the cross-scope supersede rule in server-contract section 10.2.
A4. R6B-5: tampered mode, with its ADR (amending ADR 0035 and architecture 8.3) and E3
    scenario S13. Follow the review exactly. In particular: no Tetragon writes, no store
    writes except a best-effort REVOKED marker, and an empty epochs map.
A5. E3 still green with S1–S13. Then start Part T.

## Part T — Telemetry, agent side (architecture 8.10 and 10)

### Design decisions already made (record them in one ADR, "telemetry wire format and chain")

- **Transport: our own gRPC service, not OTLP.**
  - Define `relay.telemetry.v1.Collector` with a single client-streaming RPC, `Export`:
    the agent sends `Batch` messages, and the server streams back `Ack{seq}`. Use a
    bidirectional stream so acks arrive as they happen.
  - Why not OTLP: its partial-success response has no per-batch sequence ack, and the
    collector would re-encode the payload, which breaks a hash over bytes.
  - The ADR amends architecture 10.1, where OTLP becomes the collector's onward
    format. Keep the 4317 port, the SPIFFE pinning, and the switch rule.
- **The batch is opaque bytes, hashed as sent.** This is the same principle as
  `PolicyBundle.envelope`.
  - `Batch{ bytes header; bytes payload; }`.
  - `header` is canonical JSON (a fixed key order, so it re-serializes identically)
    holding these fields: `v`, `host_uuid`, `boot_id`, `chain_id`, `seq`, `prev_hash`,
    `count`, `first_ts`, `last_ts`, `payload_sha256`, `kind`.
  - `kind` is `events`, `dropped` or `chain_reset`.
  - `hash = SHA-256(len(header) as 4-byte big-endian || header || payload)`.
  - `payload` is a sequence of length-prefixed, deterministically marshaled
    Tetragon `GetEventsResponse` messages, after redaction and enrichment.
  - No compression in 7a; it is a 7b decision, measured first.
- **Chain identity.** A chain is `(host_uuid, boot_id, chain_id)`:
  - `chain_id` is a random 128-bit value created when a chain starts;
  - `seq` starts at 1 and goes +1;
  - `prev_hash` of seq 1 is 32 zero bytes.
  - A relayd restart within the same boot **continues** the chain from the persisted
    head.
  - A new chain starts only when the boot changes, or when the head cannot be trusted
    (missing, corrupt, HMAC failure, tampered mode). In that case the new chain's first
    batch is `kind: chain_reset`, with a reason and the old chain's last known
    `(chain_id, seq, hash)` if there is one.
- **Chain head persistence.** The head (`chain_id`, `seq`, `hash`) is written
  atomically, HMAC-SHA-384 with the store's key, **before** the batch counts as
  spooled. Write it under `/var/spool/tetragon-relay` (already in `ReadWritePaths`; no
  unit change).
- **Spool.**
  - One file per batch, written to a temp file, fsynced, renamed, and the directory
    fsynced.
  - Each file is deleted only after an `Ack` covering its seq.
  - The size cap comes from config `collector.spool_max_bytes`.
  - On overflow, drop the oldest **non-security** batches first. Security events are
    those of type process_kprobe, process_lsm, process_tracepoint and process_uprobe;
    non-security events are process_exec and process_exit. The spool therefore tracks
    a class per batch, and batches are built per class.
  - Every drop emits a `kind: dropped` batch carrying `{count, seq_range, class}`, so
    loss is visible in the chain.
  - A batch file that fails its integrity check on read is dropped, counted and
    audited. It is never sent.
- **The collector can only acknowledge.**
  - An `Ack` for a seq greater than the highest sent, or for another chain, is a
    protocol error: audit it, close the stream, reconnect with backoff, and delete
    nothing.
  - Acks are cumulative.
  - On reconnect, resend everything unacknowledged, in order.
- **Ingest.**
  - Use `GetEvents` on the Tetragon socket with an allow-list filter. The event types
    come from config.
  - Bound every channel. When the pipeline is behind, block the reader rather than
    buffer without limit. Tetragon then drops events at its own buffer; record its
    lost-event count if the API exposes one. Verify this against the vendored
    v1.8.0 API and don't guess.
- **Redaction**, applied before anything is spooled:
  - drop the environment;
  - replace argv tokens that match the configured regexes with `[REDACTED]`;
  - replace file paths under `/home/*/.ssh/` with `sha256:<hex>`.
  - Patterns come from config in 7a, and config can only **add** patterns to a
    built-in default set. Signed patterns are step 7b.
  - Every regex is compiled at startup; a bad regex fails config validation. Use Go's
    RE2 `regexp` only (no backtracking).
- **Enrichment:** `host_uuid`, `boot_id`, the current epochs, and the agent version.
- **Batching:** at most `batch_max_events` (2000) or `batch_max_age` (2 s), whichever
  comes first.
- **Separation (architecture 10.2).**
  - The code lives in `internal/telemetry`.
  - A depguard rule in CI forbids `internal/telemetry` from importing `internal/apply`,
    `internal/verify`, `internal/guard`, `internal/trust`, `internal/controlclient`, or
    the apply-worker files of `internal/agent`, and forbids those packages from
    importing `internal/telemetry`.
  - The only shared surface is a narrow read-only interface supplying epochs and
    `telemetry_last_seq` and `backlog` for the heartbeat.
  - The telemetry connection uses its own mTLS dialer, pinned to the collector SPIFFE ID.
    Reuse the VerifyConnection code from ADR 0031; do not copy it.
- **Liveness.** The telemetry goroutines are registered liveness components that prove
  their own loops are alive, **not** that the collector is reachable. A collector
  outage must never cause a watchdog restart.

### Work items
T1. ADR and proto (`api/relay/telemetry/v1`), plus docs/telemetry-contract.md for the
    backend team:
    - the wire format, the hash, the chain rules and the ack rules;
    - what the collector must flag: `chain_gap`, `chain_fork`, `chain_reset`, and a
      duplicate seq with a different hash;
    - the heartbeat cross-check: the controller compares the heartbeat's
      `telemetry_last_seq` with what the collector received.
T2. `internal/telemetry`: ingest, redact, enrich, batch, chain, spool, export. Wire it
    into relayd. Fill the heartbeat's `telemetry_last_seq` and `telemetry_backlog`.
T3. **Reference chain verifier**, `internal/telemetry/chainverify`: a pure function the
    backend team can port or call. Give it table tests for gap, fork, reorder,
    duplicate, reset, boot change, a bad header and a hash mismatch.
T4. Fuzz targets: header parsing, the batch-file reader, and the chain verifier. Add
    them to the CI smoke run and the nightly fuzz job.
T5. Tests: crash-matrix tests for the spool and chain head (a crash at every write
    step, using the store's existing fault-injection approach), the overflow policy,
    redaction, a hostile ack, and resend on reconnect.
    - Coverage at least 90 % for `internal/telemetry`.
    - A benchmark at 5k events/s (record CPU and RSS in the report; not a gate yet).

### E3 scenarios (same harness rules: the real unit, documented drop-ins only)
Add `cmd/e3collector` (e3 tag). It is a collector that runs the reference verifier and
prints every batch header and verdict. Its endpoint must sit inside the unit's
`IPAddressAllow`; the existing `127.0.0.1/32` drop-in already covers it.
- **T-S1:** events arrive with a valid chain. A canary exec shows up with argv
  redacted, no environment, and a hashed `~/.ssh` path.
- **T-S2:** stop the collector for 30 s while events keep flowing. The spool grows and
  `telemetry_backlog` in the heartbeat rises. After restart everything drains in order,
  the verifier reports no gap, and the spool empties.
- **T-S3:** restart relayd mid-stream. The chain continues: same `chain_id`, seq +1,
  `prev_hash` matches.
- **T-S4:** a tiny spool cap (a drop-in setting only `collector.spool_max_bytes` through
  config, documented). Non-security batches are dropped first, a `dropped` batch
  appears in the chain, and security events survive.
- **T-S5:** the collector sends a hostile ack (a seq never sent). relayd audits it,
  reconnects, resends, and deletes nothing early.
- No SIGSYS anywhere in the job. Every syscall the telemetry path makes must be allowed
  by the unit as shipped. If one isn't, change the code, not the filter (as in 6b).

## Priority if the session runs short
Part A (A1 first), then T1, T3, T2, T5, the E3 scenarios T-S1 to T-S3, T4, and
T-S4 and T-S5 last. Stop only after a completed item with every workflow green and the
report updated.

## Definition of done
ci, integration and e3 green on GitHub for the final commit, with S1–S13 and T-S1 to T-S5
passing.

## Report: docs/reports/step-07a.md (also paste it in your final message)
Sections 1–10 as in previous steps, plus:
11. The telemetry pipeline as built: goroutines, bounds, and a Mermaid diagram from
    GetEvents to the ack.
12. E3 evidence for S13 and T-S1 to T-S5, per scenario.
13. Benchmark numbers against architecture 8.13's targets.
Progress log at the end, one line per push, as in 6b.
