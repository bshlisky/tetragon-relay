# ADR 0039: Telemetry wire format and chain

## Status

Proposed (docs/prompts/step-07a.md Part T, "Design decisions already made"; the four
refinements in Decision 4 were confirmed by the architect at the start of step 7a).
Amends architecture doc 8.10 and 10.1.

## Context

Architecture 8.10 and 10 describe a hash-chained, spooled telemetry pipeline exported
over "OTLP/gRPC mTLS :4317". OTLP's partial-success response has no per-batch sequence
ack, so the agent could not know which spooled batch it may delete. An OTLP collector
would also re-encode the payload, which breaks a hash over bytes, the same reason
`PolicyBundle.envelope` is opaque (ADR 0010).

## Decision

### 1. Transport: our own gRPC service, not OTLP

`api/relay/telemetry/v1/telemetry.proto`:

```protobuf
service Collector {
  rpc Export(stream Batch) returns (stream Ack);
}
message Batch { bytes header = 1; bytes payload = 2; }
message Ack   { bytes chain_id = 1; uint64 seq = 2; }
```

A bidirectional stream, so acks arrive as batches are processed. The agent sends only
`Batch`; the collector sends only `Ack`. Port 4317, the collector SPIFFE ID pin
(`/mgmt/collector`) and the switch rule (host -> collector VIP tcp/4317) are unchanged.

**Amends architecture 10.1:** `... -> spool -> relay.telemetry.v1.Collector/Export (mTLS
:4317) -> collector (chain verifier) -> OTLP / Kafka (TLS, ACLs) -> SIEM ...`. OTLP
becomes the collector's onward format, not the agent's.

### 2. The batch is opaque bytes, hashed as sent

- `header` is canonical JSON: the keys below in exactly this order, no whitespace,
  integers as JSON integers, hex lower-case. A receiver parses it strictly (unknown or
  duplicate keys rejected), re-serializes it, and rejects it unless the bytes are
  identical. The hash is always over the bytes as received.

  | Key | Type | Meaning |
  | --- | --- | --- |
  | `v` | int | 1 |
  | `host_uuid` | string | from config (and the certificate) |
  | `boot_id` | string | from host facts (ADR 0034); `""` if unknown |
  | `chain_id` | hex, 32 chars | random 128-bit, set when the chain starts |
  | `seq` | int | 1, 2, 3, ... within the chain |
  | `prev_hash` | hex, 64 chars | the previous batch's hash; 64 zeros at seq 1 |
  | `kind` | string | `events`, `dropped` or `chain_reset` |
  | `class` | string | `security` or `non_security` for `events`; `control` otherwise |
  | `count` | int | events in the payload (`events`); 0 otherwise |
  | `first_ts`, `last_ts` | int | earliest / latest event time, Unix nanoseconds (creation time for control batches) |
  | `agent_version` | string | enrichment (Decision 4c) |
  | `epochs` | object | enrichment: scope -> epoch, keys sorted; `{}` in tampered mode |
  | `payload_sha256` | hex, 64 chars | SHA-256 of `payload` |

- `hash = SHA-256(uint32_be(len(header)) || header || payload)`.
- `payload` for `events`: a sequence of `uint32_be(len) || bytes`, each one
  `tetragon.GetEventsResponse` marshaled with `proto.MarshalOptions{Deterministic: true}`
  after redaction. Tetragon's own message is unchanged, so any Tetragon decoder reads it.
- `payload` for `dropped` and `chain_reset`: canonical JSON (Decision 4b, section 3).
- No compression in 7a (a 7b decision, measured first).

### 3. Chain identity and lifetime

- A chain is `(host_uuid, boot_id, chain_id)`; `seq` starts at 1 and goes +1; `prev_hash`
  of seq 1 is 32 zero bytes.
- **Seq 1 of every chain is `kind: chain_reset`, and `chain_reset` appears only at seq
  1.** Its payload: `{"reason":R,"prev":{"chain_id":...,"seq":N,"hash":...}}` or
  `{"reason":R,"prev":null}`. Reasons: `boot_changed` (prev = the old head),
  `head_missing`, `head_corrupt` (unreadable, bad HMAC, wrong host), `tampered_mode`,
  `boot_id_unknown`.
- A relayd restart within the same boot **continues** the chain from the persisted head.
- A new chain starts only when the boot changes or the head cannot be trusted (missing,
  corrupt, HMAC failure, tampered mode). With no trustworthy `boot_id` (host facts not
  fresh, ADR 0034) a chain is never continued: every start is a new chain with reason
  `boot_id_unknown`.

### 4. Refinements confirmed at the start of step 7a

a. **Acks name their chain.** After a reboot the old chain's unacked batches are still
   spooled, so one stream carries several chains, oldest first. `Ack{chain_id, seq}` is
   cumulative within that chain.
b. **A `dropped` record lists what it dropped:** `{"class":C,"count":N,"batches":[{"chain_id":...,"seq":S,"hash":H}, ...]}`,
   at most `limits.MaxDroppedEntriesPerRecord` entries (more drops produce more
   records). The verifier can still check every `prev_hash` link across the hole, and
   the record arrives after the gap it explains.
c. **Enrichment goes in the header** (`host_uuid`, `boot_id`, `epochs`, `agent_version`),
   once per batch; the payload stays Tetragon's own messages.
d. **Overflow** drops the oldest `non_security` batches first, then the oldest
   `security` batches. `control` batches are never dropped.

### 5. Chain head and spool

- Spool directory `/var/spool/tetragon-relay` (already in the unit's `ReadWritePaths`).
- One file per batch, `<chain_id>-<seq, 20 digits>.batch`: written to a temp file,
  fsynced, renamed, and the directory fsynced. The file carries the header, payload and
  an HMAC-SHA-384 over both.
- The head (`chain_id`, `seq`, `hash`, `host_uuid`, `boot_id`) is written atomically,
  with an HMAC-SHA-384, **after** the batch file and **before** the batch counts as
  spooled. A batch file with a seq above the head (a crash between the two writes) was
  never spooled: it is deleted and audited, never sent.
- The HMAC key is derived from the store key with HKDF-SHA-384, info
  `"tetragon-relay telemetry spool v1"`, so `internal/telemetry` never holds the store
  key itself.
- A batch file that fails its integrity check on read is dropped, counted and audited,
  never sent.
- Each file is deleted only after an `Ack` covering its seq in its chain.
- Size cap: `collector.spool_max_bytes`. Overflow per Decision 4d; every drop is
  followed by a `dropped` batch.

### 6. The collector can only acknowledge

- Acks are cumulative per chain.
- An `Ack` for a chain not sent on this stream, for a seq above the highest seq sent on
  this stream in that chain, or lower than an earlier ack on this stream for that
  chain, is a **protocol error**: audit it, close the stream, reconnect with backoff,
  delete nothing.
- On reconnect, everything unacknowledged is resent in order (oldest chain first).

### 7. Ingest, redaction, batching

- `GetEvents` with an allow-list `Filter{event_set}` from `collector.event_types`.
- Every channel is bounded. When the pipeline is behind, the reader blocks. Tetragon's
  `RateLimitInfo.number_of_dropped_process_events` is recorded when Tetragon sends it;
  the v1.8.0 API exposes no counter for events a slow client misses, and the vendored
  stubs do not show whether Tetragon drops or blocks for a slow client, so that is
  documented as unverified, not assumed.
- Redaction, before anything is spooled, on every `Process` in the event (`process`,
  `parent`, `ancestors`): drop `environment_variables`; replace space-separated tokens
  of `arguments` that match any pattern with `[REDACTED]`; replace a path under
  `/home/*/.ssh/` with `sha256:<hex>` (in `binary`, `cwd`, and every string argument of
  kprobe, tracepoint, uprobe and LSM events). Patterns: a built-in default set plus
  `redaction.argv_patterns`, which can only add. Go RE2 only, compiled at startup; a
  bad pattern fails config validation.
- Batching per class: at most `batch_max_events` (2000) or `batch_max_age` (2 s), and at
  most `limits.MaxTelemetryPayloadBytes` (1 MiB) of payload, whichever comes first.

### 8. Separation (architecture 10.2)

- Code lives in `internal/telemetry` (and its sub-packages).
- A depguard rule forbids `internal/telemetry` from importing `internal/apply`,
  `internal/verify`, `internal/guard`, `internal/trust`, `internal/controlclient` and
  `internal/agent`, and forbids those packages from importing `internal/telemetry`.
- The only shared surface: telemetry reads epochs through a narrow interface it defines;
  the heartbeat reads `telemetry_last_seq` and `telemetry_backlog` through a narrow
  interface `internal/agent` defines. `cmd/relayd` connects them.
- The telemetry connection has its own mTLS dialer pinned to the collector SPIFFE ID.
  ADR 0031's VerifyConnection moves to `internal/spiffetls`, imported by both
  `internal/controlclient` and `internal/telemetry`, so it is shared, not copied.

### 9. Liveness

The telemetry goroutines are liveness components that prove their own loops run, not
that the collector is reachable. A collector outage never withholds the watchdog.

## Consequences

- The backend team implements `relay.telemetry.v1.Collector` and the verifier described
  in docs/telemetry-contract.md; `internal/telemetry/chainverify` is a reference they
  can call or port.
- Events read from Tetragon but not yet spooled when relayd crashes are lost without a
  trace in the chain. The chain proves completeness from the spool onward, not from
  the kernel.
