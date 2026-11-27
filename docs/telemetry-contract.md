# tetragon-relay agent — collector contract (telemetry)

Audience: the backend team implementing the collector. Design:
`docs/decisions/0039-telemetry-wire-format-and-chain.md` (amends architecture 8.10 and
10.1). Proto: `api/relay/telemetry/v1/telemetry.proto`. Reference verifier:
`internal/telemetry/chainverify` (a pure Go function with table tests; call it or port
it). Test collector: `cmd/e3collector` (build tag `e3`).

The collector is an **untrusted peer** of the agent (architecture 10): it can read and
drop telemetry, and it can acknowledge batches. It can do nothing else.

## 1. Transport

- gRPC service `relay.telemetry.v1.Collector`, one RPC: `Export(stream Batch) returns
  (stream Ack)`.
- mTLS on port 4317, TLS profile as for the controller (server-contract section 2): TLS
  1.3 only, AES-GCM suites, no resumption, no 0-RTT, ALPN `h2`.
- Your server certificate carries URI SAN `spiffe://<td>/mgmt/collector` and no DNS/IP
  SANs. The agent pins exactly that SPIFFE ID; verify the agent's client certificate
  (`spiffe://<td>/host/<uuid>`) the same way the gateway does (server-contract section
  3).
- **`header.host_uuid` must match the client certificate's host UUID.** Reject (close
  the stream) otherwise.
- Maximum message size: 2 MiB. A batch payload is at most 1 MiB.

## 2. The batch

`Batch{bytes header; bytes payload}`. **Never re-encode either field.** Store and forward
the exact bytes.

### 2.1 Header

Canonical JSON with exactly these keys in exactly this order, no whitespace:

```json
{"v":1,"host_uuid":"…","boot_id":"…","chain_id":"<32 hex>","seq":1,"prev_hash":"<64 hex>","kind":"events","class":"security","count":3,"first_ts":1795694400000000000,"last_ts":1795694401000000000,"agent_version":"…","epochs":{"prod-db":5},"payload_sha256":"<64 hex>"}
```

| Key | Rules |
| --- | --- |
| `v` | 1. Any other value: reject the batch (`bad_header`). |
| `host_uuid` | Must equal the client certificate's host UUID. |
| `boot_id` | The host's boot ID, or `""` when the agent had none it could trust. |
| `chain_id` | 32 lower-case hex characters (128 bits). |
| `seq` | ≥ 1. |
| `prev_hash` | 64 lower-case hex; 64 zeros when `seq` is 1. |
| `kind` | `events`, `dropped` or `chain_reset`. |
| `class` | `security` or `non_security` for `events`; `control` for the other kinds. |
| `count` | Number of events in the payload for `events` (≥ 1); 0 otherwise. |
| `first_ts`, `last_ts` | Unix nanoseconds; `first_ts ≤ last_ts`. |
| `agent_version` | Printable ASCII. |
| `epochs` | Scope → epoch, keys sorted. `{}` means the agent has no trustworthy epochs (tampered mode, server-contract 10.6). |
| `payload_sha256` | SHA-256 of `payload`, lower-case hex. |

**Parse strictly, then re-serialize and compare.** Reject unknown keys, duplicate keys,
other key orders, whitespace, upper-case hex, floats, and anything that does not
re-serialize to the identical bytes. Those are `bad_header`.

Security events are Tetragon `process_kprobe`, `process_lsm`, `process_tracepoint`
and `process_uprobe`. Non-security events are `process_exec` and `process_exit`.

### 2.2 Hash

```
hash = SHA-256( uint32_be(len(header)) || header || payload )
```

over the bytes as received. If `SHA-256(payload) != payload_sha256`, the batch is
`hash_mismatch` and is not part of the chain.

### 2.3 Payload

- `events`: `count` records, each `uint32_be(len) || bytes`, where the bytes are one
  `tetragon.GetEventsResponse` (Tetragon v1.8.0 API), already redacted on the host:
  - no `environment_variables`;
  - `arguments` tokens matching the host's patterns replaced with `[REDACTED]`;
  - paths under `/home/*/.ssh/` replaced with `sha256:<hex of the path>`.
- `dropped`: canonical JSON
  `{"class":"non_security","count":2,"batches":[{"chain_id":"…","seq":7,"hash":"…"},{"chain_id":"…","seq":9,"hash":"…"}]}`.
  The spool overflowed, so the agent deleted these batches unsent (or sent but not yet
  acked). `count` equals the number of entries. The hashes let you verify the
  `prev_hash` links across the hole.
- `chain_reset`: canonical JSON `{"reason":"boot_changed","prev":{"chain_id":"…","seq":41,"hash":"…"}}`
  or `{"reason":"head_missing","prev":null}`. Reasons: `boot_changed`, `head_missing`,
  `head_corrupt`, `tampered_mode`, `boot_id_unknown`.

## 3. Chain rules

A chain is `(host_uuid, boot_id, chain_id)`.

1. Seq 1 of every chain is `kind: chain_reset` with `prev_hash` of 64 zeros, and
   `chain_reset` appears at no other seq.
2. Every later batch has `seq = previous + 1` and `prev_hash = hash(previous)`.
3. A relayd restart within one boot continues the chain: same `chain_id`, the next seq,
   matching `prev_hash`.
4. A new chain starts when the boot changes or the agent's persisted head cannot be
   trusted. The old chain may still be draining: the agent sends every chain's
   remaining batches oldest-chain-first, on the same stream.
5. Batches the agent dropped are listed in a later `dropped` batch (in the current
   chain, possibly naming batches of an older chain).

## 4. What the collector must flag

Keep, per chain, the highest contiguous seq and its hash, plus any batches received
ahead of a gap. Flag:

| Signal | When | Severity (architecture 10.4) |
| --- | --- | --- |
| `chain_gap` | A seq is missing and no `dropped` record explains it, after the chain has moved on (the reference verifier reports it at the end of a run; a live collector should allow a grace period, e.g. 10 minutes or until the next heartbeat cross-check). | High; quarantine if combined with any other signal. |
| `chain_fork` | Two different batches claim the same `(chain_id, seq)` with different hashes, or a batch's `prev_hash` is not the hash of the batch before it (received, or listed in a `dropped` record). | High; quarantine if combined with any other signal. |
| `chain_reset` | Every seq-1 batch. Expected after a reboot (`boot_changed`); anything else (`head_missing`, `head_corrupt`, `tampered_mode`, `boot_id_unknown`) is a security event. | `boot_changed`: check it against the maintenance window; others: alert. |
| `duplicate_mismatch` | The same `(chain_id, seq)` arrives twice with different hashes (also a `chain_fork`). | High. |
| `bad_header`, `hash_mismatch` | Section 2. | Alert; the batch is not part of the chain. |
| `dropped` | Every `dropped` record: loss is declared, with class and count. | Informational; `security` class drops are an alert. |

An identical duplicate (same seq, same hash) is expected after a reconnect and is not a
signal.

## 5. Ack rules

- Send `Ack{chain_id: <16 raw bytes>, seq: N}` once batches up to `N` of that chain are
  **durably** stored. Acks are cumulative per chain. The agent deletes its spool files
  for that chain up to `N` when it receives the ack.
- **Ack only seqs you have received on the current stream.** After a reconnect the agent
  resends everything it holds unacked, so you will see duplicates; ack them again.
- Never ack a chain not sent on this stream, a seq above the highest the agent sent in
  that chain on this stream, or a seq lower than your previous ack for that chain on
  this stream. The agent treats any of these as a protocol error: it audits it, closes
  the stream, reconnects with backoff and deletes nothing.

## 6. Heartbeat cross-check (controller)

The control stream's `Heartbeat` carries:

- `telemetry_last_seq`: the highest seq the agent has spooled in its **current** chain;
- `telemetry_backlog`: the number of batches spooled and not yet acked, across chains.

The controller compares `telemetry_last_seq` with the highest seq the collector has
received for that host's current chain. If the agent reports a seq the collector never
receives within a reasonable window (backlog draining aside), or the collector receives
seqs the agent never reports, something between them is dropping or injecting data
(architecture 10.3). A steadily growing `telemetry_backlog` with a reachable collector
means the collector is not acking.

## 7. What the agent never does

- It never sends anything but `Batch` on this stream, and acts on nothing but `Ack`.
- It never sends a batch that failed its own integrity check on read (it deletes and
  audits it), and never a batch with a seq above its persisted head.
- It never re-encodes a spooled batch: a resend is byte-identical.
