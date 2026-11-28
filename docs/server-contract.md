# tetragon-relay agent — controller/gateway contract

Audience: the backend team implementing the controller's stream gateway, signer and
collector (docs/prompts/step-05b.md: "The server side is not built in this repository").
Everything here is derived from `docs/architecture.md` and this repository's actual code, with
file:line citations so you can verify each claim yourself. `internal/testcontroller`
(`cmd/testcontroller`, build tag `testserver`) is a runnable reference implementation of the
**handshake only** (TLS, client-certificate checks, Hello/HelloAck) — not of the message loop,
bundle distribution, or anything else below.

## 1. The AgentControl gRPC service and messages

Proto: `api/relay/control/v1/control.proto`. One bidirectional stream, `AgentControl.Connect`
(`control.proto:19-23`): the agent dials, the stream stays open for the life of the
connection, and either side sends asynchronously.

```protobuf
service AgentControl {
  rpc Connect(stream AgentMessage) returns (stream ControllerMessage);
}
```

**Exactly one active stream per host identity** (`control.proto:20-21`): if a second stream
opens from the same SPIFFE ID (not source IP — the identity, from the client certificate),
the gateway must terminate the OLDER stream and raise a duplicate-identity alert. The agent
does not implement this check; it is the gateway's job entirely.

**Server-side revocation is authoritative.** The gateway must refuse a revoked SPIFFE ID
at the mTLS layer (the denylist check in section 3), on every new connection, not rely on
the agent remembering that it was revoked. The agent persists a REVOKED marker (ADR 0035)
and normally stays away, but an agent whose store is TAMPERED cannot read that marker
(tampered mode, ADR 0038), so it will try to connect again after a restart.

### 1.1 `AgentMessage` (agent → controller), `control.proto:25-34`

| Field | Type | Semantics |
| --- | --- | --- |
| `seq` | `uint64` | Pinned (`docs/decisions/0032-seq-numbering-starts-at-one.md`): the first `AgentMessage` on a stream has `seq = 1`; every following message's `seq` is exactly the previous plus 1. Any other value -- 0, a gap, a regression, a repeat -- is a protocol error: the gateway sends `Terminate{PROTOCOL_ERROR}` and closes the stream. `internal/testcontroller.Server.Connect` enforces this on the first message today. |
| `body` (oneof) | `Hello \| Heartbeat \| ApplyResult \| StateReport \| Alert` | Exactly one of these per message. |

### 1.2 `ControllerMessage` (controller → agent), `control.proto:36-47`

| Field | Type | Semantics |
| --- | --- | --- |
| `seq` | `uint64` | Same pinned rule (`docs/decisions/0032-seq-numbering-starts-at-one.md`), the controller's own, independent stream direction: first message `seq = 1`, then exactly +1. The agent closes the stream and reconnects (existing backoff) on any other value; it does not trust a `Terminate` from a peer whose own sequencing is already broken. |
| `body` (oneof) | `HelloAck \| PolicyBundle \| StateRequest \| RotateIdentity \| TrustUpdate \| Terminate` | **This set is closed by design** (`control.proto:46`): "No exec, file write, shell, config-set, or debug messages exist by design." Do not add messages to this oneof without an ADR-equivalent review on the agent side — the agent's proto breaking-change CI gate (`docs/decisions/0010-proto-breaking-change-baseline.md`) will reject an uncoordinated change anyway. |

### 1.3 `Hello` (agent → controller, once per connection), `control.proto:49-66`

Sent as the very first `AgentMessage` after the TLS handshake completes (architecture
`6.3` step 3). Field-by-field semantics and source are in section 11 below (this step's
Hello field-by-field table, since this repository is the one that fills these in).

### 1.4 `Heartbeat`, `control.proto:68-75`

Sent every 15 s in steady state (architecture `6.3` step 5). `epochs` and `loaded_digest`
are the same values (recomputed each time) as `Hello`'s — see section 11. A normal agent
reports one `epochs` entry for every scope it serves, even when that epoch is 0. **An
empty `epochs` map means the agent has no trustworthy epochs at all**: it is in tampered
mode (section 10.6). Never read an empty map as "every epoch is zero". `health` comes
from Tetragon's `GetHealth` plus the agent's own process liveness (not yet implemented in
this repository; step 6). `telemetry_last_seq`/`telemetry_backlog` describe the separate
telemetry pipeline (architecture section 10), not this stream.

### 1.5 `ApplyResult`, `control.proto:77-87`

Sent exactly once per `PolicyBundle` the agent receives, whatever the outcome, including
a bundle superseded before it was applied (section 10). It may arrive long after the
bundle: an apply includes the health window (up to 600 s), and an ApplyResult produced
while the stream is down is sent after the next HelloAck. `status` is one of:

```
STATUS_UNSPECIFIED(0) REJECTED_SIGNATURE(1) REJECTED_TARGET(2) REJECTED_EPOCH(3)
REJECTED_EXPIRED(4) REJECTED_SCHEMA(5) REJECTED_GUARDRAIL(6) APPLY_FAILED(7)
ROLLED_BACK(8) REJECTED_CAPABILITY(9) APPLIED(10) SUPERSEDED(11) REJECTED_TAMPERED(12)
REJECTED_AGENT_STATE(13) ROLLBACK_FAILED(14) ROLLED_BACK_UNVERIFIABLE(15)
```

**Only `APPLIED` means applied.** Treat `STATUS_UNSPECIFIED`, and any status number
your bindings do not know, as **not applied** (ADR 0037). The agent never sends
`STATUS_UNSPECIFIED`; receiving it means the message was damaged or built by something
other than this agent. Never branch on `detail`: every outcome the controller must act
on has its own status.

`detail` is bounded to 4 KiB and must never contain secrets (enforced agent-side by
`internal/limits.MaxReasonBytes` for the shorter guardrail-rejection strings this maps from;
the gateway should still treat this field as untrusted-length input it forwards, not parses).

### 1.6 Everything else in the proto

`TetragonHealth`, `StateReport`, `LoadedPolicy`, `Alert`, `HelloAck`, `PolicyBundle`,
`StateRequest`, `RotateIdentity`, `TrustUpdate`, `Terminate` are all defined in
`control.proto:97-179` with field comments; nothing in this repository builds or sends most
of them yet (only `Hello` and `HelloAck`, this step — see "What this repository does not
implement yet" below). Read the proto file directly for exact field lists; it is the source
of truth and is under buf breaking-change protection
(`docs/decisions/0010-proto-breaking-change-baseline.md`).

## 2. The TLS profile the gateway must use

Architecture `docs/architecture.md:294-307` (section 6.1), as implemented by
`internal/controlclient/tlsconfig.go` (the agent side) and `internal/testcontroller/server.go`
(a reference server side):

| Parameter | Required value | Agent-side enforcement |
| --- | --- | --- |
| Protocol | TLS 1.3 only | `tlsconfig.go`: `MinVersion = MaxVersion = tls.VersionTLS13`, plus `VerifyConnection` re-checks `cs.Version` post-handshake |
| Cipher suites | `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256` only (never `TLS_CHACHA20_POLY1305_SHA256`) | **Go's TLS 1.3 stack cannot restrict which suite is offered pre-handshake** (`crypto/tls.Config.CipherSuites` doc: "TLS 1.3 ciphersuites are not configurable"). The agent enforces this as a POST-handshake check instead (`tlsconfig.go`'s `VerifyConnection`): if the gateway ever negotiates `TLS_CHACHA20_POLY1305_SHA256` with this agent, the agent will refuse the connection after the fact. **The gateway's own TLS stack must not rely on the agent for this** — configure your server to prefer/only offer the two required suites if your TLS library allows it. |
| Groups | `secp384r1`, `secp256r1` (agent default, `controlclient.DefaultGroups`); config-overridable list so a future hybrid ML-KEM group can be added without an agent code change (ADR 0022) | `tlsconfig.go`: `CurvePreferences` |
| Client auth | Required; verify chain to the enrollment/identity trust bundle; URI SAN must match `spiffe://<td>/host/*` | **Gateway's job entirely** — the agent presents its enrolled chain (`internal/identity.CertManager`'s output); see section 3 for what you must check |
| Server auth | Agent verifies the gateway's own certificate's URI SAN equals **exactly** the configured `spiffe://<td>/mgmt/controller` (SPIFFE ID pinning, never hostname — the agent's certs carry no DNS/IP SANs at all) | `tlsconfig.go`'s `VerifyConnection`: full chain verification against `ControllerCABundle` plus an exact `leaf.URIs[0].String() == ControllerSPIFFEID` check |
| 0-RTT | Disabled | Go's TLS client does not implement 0-RTT at all; **your server must not offer or accept 0-RTT/early data** |
| Session resumption | Disabled | Agent: `SessionTicketsDisabled: true`, `ClientSessionCache: nil`. **Your server must not issue session tickets** (or PSKs) that the agent could be made to present — it has no code path that would send one, but your server offering them wastes a round trip at best and should simply be turned off |
| ALPN | `h2` | Set automatically by both grpc-go's client and server `credentials.NewTLS` wrappers; no action needed if you use grpc-go, otherwise set it explicitly |
| Keepalive | HTTP/2 PING every 30 s, timeout 10 s | Agent: `grpc.WithKeepaliveParams` (`internal/controlclient/client.go`). Your gateway should set compatible (or more lenient) `keepalive.ServerParameters`; if your server's own ping interval is much shorter, you will generate unnecessary traffic, not a protocol violation |
| Limits | Max frame 1 MiB, 1 stream per identity, header list 16 KiB | Agent: `grpc.MaxCallRecvMsgSize`/`MaxCallSendMsgSize` set to `internal/limits.MaxControlMessageBytes` (1 MiB). **"1 stream per identity" and "header list 16 KiB" are gateway-enforced**, not negotiated by the agent |

### 2.1 Why you cannot authenticate the agent by hostname or IP

Agent and controller certificates (architecture `5.1`) carry **no DNS or IP SANs**, only a
URI SAN (the SPIFFE ID). If your TLS/HTTP stack defaults to hostname verification, you must
disable it and verify the URI SAN explicitly instead — exactly the problem
`internal/controlclient/tlsconfig.go`'s own doc comment describes solving on the agent side
(Go's `crypto/tls` — and grpc-go — auto-populate `ServerName` from the dial target if left
empty, which would otherwise silently re-enable a hostname check that can never pass against
these certificates).

## 3. Controller-side client checks (architecture 6.3 steps 1-2)

On every new stream, before trusting anything the agent sends:

1. **Chain valid** — your TLS stack already did this if configured per section 2.
2. **Not on denylist** — re-checked every 60 s on live streams too (architecture `6.3`
   step... see `docs/architecture.md:275` — the denylist row in the revocation table),
   not just at connect time.
3. **`host-uuid` exists in inventory** — the host UUID comes from the certificate's URI SAN
   (`spiffe://<td>/host/<uuid>`), **not** from the `Hello.host_uuid` field, which must be
   checked to MATCH the certificate (reject if they disagree — this is exactly what
   `internal/testcontroller/server.go`'s reference `Connect` handler does:
   `hello.GetHostUuid() != hostUUID` is rejected).
4. **State not `decommissioned`** (or equivalent inventory state) — this repository has no
   opinion on your inventory's state machine; just don't skip the check.
5. **Source IP matches the host's recorded management IP** (architecture `11.4`) — this is
   the credential-to-port binding; `internal/testcontroller`'s reference implementation does
   **not** implement this check (it has no inventory/IP database), so do not treat its
   absence there as "optional."

Any failure: TLS alert (reject at the TLS layer if you can determine the reason before the
handshake completes) or an immediate `Terminate` with a reason (section 6).

## 4. Controller-side limits and behaviors (architecture 6.5)

- **Per-identity rate limits**: 1 stream, 10 messages/s, 64 KiB/s sustained. Not implemented
  anywhere in this repository (agent or test server) — this is entirely your responsibility.
- **Message size cap 1 MiB**; bundles above 512 KiB rejected **at authoring time** (in your
  policy UI / signer pipeline, not at the gateway).
- **`seq` is pinned, not merely increasing** (`docs/decisions/0032-seq-numbering-starts-at-one.md`):
  per direction (the agent's `seq` and your own `seq` are independent counters), the first
  message is `seq = 1` and every following message is exactly the previous plus 1. Any other
  value — not just a gap or regression, but also `seq = 0` on the first message or a repeat —
  closes the stream.
- **The gateway only forwards bundles whose digest it has a Signer receipt for; it cannot
  construct envelopes itself** (and the agent would reject a self-constructed one anyway —
  see section 5's verification algorithm, which never trusts the gateway's own signature).

## 5. The bundle and trust-root formats

The gateway's job here is narrow and absolute: **forward the DSSE envelope bytes exactly as
the Signer produced them, inside `PolicyBundle.envelope` (`control.proto:141-149`), never
re-encoding, re-serializing, or otherwise touching the bytes.** `control.proto:142-146`'s own
comment states why: "even a semantically-neutral re-serialization... could change the bytes
being signed over." The agent verifies the DSSE signature over exactly the bytes it receives
(`internal/dsse`, `internal/verify`); any re-encoding, even byte-for-byte semantically
equivalent JSON, breaks verification and the agent will reject the bundle.

- **Envelope / payload format**: `docs/architecture.md` section 7.3 (`:457` onward in the
  current file; read that section directly — it is long and this document does not
  reproduce it). Built in `internal/dsse` and consumed by `internal/verify`.
- **Root metadata format**: typed keys (`ecdsa-p384`, `mldsa-87`), `require_keytypes`
  mandatory per role (ADR 0022). Built and consumed by `internal/trust`.
- **`require_keytypes`**: every role (root, targets, log) must declare which key type(s) it
  requires; a role's threshold can be met by any mix of key types, but `require_keytypes`
  additionally requires at least one signature of each listed type. Production roles today
  require `ecdsa-p384` only (ADR 0022's "Production default").
- **The Signer's obligations** (architecture `7.2` steps 4-7): re-verify every WebAuthn
  approval against its OWN credential registry (never trust the gateway's forwarded
  approvals blindly), check role membership/author≠approver/approval age/scope limits, sign
  with the HSM (non-exportable key, rate-limited), and append to the transparency log. None
  of this is the gateway's job or in this repository's code — it is listed here so the
  backend team implementing the Signer has the exact step numbers to cross-reference against
  `docs/architecture.md`.

## 6. What the agent will reject, and the `ApplyResult` codes it returns

(Built in steps 2-4 of this project, not step 5b; summarized here for the backend team's
reference since `ApplyResult.Status` is part of this step's proto contract.)

| Status | Meaning |
| --- | --- |
| `STATUS_UNSPECIFIED` | Never sent by the agent. Not applied. |
| `APPLIED` | Bundle verified and applied. The only status that means applied. |
| `REJECTED_SIGNATURE` | DSSE signature(s) did not satisfy the current trust root's role threshold/`require_keytypes`. |
| `REJECTED_TARGET` | This host is not in the bundle's target set. |
| `REJECTED_EPOCH` | Bundle's epoch is not newer than the host's persisted epoch for that scope (replay/rollback defense — `internal/store`'s monotonic counter backs this, step 5a). |
| `REJECTED_EXPIRED` | Bundle's `not_before`/`expires` window, or the trust root's own expiry, failed against the agent's clock (plus skew tolerance, `internal/limits.ClockSkew`). |
| `REJECTED_SCHEMA` | Bundle failed JSON Schema or guardrail validation (`internal/policydoc`, `internal/guard`). |
| `REJECTED_GUARDRAIL` | Passed schema but failed a specific guardrail rule. |
| `APPLY_FAILED` | Verified and accepted, but applying it to Tetragon itself failed. |
| `ROLLED_BACK` | Applied, then rolled back after a failed health window (architecture `7.7`). |
| `REJECTED_CAPABILITY` | Host capability probe (`internal/hostprobe`) says this host cannot safely run what the bundle requires. |
| `SUPERSEDED` | A newer bundle replaced this one in the agent's pending slot before it was started; never verified (section 10.2). |
| `REJECTED_TAMPERED` | The agent's store is TAMPERED; no bundle is applied until operator re-enrollment. |
| `REJECTED_AGENT_STATE` | Verified, but the agent's state (e.g. `DEGRADED`, `DRIFT`) does not allow `APPLYING`. Resend after the host returns to steady state. |
| `ROLLBACK_FAILED` | The health window failed and re-asserting LKG also failed; the agent is `DEGRADED` (section 10.3). |
| `ROLLED_BACK_UNVERIFIABLE` | Applied, but the health window could not prove that its view of Tetragon's events was current (freshness sentinels late or missing) for a full nominal window before its maximum (600 s), so the bundle was rolled back and LKG re-asserted (ADR 0042). Not a verdict on the bundle: retry when the host is less loaded. |
| any other number | Unknown to you: treat as not applied. |

## 7. What the agent trusts the server for, and what it does not

**Trusts the server (gateway) for:**
- Delivering a signed bundle it is otherwise unable to construct itself (the agent cannot
  author policy).
- Timely delivery (heartbeats, reconcile) — a slow or unavailable gateway degrades
  connectivity, not security (architecture `8.4`'s `DEGRADED` state; LKG enforcement
  continues locally).
- Which controller SPIFFE ID is legitimate — but only as configured locally
  (`ControllerSPIFFEID`), never auto-discovered from anything the gateway itself asserts.

**Does NOT trust the server for:**
- Bundle authenticity or integrity — every bundle is re-verified from the raw DSSE bytes
  against the agent's own trust root, regardless of what the gateway forwarded it as.
- Trust root authenticity — `TrustUpdate` entries are each verified via
  `(*trust.Root).Update` one version at a time against the agent's own persisted root; a
  gateway cannot push an unsigned or wrongly-signed root version and have it accepted.
- The agent's own identity — client certificate possession is proven by the TLS handshake
  itself (the TPM-backed private key never leaves the agent), not asserted.
- Anything about host state the agent can determine itself — `Hello`/`Heartbeat`'s
  `loaded_digest` is computed from Tetragon's own `ListTracingPolicies` response, not from
  anything the gateway told the agent it should be (architecture `6.4`).

## 8. Conformance checklist

- [ ] TLS 1.3 only; reject (or never offer) TLS 1.2 and below.
- [ ] Present a server certificate with URI SAN `spiffe://<td>/mgmt/controller`, no DNS/IP
      SANs, chaining to the agents' configured controller CA bundle.
- [ ] Require and verify the agent's client certificate; check chain, denylist, inventory
      membership, state, and source-IP binding (section 3) before trusting anything on the
      stream.
- [ ] Enforce (or confirm your TLS stack already does) no 0-RTT, no session resumption.
- [ ] Respond to `Hello` with `HelloAck{nonce: <32 random bytes>, heartbeat_interval_seconds}`
      within whatever timeout your SLA requires (the agent has no fixed timeout coded against
      this yet — step 6).
- [ ] Enforce 1 stream per identity (terminate the older one, raise an alert).
- [ ] Enforce per-identity rate limits and the message size cap.
- [ ] Forward `PolicyBundle.envelope` byte-for-byte, never re-encoded.
- [ ] Never construct a `PolicyBundle` envelope yourself; only forward one with a Signer
      receipt.
- [ ] Reject (`Terminate{PROTOCOL_ERROR}`) a stream whose `AgentMessage.seq` does not start
      at 1 and increase by exactly 1 thereafter
      (`docs/decisions/0032-seq-numbering-starts-at-one.md`); send your own `ControllerMessage.seq`
      the same way.

**Reference implementation of the handshake only**: `cmd/testcontroller` (build tag
`testserver`; see its README). It implements the TLS profile, the client-certificate checks
listed in section 3 (chain via TLS, denylist, inventory — **not** source-IP binding), and
Hello/HelloAck. It does **not** implement anything in sections 4-7 (rate limits, bundle
forwarding, the full message loop) — do not use it as a reference for those.

## 9. What this repository does not implement yet (so you don't wait on it)

- Remote attestation (`Hello.pcr_quote` is always empty from this repository today).
- The production controller, gateway, signer and collector themselves — this repository only
  ever builds the agent, plus `cmd/testcontroller` (handshake-only test tooling) and this
  contract document.

## 10. Bundle delivery (step 6b)

Implemented in `internal/agent` (`applyworker.go`, `bundle.go`); design in
`docs/decisions/0036-apply-worker-and-pending-bundle-slot.md`.

### 10.1 What the agent does with a `PolicyBundle`

1. The stream loop hands `PolicyBundle.envelope` (the exact bytes, never re-encoded) to
   the agent's single apply worker and goes straight back to reading the stream. It does
   **not** reply at this point. Heartbeats continue every 15 s throughout the apply,
   including the health window, so the gateway must never treat a host as SILENT because a
   bundle is being applied.
2. The worker verifies the envelope (architecture 7.4) against the agent's current trust
   root, persisted epoch and monitor history, the host's capability facts and the
   compiled guardrails.
3. If verification passes and the agent is in `STEADY` (or `SYNCING`), it enters
   `APPLYING`, applies (architecture 7.7, add-before-remove, health window) and, **only
   after the health window passes**, commits the new epoch, LKG and (for a monitor
   bundle) monitor history to its store in one atomic write.
4. It sends one `ApplyResult`.

### 10.2 The pending-bundle rule

The agent applies one bundle at a time and holds **at most one** bundle waiting:

- A bundle that arrives while another is being applied is held in a single pending slot.
- If a further bundle arrives before the pending one was started, the pending one is
  replaced. The replaced bundle is answered at once with
  `ApplyResult{status: SUPERSEDED, detail: "superseded", bundle_digest: <its digest>, epoch: 0}`.
  `epoch` is 0 because a superseded bundle is never verified, so nothing from its
  payload is reported.
- A pending bundle is verified when it is started, not when it arrived. A bundle whose
  epoch was current on arrival but is no longer ahead once the apply in front of it
  commits is rejected `REJECTED_EPOCH` (with a verification reason, not
  `"superseded"`).

**The slot is per host, not per scope.** Epochs are per scope, but the agent only
learns a bundle's scope by verifying it, and it verifies at dequeue, not on arrival. So
a scope-A bundle waiting in the slot can be replaced by a scope-B bundle, and scope A
then gets nothing until you resend (review R6B-4). The controller must therefore follow
these rules:

- **On `SUPERSEDED`, if the host's reported epoch for that bundle's scope is still below
  the bundle's epoch, resend the latest bundle for that scope.** Use the epochs from the
  next `Heartbeat` or `StateReport` (the `ApplyResult` of a superseded bundle carries
  `epoch: 0`, so use your own record of which scope and epoch you sent with that
  digest).
- **A controller should keep at most one bundle in flight per host**: send the next
  bundle only after the previous one's `ApplyResult`. Then nothing is ever superseded.

A controller that wants a specific bundle applied should send only the newest one and
wait for its `ApplyResult`; sending a series back to back is safe but wasteful.

### 10.3 `ApplyResult` fields

| Field | Value |
| --- | --- |
| `bundle_digest` | SHA-256 of the exact `PolicyBundle.envelope` bytes received. |
| `epoch` | The bundle's epoch once its signature and payload verified; 0 when the bundle was rejected before its payload could be trusted (signature, schema, superseded, tampered store). |
| `status` | Section 6, refined below. Never `STATUS_UNSPECIFIED`; treat that and any unknown number as not applied. |
| `detail` | At most 4 KiB, no secrets. For a verification rejection, `"<CODE>: <reason>"`; for a guardrail rejection the reason names the rule (`guardrail rejection: G5`). |
| `loaded_digest_after` | Architecture 6.4's loaded digest, recomputed from Tetragon after the apply (empty for rejections that never reached Tetragon, and if Tetragon could not be listed). The same value the next Heartbeat carries. |

Status refinements:

| Situation | `status` | `detail` |
| --- | --- | --- |
| Store is TAMPERED (step 4b C6) | `REJECTED_TAMPERED` | `store TAMPERED: every bundle is rejected until operator re-enrollment` |
| Enforce bundle, host facts missing/stale or usrmerge check failed | `REJECTED_CAPABILITY` | names the reason |
| Agent not in `STEADY`/`SYNCING` (e.g. `DEGRADED`, `DRIFT`) | `REJECTED_AGENT_STATE` | `not applied: agent state <STATE> does not allow APPLYING` — resend after the host returns to steady state |
| Tetragon loaded the bundle but the store commit failed | `APPLY_FAILED` | `loaded in Tetragon but the store commit failed; ...` — the host's epoch did not move; reconcile re-asserts the previous LKG |
| Health window failed and the previous LKG was re-asserted | `ROLLED_BACK` | `rolled back: <reason>` — halt the rollout wave (architecture 7.7 step 8) |
| Health window could not verify its observation path before its maximum; LKG re-asserted | `ROLLED_BACK_UNVERIFIABLE` | `rolled back: health_unverifiable: nominal=… elapsed=… sentinels fired=… arrived=… late=… max_latency_ms=… p50_ms=… p90_ms=… last_ms=[…] received=… rate=…/s [relayd_cpu=… nr_throttled=+…]`; the agent raises `Alert{HEALTH_UNVERIFIABLE}`. Halt the wave as for `ROLLED_BACK`; the host stays `STEADY` |
| Health window failed and re-asserting LKG also failed | `ROLLBACK_FAILED` | the rollback's reason; the agent enters `DEGRADED` and raises `Alert{ROLLBACK_FAILED}` and `Alert{DRIFT}` |

### 10.4 Alerts

`Alert{kind, detail, unix_time}`; `detail` is at most 4 KiB and carries no secrets.

| Kind | When | What to do |
| --- | --- | --- |
| `DRIFT` | A reconcile cycle (every 60 s, at agent start, and at once after a Tetragon restart) found Tetragon's relay-managed policies differing from the agent's LKG. `detail`: `lkg_bundle_digest=<hex> loaded_digest=<hex> missing=[...] unexpected=[...]`. The agent enters `DRIFT` and re-asserts LKG **once**; if that holds it returns to `STEADY` (no further alert). If it does not, it stays in `DRIFT` and alerts on every cycle (`still drifted after re-assert: ...`), subject to the rate limit. Also raised, together with `ROLLBACK_FAILED`, when a rollback fails (section 10.3). | Architecture 10.4: re-assert; quarantine if still mismatched after one cycle. |
| `TETRAGON_UNHEALTHY` | Tetragon's `GetHealth` is not serving (checked every 5 s), or Tetragon restarted (detected as a new process behind its socket). | Architecture 10.4: quarantine if repeated 3x in 10 min. |
| `TRUST_EXPIRED` | The agent's current trust root is expired: once per connection (after HelloAck) and again daily while it stays expired. Every bundle is rejected meanwhile (`REJECTED_SIGNATURE`, reason `trust root metadata has expired`); LKG stays enforced. | Send a `TrustUpdate`. |
| `TAMPER` | The agent's store was found TAMPERED while running (a bundle, trust update or reconcile read it). From then on every bundle and trust update is rejected and reconcile is suspended (nothing Tetragon has loaded is changed) until operator re-enrollment. | Treat the host as compromised. |
| `GUARDRAIL_REJECT` | A bundle was rejected `REJECTED_GUARDRAIL` or `REJECTED_CAPABILITY` by a guardrail. `detail`: the bundle digest and the reason, which names the rule (`guardrail rejection: G5`). | Fix the bundle; the agent's guardrails are compiled in. |
| `TRUST_UPDATE_REJECTED` | A `TrustUpdate` (or a step of it) was not adopted (section 10.5). | Check the root chain you sent. |
| `ROLLBACK_FAILED` | A health-window rollback could not re-assert LKG (`ApplyResult.ROLLBACK_FAILED`). The agent is `DEGRADED`; Tetragon's loaded set may differ from LKG. | Treat as drift that the agent could not repair; architecture 10.4. |
| `HEALTH_UNVERIFIABLE` | A health window ended `ROLLED_BACK_UNVERIFIABLE` (ADR 0042). `detail`: `bundle <digest> epoch <n>: ` and the `ApplyResult.detail` above, with the measured sentinel latencies. | The host's event path is behind (an exec flood, or Tetragon's own backlog). Investigate the host's load; an enforce rollout to it is delayed, not lost. |
| `KIND_UNSPECIFIED` or any other number | Never sent by this agent. | Log and keep it as an alert of unknown kind; never drop it. |

**Rate limit.** At most one alert of each kind per 5 minutes; the first of each kind is
always sent. A suppressed alert is still written to the agent's local audit log
(`alert_suppressed`); every sent alert is too (`alert`). Do not infer "resolved" from the
absence of a repeat: the agent sends no "cleared" alert. Use `Heartbeat.loaded_digest`
and `StateReport` for current state.

**While disconnected.** ApplyResults and alerts produced while the stream is down are
queued and sent right after the next HelloAck, before anything else, in the order they
were produced, each with a fresh `seq`. The queue has a bound per class (R6B-3):
ApplyResults at most 16, alerts at most 48. Alerts never push out an ApplyResult. Past
its own bound, the oldest message of the same class is dropped and counted locally; a
dropped ApplyResult is also audited (`outbox_apply_result_dropped`). One apply runs at a
time, so 16 ApplyResults are reached only if the controller sends many bundles to a
host that cannot reach it; a bundle with no ApplyResult after reconnect should be
resent.

**TAMPER at startup.** A store found TAMPERED at agent *startup* puts the agent in
tampered mode (section 10.6), which sends `TAMPER` after every HelloAck.

### 10.5 `TrustUpdate`

`TrustUpdate.signed_roots` is the ordered chain N+1..M of root metadata envelopes, each
the exact signed bytes. The agent:

- processes it on the same worker as bundles: **after** any bundle apply in progress
  finishes and **before** a pending bundle is verified, so a root never changes during a
  verification, and a bundle sent right after a `TrustUpdate` is verified under the new
  root;
- skips entries at or below its current version (you do not need to know which version
  the agent has; sending the whole chain from version 2 is fine);
- verifies each next version against its predecessor (old root threshold and new root
  threshold, exactly one version forward, not expired, validity at most 365 days) and
  persists it before it becomes current; each step is atomic;
- stops at the first entry that fails, keeping the last version it reached, and raises
  `Alert{TRUST_UPDATE_REJECTED}`. The same happens, adopting
  nothing, if the store is TAMPERED, if `signed_roots` is empty or has more than 64
  entries, or if a version requires `mldsa-87` and the agent's build has no ML-DSA;
- sends no reply on success. The adopted version shows up as `Hello.trust_root_version`
  on the next connection. A successful update is audited locally.

At most 4 `TrustUpdate` messages are held while a bundle apply runs; beyond that the
oldest is dropped. You resend trust metadata on every reconcile anyway (architecture 6.3
step 4).

### 10.6 Tampered mode (step 7a, ADR 0038)

If the agent's store is TAMPERED when relayd starts, relayd does not exit. It connects
to report the tamper, and otherwise changes nothing:

| What you see | Meaning |
| --- | --- |
| `Alert{TAMPER}` right after HelloAck, before the first heartbeat | Store TAMPERED at startup. Treat the host as compromised. |
| `Hello` with no trust root, no LKG digest and an empty `epochs` map | No epoch, LKG or trust root on the host can be trusted. |
| Heartbeats with live `loaded_digest` and `health` and an empty `epochs` map | Tetragon's real loaded set, still reported; no epochs. |
| `ApplyResult{REJECTED_TAMPERED}` for every bundle, `epoch: 0` | Nothing is verified or applied. |
| `Alert{TRUST_UPDATE_REJECTED}` for every trust update | Nothing is adopted. |
| `RotateIdentity` has no effect | The agent keeps the identity it has. |

The agent never writes to Tetragon in this mode, so what Tetragon had loaded stays
loaded. It stays in this mode until it is restarted; recovery is operator
re-enrollment. If you send `Terminate{REVOKED}`, it stops connecting for the life of
the process and tries to persist the marker; it may not be able to, so after a restart
it will connect again, and your gateway must refuse it (section 1).

