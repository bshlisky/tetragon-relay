# ADR 0017: Loaded-policy digest residual risk (amends architecture doc section 6.4)

## Status

Accepted.

## Context

Architecture doc section 6.4 and step 3 prompt Part D8 require a loaded-policy digest the
controller can compare against what it believes it shipped. Part D8 requires first
confirming whether Tetragon's `ListTracingPolicies` RPC returns policy content; if not,
the digest must be computed over what it does return instead, "since the loaded name
embeds the canonical hash prefix (D1), content identity is still bound."

`TracingPolicyStatus` (`api/v1/tetragon/sensors.proto:131-160`, pinned commit
`a5a667837d4b1ecd9018797994bb4e39b98702e1`) carries `id`, `name`, `namespace`, `info`,
`sensors`, `enabled` (deprecated), `filter_id`, `error`, `state`, `kernel_memory_bytes`,
`mode`, `stats`, `domain`, `hook_statuses` — no raw YAML, no content hash, nothing
content-addressed beyond the name itself. `internal/apply.Digest` therefore hashes the
sorted `(loaded_name, state, enabled, mode, sensors)` tuple for every relay-managed
policy `ListTracingPolicies` returns.

## Decision

Accept this digest as sufficient for this step, with the residual risk below tracked
explicitly rather than mitigated here (out of scope per the step 3 prompt's own framing).

## Residual risk

The loaded name (`<name>-v<version>-<8 hex of CanonicalSHA256>`) is the only part of the
digest that is actually bound to policy *content*. A root attacker on the host with
access to the Tetragon socket (already a significant compromise — see architecture doc
section 4.2's adversary list and T-02) could:

1. `DeleteTracingPolicy` the real, relay-loaded policy under its loaded name.
2. Craft and `AddTracingPolicy` a *different* policy document, loading it back under the
   exact same loaded name (Tetragon does not itself verify the name "means" a particular
   hash; the name is just a string to it).

`internal/apply.Digest` would not notice: the tuple `(name, state, enabled, mode,
sensors)` could be identical before and after, if the attacker's replacement policy
happens to produce the same sensor set and lands in the same state. Detecting this
specific attack is **not** this digest's job; it relies on other controls already in this
project's threat model:

- T-02 (root compromise of the relay host) is treated as a significant event requiring
  out-of-band detection (host intrusion detection, audit log review of the Tetragon
  socket's access), not something the policy digest alone can catch, per architecture
  doc section 13's threat model.
- Step 3 Part D5's health window still observes real enforcement *behavior* (events,
  admin-path kills, surge thresholds) regardless of what digest value is reported, so an
  attacker's replacement policy that actually changes enforcement behavior is still
  likely to trip a rollback even if the digest itself does not change.
- A future step (persistent LKG/epoch store, step 4; telemetry shipping, step 7) could
  extend this digest to include a periodically-reconciled content hash fetched out of
  band (e.g. reading back `/etc/tetragon/tetragon.tp.d/relay/` on disk, which this
  engine does fully control and fsync, Part D4) — not attempted here since it is a
  materially larger feature (a disk-based integrity check layered on top of the gRPC
  state Tetragon reports) that belongs with that store's own design.

## Consequences

- Operators/the controller should not treat `internal/apply.Digest` as a
  content-integrity proof against a root-level attacker; it detects ordinary drift
  (another legitimate actor adding/removing/disabling a relay-managed policy, or a
  partial apply) but not this specific replace-under-the-same-name attack.
- `internal/apply.Reconcile` (Part D9) comparing Tetragon reality to LKG inherits the
  same limitation, for the same reason.
