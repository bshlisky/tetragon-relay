# ADR 0013: Proposed root-metadata fields for G9 (guardrail extension)

## Status

Proposed. This step does NOT change the root metadata wire format (ADR
0004); it only defines the `internal/guard.ProtectedSetSource` interface
and a no-op fake, per the step 2 prompt's explicit instruction ("Do NOT
change the root-metadata format... write ADR proposing where these fields
would live, for architect review"). This ADR is that proposal, submitted
for architect review before any implementation.

## Context

Architecture doc section 7.5 and the step 2 prompt's guardrail rule G9
require: "guardrails can only be EXTENDED (more protected
binaries/paths) by signed trust-root metadata, never by a bundle." A
policy bundle has no legitimate path to add to `internal/guard`'s
compiled-in `protectedBinaries`/`protectedPaths` lists
(`internal/guard/protected.go`); `internal/guard.ProtectedSetSource` is the
interface the real extension mechanism will implement, but *where that
data is signed and transported* is a trust-root metadata question (ADR
0004's territory), not a guard-package question, and changing that format
is explicitly out of scope for this step.

## Decision (proposed, not implemented here)

Extend the root metadata payload (ADR 0004's `relay.root.v1` schema) with
two new top-level, optional fields, siblings of `require_log_proof`:

```json
{
  "schema": "relay.root.v1",
  "version": 1,
  "expires": "...",
  "keys": { "...": "..." },
  "roles": { "...": "..." },
  "require_log_proof": false,
  "extra_protected_binaries": ["/opt/vendor-agent/agent"],
  "extra_protected_paths": ["/opt/vendor-agent/state/"]
}
```

Rationale for this placement rather than, say, a new DSSE payload type or a
field inside `roles`:

- It reuses the root role's existing signing/threshold/versioning/rotation
  machinery (section 7.6) exactly as-is: a 2-of-3 root-key-signed update
  can add entries the same way it adds/removes targets-role keys today, and
  the existing monotonic-version and dual-threshold checks in
  `(*trust.Root).Update` already prevent a downgrade attack against this
  data without any new code.
- Putting it in root metadata (not targets or log) matches the trust
  level required: only the *root* role's offline, 2-of-3 key ceremony
  should be able to expand what a bundle can do to the host, exactly
  mirroring how only root can add/remove targets-role keys. If this lived
  in a structure the online targets key could sign, a stolen targets key
  (already a modeled threat, T-13) could extend the protected set itself
  into something absurd (or shrink its *effective* value by adding
  decoys), which defeats the point of G9 requiring root-level sign-off.
- `extra_*` (additive) naming, and the fields being optional with "absent
  means no extension" semantics, keeps `LoadInitialRoot` and existing root
  metadata (which this project's vectors already use) valid without
  modification — no breaking change to ADR 0004's shape, only an addition.

A real `ProtectedSetSource` implementation (a later step) would be a thin
adapter reading `(*trust.Root)`'s now-loaded fields (once `internal/trust`
is extended to parse them — also not done in this step) and returning
them from `ExtraBinaries()`/`ExtraPaths()`. `internal/guard`'s rules
already call `g.extraBinaries()`/`g.extraPaths()` everywhere
`protectedBinaries`/`protectedPaths` are consulted (G1, G2), so no guard
rule code would need to change when this is wired up — only
`internal/trust`'s root payload struct and a new adapter type.

## Consequences

- No code in this step reads or writes these fields; `internal/trust`'s
  root payload shape (ADR 0004) is untouched, and `internal/guard`'s
  `ProtectedSetSource` interface has exactly one real-codebase consumer so
  far: `fakeProtectedSetSource` in `internal/guard`'s tests.
- If the architect prefers a different placement (e.g. a dedicated
  `targets`-role-adjacent structure, or a wholly separate signed artifact),
  `ProtectedSetSource`'s two-method shape (`ExtraBinaries() []string`,
  `ExtraPaths() []string`) does not need to change — only which concrete
  type implements it.
- Until a real implementation exists, every deployment effectively runs
  with `ExtraProtected == nil` (or a fake returning nothing), meaning only
  the compiled-in lists apply; this is fail-safe (never less protection
  than the compiled-in baseline), not fail-open.
