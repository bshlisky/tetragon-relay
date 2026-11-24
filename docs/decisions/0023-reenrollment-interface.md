# ADR 0023: Operator re-enrollment interface (Reenroller)

## Status

Proposed.

## Context

Two places in this project's design require an explicit, operator-initiated recovery path
that nothing else may trigger automatically:

- Architecture doc section 8.4's agent state machine: `REVOKED -> UNENROLLED` happens "after
  operator re-enrollment," and no other transition reaches `UNENROLLED` from `REVOKED`.
- `docs/prompts/step-04b.md` Part C6: when `internal/store` detects tampering, "recovery is
  an explicit operator action (re-enrollment: specify the interface and an ADR now,
  implement later)."

Both are explicitly out of scope for step 4b's implementation (no identity/SPIRE client, no
control-stream client exist yet to re-sync from after re-enrollment), but the step 4b prompt
requires the interface and this ADR to exist now, so later steps implement against a reviewed
contract rather than inventing one ad hoc.

## Decision

`internal/agent.Reenroller` (`reenroll.go`):

```go
type Reenroller interface {
    Reenroll(ctx context.Context) error
}
```

- **Who may call it.** Only an operator-facing command (e.g. a future `relayd reenroll`
  subcommand, or an authenticated local control-socket RPC — the exact surface is a step
  5/6 decision). `Startup`, `internal/store`, and every other package in this project never
  call it themselves; a `TAMPERED` store or a `REVOKED` identity is a dead end from inside
  the agent's own startup path by design (`docs/reviews/step-04a-review.md`'s and
  `docs/prompts/step-04b.md`'s working agreement: "no silent fallbacks").
- **What a real implementation must do**, when built (step 5, once identity exists):
  1. Require a fresh, operator-supplied credential (a new join token or equivalent) —
     never proceed on cached state alone, since cached state is exactly what is
     untrusted.
  2. Re-attest the host's identity from scratch (TPM attestation, architecture doc
     section 5.2), obtaining a new SVID; the old one is not reused even if it would
     still parse, since a `REVOKED` identity's certificate must never be presented
     again.
  3. Discard the `TAMPERED` store directory's contents (`internal/store` itself never
     does this — this is the one place allowed to) and have `internal/store.Open`
     re-run its normal first-boot path against the now-empty directory.
  4. Re-sync from the controller (a reconcile-mode bundle fetch) before enforcing
     anything new, rather than trusting any locally-cached LKG.
  5. Record an audit event for the re-enrollment itself (who/when), both locally and to
     the controller once the control stream is back up.
- **Why `context.Context`.** Re-enrollment involves network round trips (attestation,
  controller re-sync); a caller must be able to cancel/time it out, consistent with every
  other network-facing interface in this project (`internal/tetra`'s RPCs,
  `apply.ReachabilityChecker`).
- **Why no implementation yet.** A real `Reenroll` needs: an identity client (SPIRE/TPM,
  step 5), a control-stream client to re-sync from (step 6), and a store API to actually
  wipe and reinitialize a `TAMPERED` directory (not needed by anything else in step 4b,
  since `internal/store.Open` already refuses to touch a `TAMPERED` directory on its own).
  Building any of those now would be scope creep past this step's explicit boundaries.

## Consequences

- `internal/agent` has no fake `Reenroller` (step 4b's prompt lists this as interface-only,
  unlike `KeySealer`/`MonotonicCounter`, which need fakes now because `internal/store`'s own
  tests exercise them). A test-only fake can be added alongside the first real caller.
- `internal/store` remains free of any "wipe and reinitialize" method: the only way to clear
  a `TAMPERED` store is for something outside this project's current code (an operator, or
  eventually `Reenroll`'s own implementation) to remove the directory's contents and let the
  next `Open` run its ordinary first-boot path.
</content>
