# ADR 0003: Per-policy YAML size cap

## Status

Accepted.

## Context

Architecture doc section 7.5 bounds policy *counts* and *selector counts*
(≤ 64 policies, ≤ 256 kprobes, ≤ 4096 selector values) to bound BPF map and
verifier load, but does not state a byte-size cap for a single policy's YAML
text. Without one, a bundle could stay under the 64-policy count limit and
the 1 MiB overall envelope limit while still devoting almost the entire
envelope to one pathological policy document, which is wasted effort to
parse and hash before the guardrail engine (step 2) ever sees it.

## Decision

`internal/limits.MaxPolicyYAMLBytes` is set to 256 KiB per policy. This is
checked before the SHA-256 hash comparison and before guardrail evaluation,
so an oversized single policy is rejected (`REJECTED_SCHEMA`) immediately.

## Consequences

- 256 KiB is far larger than any realistic hand-written or generated
  TracingPolicy; this is a defensive ceiling, not a realistic working limit.
- Combined with the 64-policy cap, the worst case for per-policy processing
  in this step is bounded at 64 × 256 KiB = 16 MiB of YAML text — which
  cannot actually occur because the overall envelope is separately capped at
  1 MiB (architecture doc section 7.4 step 1), so the 1 MiB cap is the
  binding constraint in practice. This constant exists primarily to give a
  single, reviewable, named bound rather than relying on the envelope cap
  alone to limit per-policy work.
