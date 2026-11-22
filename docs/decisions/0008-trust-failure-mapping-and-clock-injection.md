# ADR 0008: Mapping trust-root failures to verify result codes, and how "now" is injected

## Status

Accepted.

## Context

Architecture doc section 7.4's six result codes (`REJECTED_SIGNATURE`,
`REJECTED_TARGET`, `REJECTED_EPOCH`, `REJECTED_EXPIRED`, `REJECTED_SCHEMA`,
`ACCEPT`) do not include a code for "the trust root itself is expired" or
"a transparency-log inclusion proof was required but is not supported."
Separately, the prompt requires `internal/trust` and `internal/verify` to
never call `time.Now()` and to use an "injected clock," but the prompt's own
function signatures (`LoadInitialRoot(signedBytes) (*Root, error)` — no time
parameter at all; `(*Root).Update(newSignedBytes, now)`;
`(*Root).TargetsVerifier(now)`) show plain `time.Time` parameters, not a
`func() time.Time` closure type.

## Decisions

1. **Expired root metadata.** `(*Root).TargetsVerifier(now)` returns
   `ErrRootMetadataExpired` and a nil `Verifier` when `now` is at or after
   `Expires`. The caller (the future agent `control` module; simulated in
   this step's tests) is expected to treat "no Verifier obtainable" as
   equivalent to "no valid signature can be produced," i.e.
   `verify.Input.Trust = nil`, which `internal/verify.Verify` maps to
   `REJECTED_SIGNATURE` at step 3 ("no trust verifier configured"). This is
   the step-3 "else" branch of the algorithm in section 7.4, which is the
   closest fit: without current trust metadata, no signature can be deemed
   valid.
2. **Required but unimplemented log inclusion proof.** Step 4 of section 7.4
   says "if trust.require_log_proof: verify inclusion proof... else
   REJECTED_SIGNATURE" for a failed proof. Inclusion-proof verification
   itself is out of scope for this step (no transparency log client exists
   yet). Rather than silently treating `require_log_proof` as always
   satisfied (a silent fallback, forbidden by the prompt's engineering
   rules), `internal/verify.Verify` treats `RequireLogProof() == true` as an
   automatic `REJECTED_SIGNATURE`, with the reason noting it is unsupported.
   This fails closed: a root that demands log proofs gets no bundles
   accepted until a later step implements proof verification, rather than
   accepting bundles it cannot actually prove were logged.
3. **`LoadInitialRoot` and expiry.** `LoadInitialRoot` does not check whether
   the metadata it is loading is already expired; only
   `(*Root).TargetsVerifier(now)` enforces expiry. This matches the literal
   function signature in the prompt (`LoadInitialRoot(signedBytes)`, no time
   parameter) and is safe: an already-expired initial root will fail at the
   very next `TargetsVerifier` call any real caller must make before using
   it, so there is no window in which an expired root is treated as valid
   for signature purposes.
4. **Clock injection.** Rather than introducing a `type Clock func()
   time.Time` stored on `*Root` or passed to every function, "injected
   clock" is interpreted as: every function that needs the current time
   takes it as an explicit `time.Time` parameter (`Update(bytes, now)`,
   `TargetsVerifier(now)`), and no function in `internal/trust` or
   `internal/verify` calls `time.Now()` itself. This satisfies the
   underlying goal (determinism, testability, no hidden wall-clock reads)
   with less machinery, and matches the prompt's own signatures exactly.

## Consequences

- `expired_root_metadata` is a committed test vector
  (`testdata/vectors/expired_root_metadata.json`) exercising decision 1.
- `TestVerify_RequireLogProofRejects` in `internal/verify` exercises
  decision 2.
- These three mappings are not specified by the architecture doc and are
  listed as open questions for the architect in docs/reports/step-01.md.
