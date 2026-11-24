# tetragon-relay — new session: Step 4c (store hardening and remaining tests)

You are continuing an existing, security-critical project for an enterprise customer.
You have no memory of earlier sessions; the repository is the source of truth.

Repo: https://github.com/bshlisky/tetragon-relay (branch main). Clone it fresh.

## Binding context
- The working agreement, environment rules and "Read these before writing any code" list
  in docs/prompts/step-04b.md (Part 0) apply to this session unchanged. Read that prompt in
  full first; then read docs/reports/step-04b.md and the attached review.
- Current state: step 4b is accepted as partial at 75d523e (ci and integration green). The
  store (internal/store) and agent startup (internal/agent) exist; Parts E3, E4, E5 and E7
  of the step 4b prompt are not yet done.

## First actions
1. Two files are ATTACHED: this prompt and step-04b-review.md. Commit them verbatim in one
   commit ("docs: add step 4b review and step 4c prompt"):
   - docs/reviews/step-04b-review.md
   - docs/prompts/step-04c.md
2. Run `make ci` from a clean clone; confirm green.
3. Acknowledge with ≤ 12 bullets: what 4b built, the six review items and your plan.

## Part A — Review follow-ups (one commit each; regression tests each)
Full details and test lists are in docs/reviews/step-04b-review.md. Do them in this order:
A1. R4B-3: ownership check fails closed on unknown platforms.
A2. R4B-4: fsync in the blob "already present" path.
A3. R4B-5: ErrCommittedCounterLag, plus the caller-behavior test.
A4. R4B-1: forward root chaining across multiple versions (roots/ directory, ADR).
A5. R4B-6: refuse to adopt ML-DSA-requiring roots when ML-DSA is unavailable; DEGRADED
    reporting for an already-persisted one.
A6. R4B-2: raw-envelope LKG. This changes an interface (apply.LKGStore). Write the ADR
    first, as Proposed. If the design in the review conflicts with anything you find in
    the code, stop and ask before implementing.
Also add the Q3 test from the review: Startup rejects as tamper a persisted root with a
valid HMAC that fails trust verification.

## Part E — Remaining tests from step 4b (after Part A, so they cover the final design)
E3. Trust-root tests: RPM newer and chaining (accept); newer and not chaining (reject,
    keep persisted); older (ignore); first boot; a hybrid rotation persisted then
    reloaded; plus the R4B-1 multi-version cases.
E4. Property test: random sequences of apply, epoch, history and trust operations with
    random crash points and reopens never violate monotonic epochs, monotonic root
    versions, or LKG re-verification.
E5. FuzzStoreIndex (index parser), wired into the CI fuzz smoke and nightly workflows.
E7. Integration (real Tetragon): apply a bundle; simulate an agent restart (close and
    re-open the store, run Startup); confirm the epoch and the LKG persisted and the LKG
    re-verifies; replay the same bundle and confirm REJECTED_EPOCH; confirm Tetragon's
    loaded set was never changed by the restart.

Coverage gates: ≥ 95% internal/store, internal/trust, internal/verify, internal/dsse;
≥ 90% internal/agent, internal/apply.

## Definition of done
Both ci and integration green on GitHub for the final commit.

## Report: docs/reports/step-04c.md (also paste it in your final message)
Sections 1–10 as in previous steps, plus:
11. For each R4B item: commit SHA, tests, and how the fix was verified.
12. E7 integration evidence (run number, scenario output).
