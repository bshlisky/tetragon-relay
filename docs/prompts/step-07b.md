# tetragon-relay — new session: Step 7b (telemetry performance, compression, signed telemetry policy)

You are continuing an existing, security-critical project; the repository is the source of
truth. Repo: https://github.com/bshlisky/tetragon-relay (main).

## Binding context
- The working agreement in docs/prompts/step-04b.md (Part 0) applies, including the
  session-size rule, "never widen production privileges to make a test pass", the rule
  against guessing about external behavior (stop and ask, or measure), and the
  progress-log rule.
- Read these before you start:
  - docs/architecture.md sections 7.4, 8.10, 8.13 and 10
  - docs/telemetry-contract.md
  - docs/server-contract.md
  - docs/reports/step-07a.md (sections 6, 9, 11 and 13)
  - ADRs 0036–0039
  - the attached review, step-07a-review.md
- State: step 7a is accepted at eaa6c0b. The telemetry pipeline works end to end
  (T-S1 to T-S5). It measured about 8× over the CPU target, and its spool holds about
  55 minutes against the 8-hour target.

## First actions
1. Two files are ATTACHED: this prompt and step-07a-review.md. Commit them verbatim in one
   commit, with the deferred progress-log line for eaa6c0b:
   - docs/reviews/step-07a-review.md
   - docs/prompts/step-07b.md
2. Run `make ci` and confirm it is green.
3. Acknowledge with ≤ 12 bullets: your plan, plus anything in R7A-5's design you think is
   wrong. Raise it before you build it.

This step is large. **Plan for two sessions:** Parts P and Z in the first, Parts V and S in
the second. Stop at a green boundary with the report updated. The next session resumes from
the progress log.

## Part P — Performance (R7A-1)
P1. Add a Linux benchmark job step on the CI runner:
    - `BenchmarkPipeline5k` with pprof (CPU and alloc profiles uploaded as artifacts);
    - harness cost excluded: pre-built input events; measure the pipeline's goroutines
      only;
    - a cost breakdown by stage (decode, classify and redact, marshal, compress, spool).
    Put the baseline numbers in the report before you optimize anything.
P2. Optimize: field-specific redaction (no reflection), buffer and `sync.Pool` reuse, no
    per-event allocations in classify, and exactly one HMAC and one fsync per batch.
    Profile again after each change, and record before and after for each.
P3. Gate: a CI check fails if pipeline CPU is > 6 µs per event (≤ 3 % of a core at
    5k events/s) on the runner, with the measured value printed. If 6 µs can't be
    reached, **stop and bring the profile**. Do not relax the gate.
P4. An ADR amending 8.13's CPU and RSS targets to the measured, gated values. Also
    measure RSS of relayd itself under the real unit, in E3, at a sustained event rate:
    it must stay < 64 MiB with `MemoryMax=256M` untouched.

## Part Z — Compression (R7A-1)
Z1. A dependency ADR for `github.com/klauspost/compress/zstd`: vendored, pinned, covered
    by govulncheck, and included in the SBOM.
Z2. Payloads are zstd-compressed at a fast level, and the header gains `enc: "zstd"`.
    `payload_sha256` and the batch hash cover the compressed bytes as sent. Old
    uncompressed batches still in a spool stay valid (`enc` absent means `none`), and the
    reference verifier accepts both.
Z3. Decompression bombs:
    - The contract states a maximum decompressed size per batch (propose 8 MiB).
    - `chainverify` and e3collector enforce it with the decoder's memory limit.
    - Fuzz the decoder path.
Z4. Report the measured compression ratio on realistic events and the resulting hours per
    2 GiB at 5k events/s. Add the figure to the 8.13 ADR.

## Part V — Verify Tetragon behavior on the real binary (R7A-3, R7A-4)
V1. In CI, run `tetragon --help` (v1.8.0, the pinned tarball) and capture the flag that
    populates process environment variables. Cite the output in the report.
V2. Make T-S1 use that flag, run the canary with `SECRET_TOKEN=<random>` in its
    environment, and prove the token never reaches the collector. Search the
    collector's decoded output and the spool files for it.
V3. Slow-client experiment, as a new E3 scenario T-S6:
    - throttle the builder to about 100 events/s with a test-only hook (e3 tag);
    - generate about 2k exec/s for 60 s;
    - record Tetragon's RSS before, during and after, `RateLimitInfo`, and generated
      versus received counts.
    Write the observed behavior into ADR 0039. If loss happens without any signal from
    Tetragon, make relayd detect and surface it: an `Alert` plus a `dropped` record with
    an estimated count, using whatever discontinuity the event stream offers. Cite the
    field you use, and don't guess.

## Part S — Signed telemetry policy (R7A-5)
S1. An ADR covering the design in R7A-5:
    - the `telemetry-policy` document type, its DSSE payload type and its schema;
    - signed by the targets role, with epoch scope `telemetry`;
    - a new `TelemetryPolicy{envelope}` control message, and the contract update.
S2. Verification reuses `verify` (steps 1–9 and 11–12) with a telemetry guardrail set:
    - RE2 patterns compile, with size limits per pattern and in total;
    - the built-in redaction set can't be removed;
    - `process_kprobe` and `process_lsm` can't be removed from the allow-list;
    - `keep_env` is a list of variable names matching `^[A-Z_][A-Z0-9_]{0,63}$`, at most
      32 of them, never values.
    Fuzz the parser.
S3. Delivery runs as an apply-worker job (ADR 0036 ordering: after the apply in progress).
    The policy is persisted (store, HMAC'd) and applied to the telemetry pipeline between
    batches through a narrow interface that respects the depguard boundary: telemetry
    receives an already-verified, immutable policy value and imports nothing from verify
    or agent.
S4. Batch headers carry `telemetry_policy_epoch`, which is 0 for the built-in default.
    The verifier reports it.
S5. An E3 scenario, T-S7: a signed telemetry policy adds a pattern and drops
    `process_exec` from the allow-list. Exec events stop arriving, kprobe events keep
    arriving, and the new pattern is redacted. A replay of the same policy gets
    `REJECTED_EPOCH`. A policy that tries to remove `process_kprobe` gets
    `REJECTED_GUARDRAIL`.
S6. Contract additions: R7A-2's sentence about enrolled hosts that send no telemetry,
    and R7A-6's proposed defaults for the gap grace period (35 s) and pruning (24 h),
    marked "proposed, backend to confirm".

## Priority if the session runs short
P1, P2, P3, then Z, P4, V1, V2, S1–S4, S5, V3, S6.

## Definition of done
ci, integration and e3 green on GitHub for the final commit, with S1–S13 and T-S1 to T-S7
passing, and the CPU gate passing in CI.

## Report: docs/reports/step-07b.md (also paste it in your final message)
Sections 1–10 as in previous steps, plus:
11. The profile breakdown, before and after (a table per stage).
12. Compression ratio and spool hours.
13. Tetragon's slow-client behavior as observed (T-S6), with numbers.
14. E3 evidence for T-S6 and T-S7.
Progress log at the end.
