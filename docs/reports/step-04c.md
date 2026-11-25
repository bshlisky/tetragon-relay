# Step 4c report: store hardening and remaining tests

## 1. Summary

- Part A (step-04b-review.md's six follow-ups), all closed, one commit each:
  - **R4B-3**: `checkOwnerAndMode` now fails closed (refuses to open) on a platform where
    `fi.Sys()` is not `*syscall.Stat_t`, instead of silently skipping the ownership check.
  - **R4B-4**: `writeBlobIfMissing`'s "already present" branch now fsyncs the existing file
    and the blobs directory, rather than assuming an earlier writer already did.
  - **R4B-5**: a new `store.ErrCommittedCounterLag`, distinct from `ErrCounterUnavailable`,
    for "index write committed but the counter Increment right after it failed" — plus a
    regression test through the real `internal/apply.Engine` <-> `*store.Store` wiring
    proving the apply engine never rolls Tetragon back because of it.
  - **R4B-1**: forward root chaining across multiple RPM-shipped versions
    (`Config.AvailableRPMRoots`), walking one version at a time from the persisted version,
    stopping at a gap, a misnamed file, a duplicate-version conflict, a chain-verification
    failure, or a new `limits.MaxRootChainFiles` step bound. ADR 0024 documents the RPM
    packaging layout decision this depends on (`roots/<version>.root.json`, `root.json`
    kept as the first-boot/lowest version).
  - **R4B-6**: the chain-walk now refuses to **adopt** a candidate root requiring
    `mldsa-87` when the crypto self-test reports ML-DSA unavailable (stops, keeps the last
    good version, audits); `StartupResult` gained `Degraded`/`DegradedReason` so an
    **already-established** root requiring it surfaces immediately, not just at the first
    bundle.
  - **R4B-2**: the LKG is now persisted as the raw signed DSSE envelope (ADR 0025,
    Proposed then implemented): `apply.LKGSet` gained `RawEnvelope`/`RootVersion`
    (additive, no `LKGStore` method-signature change), `verify.Result` threads them
    through from `Input.Envelope`/`Input.RootVersion`, `internal/store` persists the raw
    envelope and retains every root version's blob still referenced by any domain's LKG
    (`TrustRootHistory`, pruned to the live set on every commit), and
    `internal/agent.Startup` now re-verifies every domain's LKG at every boot against the
    *exact* historical root version that verified it.
- The Q3 open question from step-04b-review.md ("Startup rejects a persisted root whose
  bytes carry a valid HMAC but fail trust verification") now has a dedicated regression
  test.
- Part E, all four remaining items closed:
  - **E3**: the trust-root test matrix is complete — RPM newer/chaining, RPM
    newer/not-chaining, RPM older/ignored, first boot, and the previously-missing "hybrid
    rotation persisted and reloaded" case — plus the full R4B-1 multi-version matrix (two
    versions behind, a gap, a misnamed file, an unparsable file, a duplicate-version
    conflict, the step bound, a persist failure mid-walk).
  - **E4**: a new property test (`internal/store/property_test.go`) runs randomized,
    deterministically-seeded sequences of `RecordEpoch`/`Put`/`PersistTrustRoot` with random
    simulated crash points and reopens, asserting epochs and root versions are never
    observed to go backward and that every domain's `LKG.RootVersion` always still has a
    retrievable root (ADR 0025's retention invariant) — across combinations the existing
    per-operation crash matrix does not exercise.
  - **E5**: `FuzzStoreIndex` (the index JSON parser), seeded from a real index file plus
    hand-built/malformed variants, wired into `make fuzz-short` and `nightly-fuzz.yml`.
  - **E7**: a new `internal/agent` integration test (`-tags integration`, same harness
    convention as `internal/tetra`'s/`internal/apply`'s) against a real Tetragon: apply a
    bundle, record its epoch, simulate an agent restart (close/reopen the store, run
    `Startup` — which re-verifies the LKG for real), confirm the epoch and LKG survived,
    replay the same envelope and confirm `REJECTED_EPOCH`, and confirm Tetragon's own
    loaded set is unchanged by the restart. **Run and confirmed green on GitHub Actions
    against real Tetragon v1.8.0** (run 45554200234; see section 12).
- Coverage gates hold for every package touched: `internal/store` 95.7% (≥95%),
  `internal/agent` 90.3% (≥90%), `internal/apply` 91.9% (≥90%), `internal/verify` 99.5%
  (≥95%). `internal/tetra`'s 86.0% local-only shortfall is the same pre-existing,
  environment-specific (macOS, linux-only test files) condition step-04b's report
  documented — unaffected by this step and passing on GitHub Actions' Linux runner.
- No deviations from this prompt or the architecture; no new third-party dependencies.

## 2. File tree of what was added or changed (since 75d523e)

```
.github/workflows/ci.yml                     (integration job builds/runs internal/agent's new itest)
.github/workflows/nightly-fuzz.yml           (+FuzzStoreIndex)
Makefile                                     (fuzz-short +FuzzStoreIndex)
docs/
  decisions/0024-forward-root-chaining.md    (new, Accepted: R4B-1 RPM layout)
  decisions/0025-lkg-raw-envelope.md         (new, Proposed->implemented: R4B-2)
  prompts/step-04c.md                        (new, committed verbatim)
  reports/step-04c.md                        (this file)
  reviews/step-04b-review.md                 (new, committed verbatim)
internal/
  agent/
    errors.go                                (+ErrTooManyRootFiles)
    startup.go                               (R4B-1 multi-version chain, R4B-6 refuse/degrade, R4B-2 reverify wiring)
    reverify.go                              (new: ADR 0025 per-domain LKG re-verification)
    helpers_test.go, internal_test.go,
    startup_test.go, reverify_test.go        (new tests for all of the above)
    integration_test.go                      (new, -tags integration: Part E7)
  apply/
    interfaces.go                            (LKGSet +RawEnvelope, +RootVersion)
    engine.go                                (+ResolveLKGSet; bundleToLKG carries the new fields)
  limits/limits.go                           (+MaxRootChainFiles, +MaxStoreRootHistoryVersions)
  store/
    errors.go                                (+ErrCommittedCounterLag)
    blob.go                                  (R4B-4 fsync-existing-blob)
    store.go                                 (R4B-3 fail-closed ownership; R4B-5 ErrCommittedCounterLag;
                                               ADR 0025 TrustRootHistory/Domains/RootAtVersion)
    index.go                                 (indexPayload +TrustRootHistory; lkgEntry +RootVersion)
    coverage_test.go, store_test.go,
    apply_wiring_test.go                     (new), property_test.go (new), fuzz_test.go (new)
  verify/
    input.go, result.go, verify.go           (Input +RootVersion, Result +RawEnvelope/RootVersion)
    reverify.go                              (new: ParseBundleUnverified)
    reverify_test.go                         (new)
```

## 3. Command output

### Local verification (macOS/Darwin, this development machine)

Same platform caveat as step-04b: `make ci`'s own `lint` target fails locally only on the
pre-existing, environment-specific `internal/tetra/_linux.go`-only `unused` findings
(confirmed unchanged on a clean `75d523e` checkout, and not touched by this step). What was
run and verified locally, matching `ci.yml` as closely as this platform allows:

```
$ gofmt -l $(...); goimports -l $(...)                       # clean
$ go vet ./...; go vet -tags integration ./...                # clean
$ golangci-lint run ./...                                     # 5 pre-existing unused findings, internal/tetra/_linux.go only
$ golangci-lint run --build-tags "testtools integration" ./internal/agent/...   # 0 issues
$ govulncheck ./...                                            # No vulnerabilities found
$ go mod verify; make vendor-check; make verify-crd; make verify-tetragon-api   # all OK
$ go build ./...; go build -tags integration ./...             # clean
$ go test -race -count=1 ./...                                 # ok, all packages
$ go test -run=NONE -fuzz=FuzzStoreIndex -fuzztime=20s ./internal/store/...   # PASS, 211+ interesting inputs, no crashes
$ make coverage                                                 # see table below; all ≥95%
$ make coverage90                                               # internal/tetra 86.0% (pre-existing, macOS-only; see step-04b report);
                                                                 # apply/hostprobe/agent all pass
```

GitHub Actions (authoritative) run numbers are in the table below; `gh run view` confirms
`ci` green on every commit in this step (three commits share a single push/run each where
noted) and `integration` green for the final commit, including the new
`TestIntegration_AgentRestartPersistsEpochAndLKG` actually running and passing against a
real Tetragon v1.8.0.

### Per-package coverage (`go test -cover`, this run)

| Package | Coverage | Gate |
| --- | --- | --- |
| internal/dsse | 100.0% | ≥95% |
| internal/strictjson | 98.5% | ≥95% |
| internal/trust | 95.3% | ≥95% |
| internal/verify | 99.5% | ≥95% (was 100.0% before ADR 0025's `ParseBundleUnverified`; new tests brought it to 99.5%) |
| internal/policydoc | 95.9% | ≥95% |
| internal/guard | 96.8% | ≥95% |
| **internal/store** | **95.7%** | **≥95%** |
| internal/tetra | 86.0% local (linux-only tests excluded on darwin) / passing on GitHub Actions | ≥90% |
| internal/apply | 91.9% | ≥90% |
| internal/hostprobe | 90.4% | ≥90% |
| **internal/agent** | **90.3%** | **≥90%** |

### GitHub Actions run numbers (this step's commits, branch `main`)

| Commit | ci | integration |
| --- | --- | --- |
| `b52ac0d` docs: step 4b review + step 4c prompt | 45505779781 success | (docs-only) |
| `1e9db99` R4B-3 | — (pushed with the next two) | — |
| `6ea6373` R4B-4 | — (pushed with the next) | — |
| `a81fe76` R4B-5 (covers R4B-3/4/5 in one push) | 45508874566 success | — |
| `e7dd96b` R4B-1 | 45508905904 success | — |
| `7785086` R4B-6 | — (pushed with ADR 0025 docs) | — |
| `049eaea` ADR 0025 (Proposed) | 45550121696 success | — |
| `6f88674` R4B-2 implementation | 45552424016 success | — |
| `9997e5c` Q3 test | 45552604383 success | — |
| `b6225f6` E3 hybrid rotation test | 45552764797 success | — |
| `2edf309` E4 property test | 45553300678 success | — |
| `9335ed0` E5 FuzzStoreIndex | 45553628336 success | — |
| `942eb89` E7 integration test (**final commit**) | 45554200234 success | **45554200234 success** |

(The `ci` and `integration` jobs share one GitHub Actions *run* ID per push; `integration`
runs as a second job gated on `ci` via `needs: ci`, so the table's single run number covers
both where `integration` ran at all — it is skipped for docs-only/no-op-for-Linux pushes
the same way step-04b's table showed.)

### Fuzz, benchmarks

`FuzzStoreIndex` (new, Part E5) ran 20s locally with 211+ interesting corpus entries
discovered and zero crashes; `make fuzz-short` (60s/target, including the new target) runs
on every `ci` push. No other fuzz target's seed corpus or behavior changed. No new
benchmarks were added or needed changing.

### govulncheck

No vulnerabilities found, locally and on every green `ci` run in the table above. No new
third-party dependencies were added this step.

## 4. Mapping: item → functions → tests → vectors

| Item | Functions | Tests |
| --- | --- | --- |
| R4B-3 (fail-closed ownership check) | `checkOwnerAndMode` | `TestCheckOwnerAndMode_UnknownPlatformFailsClosed`, `TestCheckOwnerAndMode_UnknownPlatformStillChecksModeFirst` |
| R4B-4 (fsync existing blob) | `writeBlobIfMissing`, `fsyncExistingBlob` | `TestWriteBlobIfMissing_AlreadyPresentFsyncsAgain` |
| R4B-5 (`ErrCommittedCounterLag`) | `commitLocked` | `TestCommitLocked_CounterIncrementFailsAfterDurableWrite`, `TestApplyEngine_LKGStorePutErrorDoesNotRollBackTetragon` |
| R4B-1 (multi-version chain) | `establishTrustRoot`, `collectRootChainCandidates` | `TestStartup_MultiVersionChain_*` (9 tests: two-behind-accept, gap, misnamed file, malicious non-chaining file, unparsable file, duplicate-version conflict, step bound, persist failure, too-many-files config error) |
| R4B-6 (refuse/degrade for ML-DSA) | `establishTrustRoot`'s chain-walk refusal, `startupDegradedCondition`, `rootRequiresMLDSA` | `TestEstablishTrustRoot_RefusesToAdoptRootRequiringUnavailableMLDSA`, `TestStartupDegradedCondition_ReportsWhenPersistedRootRequiresUnavailableMLDSA` |
| R4B-2 (raw-envelope LKG) | `verify.Verify`/`ParseBundleUnverified`, `apply.ResolveLKGSet`, `store.Store.{Put,Get,PersistTrustRoot,RootAtVersion,Domains}`, `agent.reverifyLKG`/`reverifyDomainLKG` | `TestParseBundleUnverified_*` (7), `TestRootHistory_RetainedWhileReferencedThenGarbageCollected`, `TestDomains_*`, `TestRootAtVersion_*`, `TestStartup_ReverifyLKG_*` (8 tests covering happy path, tampered-with-matching-HMAC, no-raw-envelope-skip, root-not-retained, corrupt-historical-root, expired-root-skip, cached-content-mismatch, verified-under-old-root-survives-rotation) |
| Q3 (valid HMAC, invalid trust metadata) | `establishTrustRoot`'s persisted-root-parse-failure branch | `TestStartup_PersistedRootWithValidHMACButFailingTrustVerificationIsTampered` |
| E3 (trust-root matrix) | (see R4B-1 row; plus) `TestStartup_HybridRotationPersistedAndReloaded` | — |
| E4 (property test) | `runPropertySequence` | `TestProperty_RandomOperationSequence` (5 seeded sub-tests) |
| E5 (fuzz) | `decodeIndexFile` | `FuzzStoreIndex` |
| E7 (integration) | `agent.Startup`, `apply.Engine.Apply`, `verify.Verify`, `store.Store` (real Tetragon) | `TestIntegration_AgentRestartPersistsEpochAndLKG` |

## 5. Invariants and threats addressed

- **T-07/T-24 (replay / rollback)**: R4B-5's `ErrCommittedCounterLag` and the E4 property
  test together close a gap in how confidently this step's own crash-safety claims could be
  stated: the property test is the first evidence that monotonicity holds across
  *combinations* of operations with interleaved crashes, not only each operation in
  isolation.
- **T-13/T-24 (stolen key / rollback, trust root)**: R4B-1's multi-version forward chaining
  closes the "falls behind by more than one RPM release, can never catch up" gap
  step-04b-review.md identified — the host's root is never permanently frozen behind a
  single missed release. R4B-6 adds a new, distinct threat closure: adopting a root that
  requires an algorithm this build cannot evaluate would otherwise make every future bundle
  silently unverifiable; the chain-walk now refuses that specific step outright.
- **INV-1 (signature/threshold is the basis of acceptance) extended to the LKG**: R4B-2 is
  this step's primary new invariant. Before it, a restarted agent's LKG was only as
  trustworthy as the store's own HMAC (an operational integrity check, not a cryptographic
  provenance one); after it, every persisted LKG is independently re-verifiable against the
  exact trust-root version that originally accepted it, and `internal/agent.Startup`
  actually performs that re-verification on every boot, with any mismatch escalated to
  `store.ErrTampered` fail-closed, same as every other tamper path.
- **State rollback (step-04b's own primary invariant)**: unaffected structurally by this
  step; R4B-2's `TrustRootHistory` retention is additive bookkeeping on top of the same
  generation/counter mechanism, verified by E4's property test to never violate it.

## 6. Deviations from this prompt or the architecture

None. R4B-2 — the one item flagged by the architect as needing a stop-and-ask rather than a
deviation note — was implemented via ADR 0025, written as Proposed and confirmed against the
user before any code was written (see that ADR's Status/Context for the full design and the
session record for the explicit confirmation).

## 7. Dependencies added

None.

## 8. Known limitations

- Everything in `internal/store` still sits behind fake interfaces (`FakeKeySealer`,
  `FakeMonotonicCounter`) — no TPM integration (step 5, unchanged from step 4b).
- `internal/agent.Reenroller` remains interface-only (ADR 0023), unchanged.
- R4B-1's packaging half (the RPM actually shipping `roots/<version>.root.json` files, and
  relayd's `main()` listing that directory into `Config.AvailableRPMRoots`) is deferred to
  step 6/8 as ADR 0024 documents; this step only fixes the shape those later steps must
  produce and consume, consistent with step-04b's prompt's own "Out of scope" for
  packaging.
- `internal/apply.Engine` still does not itself call `verify.EpochSource.RecordEpoch` /
  `guard.PolicyHistory.RecordMonitorNames` after a successful apply — that orchestration
  (Part D1's documented ordering) is relayd `main()`'s job, step 6, same as step 4b's
  report already noted. The E7 integration test calls `store.RecordEpoch` directly, in the
  same place that future orchestration would, to exercise the real persisted-epoch/replay
  path end to end without building step 6 early.
- `internal/tetra`'s coverage90 gate shows 86.0% on this (macOS) development machine for the
  same pre-existing, environment-specific reason step-04b's report documented (its
  `_linux.go` files and their tests do not build here); GitHub Actions' own Linux runner is
  unaffected and this step did not touch `internal/tetra` at all.

## 9. Open questions for the architect

1. R4B-2's design keeps `apply.LKGSet.Policies`/`.Mode` as an operational cache alongside
   the new `RawEnvelope`/`RootVersion` (ADR 0025 section 2), rather than deriving them from
   the envelope on every `Get()` call. Is this the right trade-off, or should `Get()` (or a
   periodic background pass) re-derive them lazily instead, trading a small amount of CPU
   for one less place the two could ever drift apart outside of `Startup`'s own explicit
   re-verification?
2. `internal/agent.reverifyLKG` treats an historical root whose OWN validity has expired as
   "skip, audit, not tamper" (ADR 0025, section 4's implementation note). Is this the
   intended operational posture for a domain that has not received a new bundle in a very
   long time, or should an operator-facing signal (beyond an audit record) exist for "this
   domain's LKG can no longer be re-verified until its scope gets a fresh bundle"?
3. E7's integration test calls `store.RecordEpoch` directly (see section 8) since
   `apply.Engine` does not call it itself. Should step 6's relayd `main()` wiring be
   prioritized next specifically to close this gap, given it is now the one piece of the
   verify → apply → store pipeline this step's own integration evidence had to work around
   rather than exercise as built?

## 10. Self-review: 5 places a reviewer is most likely to find a bug

1. **`prunedRootHistory`'s reliance on every commit re-deriving its "keep" set from the
   CURRENT `next.LKG`/`next.TrustRoot`, not from history's own existing keys** (`store.go`):
   this is correct (verified by the E4 property test, which specifically found and this
   report's author fixed a *test-harness* bug exploiting a misunderstanding of exactly this
   point before the property test itself was trusted), but it is subtle enough that a future
   change to `commitLocked`'s ordering (e.g. pruning before `next.LKG`/`next.TrustRoot` are
   both fully populated) could silently reintroduce a premature-GC bug with no new test
   failure until a rotation + a stale Put coincide in production.
2. **`reverifyDomainLKG`'s "no raw envelope recorded" skip** (`agent/reverify.go`): any
   `LKGSet` with an empty `RawEnvelope` is treated as "nothing to check," which is correct
   for genuinely pre-R4B-2 data but would also silently skip re-verification of a *new*
   record if some future caller ever constructed one without setting `RawEnvelope` (a
   programming error, not an attack) — there is no way for this package to distinguish "old
   data, expected" from "new data, caller bug" from the stored bytes alone.
3. **R4B-1's `collectRootChainCandidates` ordering ("root.json's candidate is considered
   first")** (`agent/startup.go`): the duplicate-version-conflict rule picks whichever
   source is encountered first in a fixed order (`root.json`, then `roots/` ascending), not
   by any notion of "more authoritative" — this is a reasonable, deterministic tie-break for
   an situation that should never arise from a correctly-built RPM, but a reviewer should
   confirm no legitimate packaging workflow could produce two different, both plausible,
   files for the same version.
4. **`establishTrustRoot`'s R4B-6 refusal stops the WHOLE walk, not just that step**
   (`agent/startup.go`): if version N+2 (not requiring mldsa-87) exists and would otherwise
   chain fine from N+1 (which does require it, and is refused), N+2 is never even attempted,
   since the walk never reaches it (it only ever tries `current.Version+1`). This is the
   conservative, fail-closed choice (never skip over a version whose own security posture
   this build couldn't evaluate), but a reviewer should confirm it matches the intended
   operational story for a hybrid rotation rollout that includes an intermediate,
   hybrid-only version.
5. **The E7 integration test's `store.RecordEpoch` call substituting for relayd `main()`'s
   not-yet-built orchestration** (`agent/integration_test.go`): this is explicit and
   documented (section 8/9), but a reviewer should confirm this is an acceptable way to get
   real integration evidence for the epoch-replay path ahead of step 6, versus deferring
   this specific piece of E7 until that wiring exists for real.

## 11. R4B items: commit, tests, verification

| Item | Commit SHA | Tests | Verified by |
| --- | --- | --- | --- |
| R4B-3 | `1e9db99` | `TestCheckOwnerAndMode_UnknownPlatformFailsClosed`, `TestCheckOwnerAndMode_UnknownPlatformStillChecksModeFirst` | `go test ./internal/store/...`; CI run 45508874566 |
| R4B-4 | `6ea6373` | `TestWriteBlobIfMissing_AlreadyPresentFsyncsAgain` | same |
| R4B-5 | `a81fe76` | `TestCommitLocked_CounterIncrementFailsAfterDurableWrite`, `TestApplyEngine_LKGStorePutErrorDoesNotRollBackTetragon` | same |
| R4B-1 | `e7dd96b` | `TestStartup_MultiVersionChain_*` (9 tests), `TestStartup_ForwardChain_AdoptsNewerRPMRoot`, `TestStartup_RPMRootMoreThanOneVersionAheadIsIgnored`, `TestStartup_IgnoresOlderOrEqualRPMRoot` | CI run 45508905904 |
| R4B-6 | `7785086` | `TestEstablishTrustRoot_RefusesToAdoptRootRequiringUnavailableMLDSA`, `TestStartupDegradedCondition_ReportsWhenPersistedRootRequiresUnavailableMLDSA` | CI run covering `6f88674` (45552424016; pushed together) |
| R4B-2 | `6f88674` (design: `049eaea`) | `TestParseBundleUnverified_*`, `TestRootHistory_RetainedWhileReferencedThenGarbageCollected`, `TestDomains_*`, `TestRootAtVersion_*`, `TestStartup_ReverifyLKG_*` (8), `TestApplyEngine_LKGStorePutErrorDoesNotRollBackTetragon` | CI run 45552424016; E7 integration run 45554200234 (real re-verification path) |
| Q3 | `9997e5c` | `TestStartup_PersistedRootWithValidHMACButFailingTrustVerificationIsTampered` | CI run 45552604383 |

## 12. E7 integration evidence

- **Run**: GitHub Actions run `45554200234` (commit `942eb89`, this step's final commit),
  job `integration`, step "Run integration test suite (unprivileged, build tag
  'integration')", against a real Tetragon v1.8.0 (the same release/hash-pinned instance
  `internal/tetra`'s and `internal/apply`'s own integration suites use, started earlier in
  the same job).
- **Scenario output** (from the job log):
  ```
  === RUN   TestIntegration_AgentRestartPersistsEpochAndLKG
  --- PASS: TestIntegration_AgentRestartPersistsEpochAndLKG (16.58s)
  ```
- The job's final cleanliness checks also passed, both mid-run (apply's own
  `TestZZZFinalCheck_NoTracingPoliciesLeftLoaded`, which runs after `internal/agent`'s new
  suite in the same step) and in the job's dedicated, separate final step:
  ```
  === RUN   TestZZZFinalCheck_NoTracingPoliciesLeftLoaded
  --- PASS: TestZZZFinalCheck_NoTracingPoliciesLeftLoaded (0.00s)
  ```
  confirming the new test's `t.Cleanup`-registered policy deletion (step-03a-review.md
  R3-E3 fix F1's contract, duplicated in `internal/agent/integration_test.go`'s own
  `dialIntegration`) actually ran and left Tetragon clean, and that the "final check stays
  last" requirement held for the whole job.
- Scenario covered end to end against the real daemon: bundle verified and applied
  (`StatusApplied`); epoch recorded; store closed and reopened via a fresh `agent.Startup`
  call with no RPM-shipped root configured (persisted-root path only); the persisted epoch
  (`1`) and LKG (`RawEnvelope`/`RootVersion` both non-zero and matching the original) both
  confirmed survived, with `Startup` itself performing ADR 0025's real re-verification
  along the way (a non-tampered record is required for `Startup` to succeed at all); a
  replay of the identical envelope at the identical epoch confirmed `CodeRejectedEpoch`;
  and Tetragon's own `ListTracingPolicies` result for the relay domain confirmed
  byte-for-byte (by name) unchanged across the simulated restart, since no RPC was made to
  Tetragon during it.
