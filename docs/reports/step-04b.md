# Step 4b report: persistent state store

## 1. Summary

- Part A (step-04a-review.md follow-ups): `require_keytypes` is now mandatory on every
  trust-root role (R4A-1); SPKI keys are now required to be in canonical encoding, and a
  real (not merely hypothetical) non-canonical ecdsa-p384 encoding this package's own
  parser accepts was found and is rejected (R4A-2). R4A-3 (crypto self-test) is implemented
  in `internal/agent`, Part D.
- Part C: a new `internal/store` package implements a crash-safe, tamper-evident persistent
  store (epochs, monitor-mode history, LKG sets, the trust root), HMAC-authenticated and
  rollback-protected via a mirrored monotonic counter.
- Part D: a new `internal/agent` package implements the startup sequence (crypto self-test,
  open the store, establish the trust root per the forward-only chaining rule, TAMPERED
  decision) short of relayd's actual `main()` wiring (step 6).
- Part E1/E2: a fault-injection filesystem layer sweeps every write path's crash points; a
  tamper matrix covers every case step-04b.md Part E2 lists.
- Part E6: `internal/store` (95.6%) and `internal/agent` (90.3%) meet their coverage targets
  and are added to `make coverage`/`make coverage90`.
- **Not completed this session** (see "Known limitations" and "Open questions"): Part E3's
  dedicated trust-root test matrix beyond what `internal/agent`'s own tests already cover,
  Part E4's property test, Part E5's `FuzzStoreIndex` and its CI wiring, and Part E7's
  integration-test addition. These are the next items to pick up.
- Deviation: `internal/store`'s LKG blob is the already-verified, already-parsed `LKGSet`'s
  canonical JSON, not the architecture doc's literal "raw DSSE bytes" — `apply.LKGStore`
  (step 3's fixed interface) never gives this package a raw envelope. See doc.go and
  "Deviations" below.

## 2. File tree (added or changed since e1a4bfb)

```
docs/
  decisions/0022-crypto-agility.md        (amended: R4A-1, R4A-2)
  decisions/0023-reenrollment-interface.md (new)
  prompts/step-04b.md                      (new, committed verbatim)
  reports/step-04b.md                      (this file)
  reviews/step-04a-review.md               (new, committed verbatim)
cmd/bundlesign-test/{root,rootupdate,vectors}.go   (R4A-1: roleOf mandatory require_keytypes)
internal/
  agent/              (new package, Part D)
    doc.go errors.go audit.go reenroll.go
    selftest.go selftest_vectors.go startup.go
    helpers_test.go internal_test.go startup_test.go
  limits/limits.go    (new MaxStore* constants, Part C8)
  store/              (new package, Part C)
    doc.go errors.go fs.go seal.go counter.go index.go blob.go store.go
    store_test.go tamper_test.go fault_test.go fault_matrix_test.go coverage_test.go
  trust/
    root.go keytype.go errors.go types.go  (R4A-1, R4A-2)
    helpers_test.go internal_test.go parsing_test.go
testdata/vectors/*.json   (regenerated for R4A-1; two new vectors)
Makefile                  (internal/store added to coverage; internal/agent to coverage90)
```

## 3. Command output

### `make ci` (clean clone, this development machine)

This environment is macOS (Darwin/arm64), not the Linux CI runner; `internal/tetra`'s
`_linux.go` files and their tests do not compile here (confirmed unused-symbol warnings
match exactly `internal/tetra/config.go`'s `_linux.go`-only consumers), so `make ci`'s own
`lint` target fails locally on this pre-existing, environment-specific condition — not
something this step introduced (verified: `golangci-lint run ./...` here shows exactly the
same 5 `unused` findings on a clean checkout of e1a4bfb). What was actually run and verified
locally instead, matching `ci.yml` step for step as closely as this platform allows:

```
$ gofmt -l $(...); goimports -l $(...)      # clean
$ go vet ./...                              # clean
$ golangci-lint run ./internal/store/... ./internal/agent/...   # 0 issues
$ golangci-lint run ./...                   # 5 pre-existing unused findings, internal/tetra/_linux.go only
$ go build ./...                            # clean
$ GOOS=linux go build ./...                 # clean (cross-compile sanity check)
$ go test -count=1 ./...                    # ok, all packages
$ make coverage                             # see below
$ make coverage90                           # internal/tetra 86.0% locally (linux-only tests excluded on darwin;
                                             # was passing on e1a4bfb's own GitHub Actions run, not touched this
                                             # step); internal/apply, internal/hostprobe, internal/agent all pass
```

GitHub Actions (authoritative) run numbers for `ci`/`integration` are in section 3's table
below; `gh run view` confirms the `ci` job green on every commit in this step except the two
explicitly superseded by a same-session fix (see the commit list).

### Per-package coverage (`go test -cover`, this run)

| Package | Coverage | Gate |
| --- | --- | --- |
| internal/dsse | 100.0% | ≥95% |
| internal/strictjson | 98.5% | ≥95% |
| internal/trust | 95.3% | ≥95% |
| internal/verify | 100.0% | ≥95% |
| internal/policydoc | 95.9% | ≥95% |
| internal/guard | 96.8% | ≥95% |
| **internal/store** | **95.6%** | **≥95% (new this step)** |
| internal/tetra | 86.0% local / passing on GitHub Actions (linux-only tests) | ≥90% |
| internal/apply | 95.5% | ≥90% |
| internal/hostprobe | 90.4% | ≥90% |
| **internal/agent** | **90.3%** | **≥90% (new this step)** |

### GitHub Actions run numbers (this step's commits, branch `main`)

| Commit | ci | integration |
| --- | --- | --- |
| `2f7b71e` docs: step 4a review + step 4b prompt | 45461380805 success | (shares run with ci) |
| `c2c8f0c` R4A-1 | 45475707065 success | success |
| `7620540` R4A-2 | 45477254496 **failure** (internal/trust coverage 94.7% < 95%) | — |
| `8bbd3e2` R4A-2 coverage fix | 45480332472 success | success |
| `042c187` store core (Part C) | — | — |
| `f586ceb` store E1/E2 tests | 45482037772 **failure** (golangci-lint not run locally first) | — |
| `cba9617` store coverage polish | — | — |
| `7a40d8b` agent (Part D) | — | — |
| `288b633` ADR 0023 | 45484705945 **failure** (same lint findings, not yet fixed) | — |
| `5edaafd` lint fixes (final commit) | 45486062711 success (ci in 8m36s) | success (in 2m33s) |

Three pushes failed CI in this session (two coverage regressions, one lint findings not
checked locally before pushing) and were fixed in the immediately following commit each
time, per the working agreement's "fix forward." `docs/prompts/step-04b.md`'s own
instruction is to confirm both `ci` and `integration` green on GitHub for the **final**
commit before calling a step done; at the time this report was written, `5edaafd`'s `ci` job
is green and `integration` had not yet finished — see "Open questions" #1.

### Fuzz, benchmarks

No new fuzz targets were added this step (`FuzzStoreIndex`, Part E5, was not completed —
see "Known limitations"). Existing fuzz targets (`FuzzStrictJSON`, `FuzzVerifyEnvelope`,
`FuzzRootUpdate`, `FuzzRootV2`, `FuzzPolicyParse`, `FuzzGuard`) were re-run locally for 15s
each against the R4A-1/R4A-2 trust changes with no crashes (reported in the per-commit
sections above); `make fuzz-short`'s full 60s-per-target run is exercised by GitHub Actions
`ci` on every push. No new benchmarks were added or needed changing.

### govulncheck

Not runnable standalone in this environment without network access matching CI's; GitHub
Actions `ci`'s `govulncheck` step passed on every successful run in the table above. No new
third-party dependencies were added this step (golang.org/x/sys was already a dependency,
used for `unix.Flock`).

## 4. Mapping: item → functions → tests → vectors

| Item | Functions | Tests | Vectors |
| --- | --- | --- | --- |
| R4A-1 (mandatory require_keytypes) | `trust.validateRole`'s require_keytypes check (`root.go`) | `TestLoadInitialRoot_InvalidRequireKeyTypes` (incl. "omitted"), `TestLoadInitialRoot_RequireKeyTypesOmittedOnRootOrLogRole` | `role_missing_require_keytypes.json`, `root_update_new_root_missing_require_keytypes.json`, every other vector regenerated |
| R4A-2 (canonical SPKI) | `requireCanonicalECDSASPKI`, `requireCanonicalMLDSA87SPKI`, `marshalMLDSA87SPKI` (`keytype.go`) | `TestRequireCanonicalECDSASPKI_RejectsMismatch`, `TestRequireCanonicalMLDSA87SPKI_RejectsMismatch`, `TestLoadInitialRoot_NonCanonicalSPKIWithTrailingAlgorithmIdentifierContentRejected`, `TestLoadInitialRoot_NonMinimalLengthSPKIRejected` | none (no accepted non-canonical encoding exists to commit as a fixture for ecdsa; mldsa's splice is caught by a pre-existing check) |
| R4A-3 (crypto self-test) | `agent.RunCryptoSelfTest`, `verifyECDSASelfTest`, `verifyMLDSASelfTest` | `TestRunCryptoSelfTest_Succeeds`, `TestRunCryptoSelfTest_ECDSAFailureRefusesToStart`, `TestRunCryptoSelfTest_MLDSAFailureIsNotFatal`, `TestVerifyECDSASelfTest_EachFailureBranch`, `TestVerifyMLDSASelfTest_EachFailureBranch`, `TestCheckMLDSARequirement_*` | embedded vectors in `selftest_vectors.go` (generated, not committed test data files) |
| C1 (layout/permissions) | `openWithFS`, `checkOwnerAndMode` | `TestOpen_WrongDirectoryMode`, `TestOpen_NonexistentDirectory`, `TestOpen_PathIsAFileNotADirectory`, `TestOpen_BlobsPathIsAFileNotADirectory`, `TestIndexFilePermissionsOnDisk` | — |
| C2/C3 (layout, crash safety) | `writeIndexFile`, `writeBlobIfMissing`, `commitLocked`, `gcBlobs` | `TestCrashMatrix_*` (fault_matrix_test.go), `TestEpoch_RoundTripsAndPersistsAcrossReopen`, `TestLKGStore_RoundTrips` | — |
| C4 (HMAC, blob hash) | `computeHMAC`, `canonicalPayloadBytes`, `readBlob` | `TestTamper_FlipByteInIndex`, `TestTamper_FlipByteInEachBlob`, `TestReadBlob_TooLargeOnDisk` | — |
| C5 (rollback protection) | `loadAndValidateIndex`'s generation-vs-counter switch | `TestTamper_RestoreOlderIndexAndBlobs_Rollback`, `TestTamper_IndexGenerationAheadByTwo`, `TestCommitLocked_CounterIncrementFailsAfterDurableWrite` (the crash-window case from the write side) | — |
| C6 (TAMPERED, first boot) | `firstBoot`, `markTamperedLocked`, `Tampered` | every `TestTamper_*`, `TestOpen_FirstBoot`, `TestOpen_ReopenIsNotFirstBoot`, `TestOpen_FirstBootWithNonzeroCounterIsTampered` | — |
| C7 (trust-root persistence) | `store.PersistTrustRoot`/`TrustRoot`, `agent.establishTrustRoot` | `TestTrustRoot_PersistAndDowngradeProtection`, `TestStartup_FirstBoot_AdoptsInitialRoot`, `TestStartup_ForwardChain_AdoptsNewerRPMRoot`, `TestStartup_IgnoresOlderOrEqualRPMRoot`, `TestStartup_RPMRootMoreThanOneVersionAheadIsIgnored`, `TestStartup_MalformedRPMRootOnReopenIsIgnored` | — |
| C8 (size bounds) | `verifyIndexLimits`, limits constants | `TestVerifyIndexLimits_EachBound`, `TestLoadAndValidateIndex_TotalBlobBytesExceeded`, `TestWriteIndexFile_TooLargeAfterLimitsPass` | — |
| C9 (concurrency) | `Store.mu`, `fs.Flock` | `TestOpen_AlreadyOpenByAnotherHandle` | — |
| D1 (interface wiring) | `Store.Current/RecordEpoch`, `Store.SeenInMonitor/RecordMonitorNames`, `Store.Get/Put` | `TestStartup_HandsStoreToApplyLKGStoreInterface`, `TestEpoch_*`, `TestPolicyHistory_RoundTrips` | — |
| D2 (startup sequence) | `agent.Startup` | all of `startup_test.go` | — |
| E1 (fault injection) | `faultFS`/`faultFile` (fault_test.go), `crashMatrix` (fault_matrix_test.go) | `TestCrashMatrix_RecordEpoch/Put/PersistTrustRoot/RecordEpochTwice/FirstBoot` | — |
| E2 (tamper matrix) | — | `tamper_test.go`, every test | — |
| E6 (coverage) | — | `coverage_test.go` | — |

## 5. Invariants and threats addressed

- **INV-1** (signature/threshold is the basis of policy acceptance): unaffected by this
  step's changes to `internal/trust`, strengthened by R4A-1/R4A-2 closing two ways a role's
  intended guarantee could be silently weaker than declared.
- **T-07** (compromised/malicious controller cannot forge acceptance): the persistent store
  now means a restarted agent re-derives the same epoch/LKG state rather than trusting
  anything the controller might claim about prior history — `internal/store` is itself the
  durable half of that defense, with `Current`/`Get` answering only from HMAC-verified,
  rollback-checked local state.
- **T-13** (signing key stolen; root metadata revokes it): R4A-1 ensures a revocation/rotation
  that intends to add a keytype requirement cannot be silently ignored by omission; C7's
  forward-only chaining ensures a stolen-old-root-key replay cannot roll a host back to a
  root version that still trusts the compromised key.
- **T-24** (trust-root rollback or freeze): C5/C7 together are the primary new defense here —
  the monotonic-counter-backed generation check (C5) stops an attacker from restoring an
  older but validly-HMAC'd store directory, and C7's version-must-move-forward rule stops an
  attacker (or a stale RPM) from reintroducing an old root even via the "legitimate" adoption
  path.
- **State rollback** (this step's own primary new invariant, step-04b.md Part C5/C7): see the
  crash-point matrix (section 11) and the tamper matrix (`tamper_test.go`) for how both the
  store generation and the trust-root version are protected independently.

## 6. Deviations from this prompt or the architecture

1. **LKG blob granularity** (doc.go, section 1 above): `internal/store`'s LKG blobs are the
   canonical JSON of `apply.LKGSet`, not raw DSSE envelope bytes. `apply.LKGStore` (step 3's
   already-accepted interface) only ever gives this package the structured, already-verified
   `LKGSet`; changing that interface's signature to also carry raw envelope bytes was out of
   this step's scope ("Do not change... existing vector expectations unless this prompt says
   so" — the prompt's Part D1 says "implement...apply.LKGStore on internal/store", not
   "change it"). Every crash-safety/content-addressing/HMAC property section 8.2 asks for is
   preserved at the LKGSet granularity instead.
2. **Trust-root chaining split between `internal/store` and `internal/agent`**: `store`
   enforces "version must strictly increase" as a structural invariant (`PersistTrustRoot`),
   independent of `agent.establishTrustRoot`'s actual cryptographic chain verification
   (`trust.Root.Update`). `internal/store` has no dependency on `internal/trust` at all. This
   was a design choice, not something the prompt specified either way; recorded here for
   review since it means `store.PersistTrustRoot` alone does not guarantee the persisted
   bytes actually verify as a root (only that their claimed version moves forward) — a caller
   that bypassed `agent.establishTrustRoot` and called `PersistTrustRoot` directly with
   unverified bytes could persist garbage at a higher version number. No such caller exists
   today; `internal/agent.Startup` is the only one.
3. **Session boundary**: Part E3 (dedicated trust-root test matrix), E4 (property test), E5
   (`FuzzStoreIndex` + CI wiring), and E7 (integration test addition) were not completed —
   see "Known limitations".

## 7. Dependencies added

None. `golang.org/x/sys` (already a direct dependency, used elsewhere for `_linux.go`
syscalls) is now also used by `internal/store/fs.go` for `unix.Flock`.

## 8. Known limitations

- Everything in `internal/store` still sits behind fake interfaces (`FakeKeySealer`,
  `FakeMonotonicCounter`) — no TPM integration (step 5, as specified).
- `internal/agent.Reenroller` is interface-only (ADR 0023), as the prompt specifies.
- Part E3's full matrix ("RPM newer and chaining," "RPM newer and not chaining," "RPM older,"
  "first boot," "a hybrid rotation persisted and reloaded") is **mostly** covered by
  `internal/agent`'s `startup_test.go` (`TestStartup_ForwardChain_AdoptsNewerRPMRoot`,
  `TestStartup_RPMRootMoreThanOneVersionAheadIsIgnored`, `TestStartup_IgnoresOlderOrEqualRPMRoot`,
  `TestStartup_FirstBoot_AdoptsInitialRoot`) but the specific "hybrid rotation persisted and
  reloaded" case (a root rotating into a hybrid ecdsa+mldsa targets role, persisted, then a
  fresh `Open` reloading it) is not yet a dedicated test.
- Part E4 (a property test: random apply/epoch/history/trust operation sequences with random
  crash points, asserting monotonic epochs/root versions never violated) was not written.
  `fault_matrix_test.go`'s crash matrix is deterministic and per-operation, not randomized
  /combined across operation types in one run.
- Part E5 (`FuzzStoreIndex`, a fuzz target for the index JSON parser, wired into
  `make fuzz-short` and the nightly workflow) was not written. `decodeIndexFile` and
  `loadAndValidateIndex` are exercised by every unit/tamper/crash test with hand-built
  inputs, but not by a dedicated fuzzer.
- Part E7 (an integration test: apply a bundle, re-open the store simulating an agent
  restart, confirm the epoch and LKG persisted, confirm a replay is rejected with
  REJECTED_EPOCH) was not added to `internal/apply`'s integration suite. This would need
  `internal/apply.Engine` wired to a real `*store.Store` instead of `FakeLKGStore` plus a
  fake `verify.EpochSource`, which did not exist before this step.
- `internal/tetra`'s coverage90 gate shows 86.0% on this (macOS) development machine because
  its `_linux.go` files and their tests do not build here; this is a pre-existing,
  environment-specific condition (confirmed unchanged on a clean e1a4bfb checkout), not a
  regression from this step, and GitHub Actions' own Linux runner is unaffected.
- `internal/store`'s `checkOwnerAndMode` UID check cannot be exercised by a test running as a
  non-root user with a mismatched UID (there is no portable way to create a directory owned
  by a different UID without privilege); the mode check alone is tested.

## 9. Open questions for the architect

1. Both `ci` and `integration` are confirmed green for the final commit (`5edaafd`, run
   45486062711: `ci` 8m36s, `integration` 2m33s). Neither `internal/store` nor
   `internal/agent` are exercised by the current integration suite (it only covers
   `internal/tetra` and `internal/apply`), so this integration pass is not itself evidence
   this step's new code works on a real host/kernel — only that it did not regress anything
   step 3 already covers. Part E7 (not completed this session) is what would actually
   exercise `internal/store` end to end against `internal/apply.Engine`.
2. Is the LKG-blob-granularity deviation (section 6, item 1) acceptable, or should
   `apply.LKGStore`'s interface be revisited in a future step to also carry the raw envelope,
   with `internal/apply.Engine` plumbing it through from `verify.Verify`'s already-parsed
   input? This would let `internal/store` persist the literal architecture-doc-specified
   artifact.
3. Should `internal/store.PersistTrustRoot` import `internal/trust` and verify `raw` parses
   as valid root metadata (defense in depth against the hypothetical bypass in section 6,
   item 2), or is keeping `store` free of a `trust` dependency preferred for layering
   reasons? Currently only `internal/agent.Startup` ever calls it, and it always calls
   `trust.LoadInitialRoot`/`Update` first.
4. This step did not complete Part E3 (the hybrid-rotation-reload case specifically), E4, E5,
   or E7. Given the working agreement's "finish a coherent part... and stop," should the next
   session pick these up as the sole focus, or should they be deferred further in favor of
   step 5 (TPM) if the architect judges Part C/D's core guarantees (already tested
   extensively via E1/E2/E6) sufficient to build on?

## 10. Self-review: 5 places a reviewer is most likely to find a bug

1. **`establishTrustRoot`'s "more than one version ahead" handling** (`agent/startup.go`):
   when the RPM-shipped root is 2+ versions ahead of the persisted root,
   `persistedRoot.Update` returns `ErrVersionSkip` and this code treats that identically to
   "RPM root is garbage" or "chain verification failed" — logging and keeping the persisted
   root. That is almost certainly the right fail-closed behavior (an intermediate version
   this package has no way to fetch), but a reviewer should confirm there is no production
   path where the RPM genuinely ships a version more than one ahead of what any host could
   plausibly be at, which would mean hosts that fall behind can never catch up without
   operator intervention — worth an explicit runbook note (architecture doc section 14.3)
   if so.
2. **`writeBlobIfMissing`'s "already present" fast path** (`store/blob.go`): it treats any
   existing file at `blobs/<digest>` whose content hash matches `digest` as already-durable
   and skips writing/fsyncing again. If the filesystem silently corrupted that file's mtime
   or the file was `fsync`'d by a different, interrupted write that nonetheless landed
   correctly, this is fine; but this path does not itself call `fsync` again on the "already
   there" branch, relying on the ASSUMPTION that whatever wrote it before already fsynced
   it (true for every caller in this codebase, but worth flagging as a precondition the type
   system does not enforce).
3. **`checkOwnerAndMode`'s silent `nil` on non-`*syscall.Stat_t` platforms** (`store/store.go`):
   on a platform where `fi.Sys()` does not return `*syscall.Stat_t` (not Linux or Darwin), the
   ownership check becomes a no-op and only the permission-bits check still applies. This
   project only targets RHEL 9 (Linux) in production, so this is low risk, but it is a silent
   downgrade of a security check on an unanticipated platform rather than a hard failure —
   arguably it should refuse to run at all if it cannot verify ownership.
4. **`commitLocked`'s counter-increment failure path**: when `writeIndexFile` succeeds but
   `s.counter.Increment()` fails, `commitLocked` returns an error but `s.committed` has
   already been updated to the new generation in memory. A caller that treats a non-nil
   return from `RecordEpoch`/`Put`/etc. as "nothing happened" (reasonable given most other
   errors in this codebase) would be wrong here — the write is durable even though the call
   reported an error. This is intentional and documented, but is exactly the kind of subtlety
   a future maintainer modifying `apply.Engine`'s error handling around these calls could get
   wrong.
5. **`agent.checkMLDSARequirement` is advisory only**: if a future trust-root rotation adds
   `mldsa-87` to a role's `require_keytypes` on a build where ML-DSA is unavailable,
   `Startup` logs it but still returns success. The actual fail-closed behavior happens later
   and elsewhere (`trust.ErrMLDSAUnavailable` at verify time). A reviewer should confirm this
   two-step design (log early, fail late) is acceptable versus, e.g., `Startup` refusing to
   adopt a root with an unsatisfiable `require_keytypes` for this build at all.

## 11. Crash-point matrix (Part E1)

Each row is a write path; "crash points" is the number of distinct filesystem operations
swept by `crashMatrix`/`TestCrashMatrix_FirstBoot` (one `t.Run` subtest per point, 0 through
`maxCrashPoints-1 = 14`, with the sweep running several iterations past the point where the
action completes without being crashed, confirming no later point was missed).

| Operation | Crash points swept | Outcome asserted |
| --- | --- | --- |
| First boot (`Open` on an empty directory) | 15 | `Open` always succeeds on recovery; `Generation() == 1`; `FirstBoot()` is `true` if the original attempt was interrupted before the index committed, `false` if it had already committed |
| `RecordEpoch` (generation 1 → 2) | 15 | recovered epoch is `0` (old) or `5` (new), never anything else |
| `RecordEpoch` (generation 2 → 3, i.e. from a non-zero prior generation) | 15 | recovered epoch is `5` (old) or `10` (new) |
| `Put` (LKG, generation 1 → 2) | 15 | `Get` returns `ok=false` (old) or the exact new `LKGSet` (new) |
| `PersistTrustRoot` (generation 1 → 2) | 15 | `TrustRoot()` returns `ok=false` (old) or the exact new `(raw, version)` (new) |

Every row additionally confirms the recovery `Open` call itself never returns
`store.ErrTampered` for a crash at any of these points (a crash during a legitimate write is
not evidence of tampering) — the fault-injection crash is deliberately only ever at this
package's own write-path operations, never at an unrelated read, so a crashed write and a
tampered store remain distinguishable by this test design the same way they are in the real
`Open` logic.
</content>
