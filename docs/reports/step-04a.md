# Step 4a report: review follow-ups + crypto-agile trust formats (ML-DSA-87)

Commits: `a62e1de`..`1f9b3ac` (docs review commit, A1-A4 fixes, go directive bump,
B1-B4 crypto-agile core, B6 hybrid vectors + FuzzRootV2). Final commit: `1f9b3ac`.

This report covers step 4a only (Part A review follow-ups and Part B crypto-agility),
per the scoping agreed at session start. Parts C, D and the remaining E items
(fault-injection store, agent startup sequence) are step 4b, not started here.

## 1. Summary

- **A1 (R3B-1) fixed**: `internal/tetra.Config.SELinuxRequired` (zero value = fail
  open) renamed/inverted to `AllowSELinuxDisabled` (zero value = fail closed). Added
  `HostSELinuxMode`: when host facts positively assert SELinux enforcing/permissive, an
  AppArmor-style bare `SO_PEERSEC` label is a hard failure regardless of
  `AllowSELinuxDisabled`.
- **A2 (R3B-2) fixed**: `internal/apply`'s health window now only treats a stream
  timeout as "the window's own deadline" when `limits.HealthWindowDeadlineTolerance`
  (2s) or less of the window remains; otherwise it fails with `reasonHealthNotServing`.
- **A3 (R3B-3) measured, closed**: re-ran E1 with per-trigger wall-clock + kernel-time
  correlation (throwaway PR #3, closed without merging). 99/99 triggers matched, first
  match 543µs after its own trigger. No enforcement gap; "delivery latency only"
  confirmed (see section 11).
- **A4 (R3B-4) fixed**: corrected ADR 0019's "never races" claim; added
  `TestPersistDir_RestartReadIsAlwaysSupersetOfOldOrNew`, which simulates a Tetragon
  restart's directory read at every step of `PersistDir`'s sequence.
- **Part B**: root metadata keys are now typed (`ecdsa-p384` | `mldsa-87`);
  `internal/dsse.VerifyMLDSA87` verifies pure ML-DSA-87 signatures; `Role.RequireKeyTypes`
  adds a per-role algorithm requirement; `internal/limits.MaxRootMetadataBytes` raised to
  256 KiB; production roles still require `ecdsa-p384` only; every vector regenerated,
  9 new hybrid vectors added; `FuzzRootV2` added. Full design in ADR 0022.
- `go.mod`'s `go` directive bumped to 1.27.0 for `crypto/mldsa` (ADR 0021), in its own
  commit.
- Coverage: `internal/dsse` 100.0%, `internal/trust` 96.3%, `internal/verify` 100.0%
  (all ≥ 95% gate).
- `ci` and `integration` are green on GitHub for the final commit (run `45458928974`).

## 2. File tree of what was added or changed

```
docs/decisions/0019-persistdir-non-atomic-update.md   (amended)
docs/decisions/0002-root-metadata-size-cap.md         (amended, B4 arithmetic)
docs/decisions/0021-go-1.27-mldsa-toolchain-bump.md   (new)
docs/decisions/0022-crypto-agility.md                 (new)
docs/reviews/step-03b-review.md                       (new, committed verbatim)
docs/reports/step-04a.md                              (this file)
go.mod                                                (go 1.27.0)
.github/workflows/nightly-fuzz.yml                    (+FuzzRootV2)
Makefile                                              (+FuzzRootV2 in fuzz-short)
internal/tetra/config.go, dial_linux.go               (A1)
internal/tetra/dial_linux_test.go                     (A1 tests)
internal/apply/health.go                              (A2)
internal/apply/health_test.go                         (A2 tests)
internal/apply/persist.go                             (A4 doc fix)
internal/apply/persist_test.go                        (A4 test)
internal/apply/integration_test.go                    (AllowSELinuxDisabled wiring)
internal/limits/limits.go                             (HealthWindowDeadlineTolerance, MaxRootMetadataBytes)
internal/trust/types.go                               (KeyType, Role.RequireKeyTypes, Root.keys type)
internal/trust/keytype.go                             (new: TrustedKey, SPKI OID parsing/dispatch)
internal/trust/keyid.go                               (DeriveKeyIDFromDER)
internal/trust/errors.go                              (new typed errors)
internal/trust/root.go                                (parse/validate/verify rewrite for B1-B3)
internal/trust/{internal,parsing,trust,fuzz,fuzz_helpers,helpers,vectors}_test.go  (updated)
internal/trust/keytype_internal_test.go               (new)
internal/dsse/mldsa.go                                (new: VerifyMLDSA87)
internal/dsse/mldsa_test.go                            (new)
internal/verify/{bench,helpers}_test.go               (B4 ML-DSA-87 benchmark)
cmd/bundlesign-test/keys.go                           (ML-DSA-87 test keys)
cmd/bundlesign-test/root.go                           (RequireKeyTypes wire field)
cmd/bundlesign-test/hybrid.go                         (new: hybrid root + B6 vectors)
cmd/bundlesign-test/vectors.go                        (trustErrorsByName, accept-case Update)
testdata/vectors/*.json                               (all regenerated; 9 new hybrid vectors)
testdata/vectors/README.md                            (regenerated)
```

## 3. Command output

### `make ci` (local, darwin/arm64 — linux-only paths verified on GitHub Actions)

Local `make lint` hits expected linux-only false positives (`internal/tetra` helpers
used only from `dial_linux.go`/`peercgroup_linux.go`, build-constrained to linux; this
matches step-03's documented darwin-development pattern). Everything else run locally:

```
go build ./...        -> clean
go vet ./...           -> clean
go test -count=1 ./... -> ok, all packages
govulncheck ./...      -> No vulnerabilities found
go mod verify           -> all modules verified
go mod vendor           -> no diff
gofmt -l / goimports -l -> clean
golangci-lint run ./... -> clean except the known darwin-only internal/tetra "unused" false positives
```

### Per-package coverage (`go test -covermode=count`)

| Package | Coverage | Gate |
| --- | --- | --- |
| internal/dsse | 100.0% | 95% |
| internal/trust | 96.3% | 95% |
| internal/verify | 100.0% | 95% |

### Fuzz exec counts (GitHub Actions run `45458928974`, `make fuzz-short`, 60s/target)

| Target | Execs | New interesting | Crashes |
| --- | --- | --- | --- |
| FuzzRootUpdate | 911,270 | 99 | 0 |
| FuzzRootV2 | 291,436 | 11 | 0 |

(FuzzStrictJSON/FuzzVerifyEnvelope/FuzzPolicyParse/FuzzGuard also ran, unaffected by
this step, all 0 crashes — see the same run.)

### Benchmarks (B4 requirement: ML-DSA-87 worst case < 50ms)

```
TestVerify_WorstCaseMLDSAPerformance: best of 7 runs took 8.625041ms (budget 50ms)
```
(16 ML-DSA-87 signatures, 64 policies — the same worst-case shape as the existing
`TestVerify_WorstCasePerformance` ECDSA benchmark, run on this development machine;
re-verified green in the GitHub Actions `Test with race detector and coverage` step.)

### GitHub Actions, final commit `1f9b3ac`

- `ci` run **45458928974**: **success** (8m32s)
- `integration` run **45458928974** (same workflow run): **success** (2m31s)

## 4. Mapping: each item → functions → tests → vectors

| Item | Functions | Tests | Vectors |
| --- | --- | --- | --- |
| A1 | `tetra.Config.AllowSELinuxDisabled/HostSELinuxMode`, `verifySELinuxLabel`, `verifyPeerSELinux` | `TestVerifySELinuxLabel`, `TestVerifyPeerSELinux` (zero-value-refuses, host-facts-enforcing cases) | n/a |
| A2 | `withinHealthWindowDeadlineTolerance`, `runHealthWindow` | `TestRunHealthWindow_ErrTimeout{Near,WellBefore}Deadline_*`, `TestRunHealthWindow_EventsClosedPendingTimeout*` | n/a |
| A3 | (measurement only) | throwaway `TestDiagnoseA3_E1_PerTriggerGap` (deleted with the branch) | n/a |
| A4 | `PersistDir` (doc only) | `TestPersistDir_RestartReadIsAlwaysSupersetOfOldOrNew` | n/a |
| B1 | `TrustedKey`, `parseSPKIAlgorithm`, `parseTrustedKey`, `DeriveKeyIDFromDER` | `TestParseSPKIAlgorithm_Errors`, `TestParseTrustedKey_*`, `TestLoadInitialRoot_UnknownKeyType`, `TestLoadInitialRoot_DeclaredKeyTypeDoesNotMatchSPKI` | `mldsa_keytype_spki_mismatch`, `unknown_keytype_rejected`, `non_p384_key` |
| B2 | `dsse.VerifyMLDSA87`, `TrustedKey.verifySignature` | `internal/dsse/mldsa_test.go` (valid/wrong-message/wrong-key/unavailable/External-mu) | `hybrid_role_satisfied`, `*_attributed_to_*_keyid` |
| B3 | `Role.RequireKeyTypes`, `verifyRoleThreshold`, `(*Root).Update` | `TestVerifyRoleThreshold_RequireKeyTypesNotSatisfied`, `TestLoadInitialRoot_InvalidRequireKeyTypes` | `hybrid_role_only_{ecdsa,mldsa}_signature`, `root_update_ecdsa_to_hybrid_accept`, `root_update_only_new_hybrid_keys_reject` |
| B4 | `limits.MaxRootMetadataBytes` | `TestVerify_WorstCaseMLDSAPerformance`, `BenchmarkVerify_WorstCaseMLDSA` | n/a (ADR 0002 arithmetic) |
| B5 | (no code; production generator unchanged) | n/a | all non-hybrid vectors (`ecdsa-p384`-only roots) |
| B6 | (vectors + unit tests per B2/B3 above) | see B1-B3 rows | 9 new vectors (listed in section 1) |
| B7 | (design only) | n/a | ADR 0022 |
| E5 | `FuzzRootV2`, `hybridRootSeeds` | n/a | seeded from all vectors + synthetic hybrid roots |
| E6 | n/a | coverage run (section 3) | n/a |

## 5. Invariants and threats addressed

- **INV-1** (no policy loaded without a valid signature chaining to the pinned root):
  unaffected in substance; crypto-agility only widens which algorithms a chain may use,
  never weakens the chain itself. `require_keytypes` makes INV-1 strictly stronger for
  any role that sets it (an additional algorithm-diversity requirement on top of the
  existing threshold).
- **T-07-class (signature confusion)**: B6's "signature attributed to the wrong keyid"
  vectors confirm dispatch is on the trusted KEY's own keytype, never anything the
  signature or envelope claims, closing any path where an attacker-controlled envelope
  could pick its own verification algorithm.
- **T-13-class (algorithm downgrade/confusion)**: HashML-DSA is structurally unreachable
  (ADR 0022); a role's `require_keytypes` cannot be satisfied by a weaker algorithm
  standing in for a required one (B3's distinct-per-type accounting).
- **T-24-class (fail-open on missing capability)**: ML-DSA unavailability fails closed
  (`ErrMLDSAUnavailable`), never silently skips the requiring role.
- **New rollback-adjacent threat (A4)**: a Tetragon restart racing `PersistDir` can no
  longer be argued safe on a false "never races" premise; the actual invariant (always a
  superset of the old or new on-disk set) is now stated and tested directly.

## 6. Deviations from this prompt or the architecture

- B6's "HashML-DSA signature (reject)" and "ML-DSA unavailable (fail closed)" scenarios
  are direct Go unit tests, not `testdata/vectors` JSON fixtures: `crypto/mldsa.Verify`
  has no HashML-DSA code path to accidentally invoke in the first place (confirmed by
  reading its source, not merely testing one input), and this development environment
  is not built against the FIPS 140-3 Go Cryptographic Module v1.0.0, so a real
  "unavailable" build cannot be produced here. The unavailable-path test exercises the
  identical `mldsa.NewPublicKey` failure branch via a malformed key instead, which ADR
  0022 documents as code-path-identical.
- The root ROLE itself (as opposed to the targets role) is never made hybrid in any
  committed vector; B5 and the hybrid rotation vectors treat "hybrid" as a targets-role
  concern. Root-role hybrid rotation is mechanically identical code (B3 applies to every
  role uniformly) but was not separately vectorized, to bound scope.
- Commit sizes exceed the ~400-line guidance for the two Part B commits (1403 and 776
  lines): the format change, its verifier, and its required vector regeneration are a
  single cohesive, tightly-coupled unit that cannot be split further without leaving an
  intermediate commit non-compiling or non-self-checking.

## 7. Dependencies added

None (third-party). `crypto/mldsa` is standard library, new in Go 1.27 (ADR 0021, the
`go` directive bump commit).

## 8. Known limitations and everything still behind fake interfaces

- Everything from step 3 remains unchanged in this regard (`verify.EpochSource`,
  `guard.PolicyHistory`, `apply.LKGStore` are still in-memory fakes — step 4b/Part C).
- ML-DSA-87 verification is complete and tested but not reachable in production (B5);
  the first real-world exercise of that code path will be whenever an operator issues a
  hybrid trust-root update.
- `scripts/e2e-rhel9.sh` (R3B-5, ship-blocking per the architect review) still has not
  been run on a real RHEL 9 host; unaffected by this step's changes but still open.

## 9. Open questions for the architect

1. Should the root ROLE itself ever be made hybrid-capable in a committed vector (not
   just the targets role), or is "root role stays `ecdsa-p384`-only, forever, by
   operational policy" an acceptable permanent constraint worth stating explicitly in
   the architecture doc?
2. ADR 0019's status is still "Proposed" even after this step's correction — should it
   move to "Accepted" now, or does the correction itself need a separate review pass
   first?
3. B4's 256 KiB `MaxRootMetadataBytes` headroom (~75% over the computed worst case) —
   is that the right margin, or should it be tied more precisely to a maximum key/role
   count the architecture doc states explicitly (today it states none)?

## 10. Self-review: 5 places a reviewer is most likely to find a bug

1. **`parseTrustedKey`'s ECDSA curve-OID pre-check** (added only to resolve an `unused`
   lint finding on `oidNamedCurveP384`): it duplicates a check `x509.ParsePKIXPublicKey`
   plus the `elliptic.P384()` comparison already performs. If the two checks ever
   disagree (e.g. a future Go release changes curve OID handling), the earlier one wins
   silently — worth a reviewer's second look at whether this duplication is actually
   buying anything beyond satisfying the linter.
2. **`verifyRoleThreshold`'s `firstErr` is the FIRST error only**, not every error
   encountered. If a role has multiple unavailable/malformed keys, only one is
   surfaced; a caller inspecting the error cannot tell how many keys were actually
   affected.
3. **`cloneKeyAsType`'s shallow copy** (`cmd/bundlesign-test/hybrid.go`): copies a
   `*testKey` by value including its private key pointers. If `testKey` ever gains a
   mutable field that needs independent state between the original and the clone, this
   would silently share it.
4. **The hybrid vectors' "mislabeled" signatures** (`mldsa_signature_attributed_to_ecdsa_keyid`
   etc.) rely on `ecdsa.VerifyASN1`/`mldsa.Verify` rejecting cross-algorithm garbage by
   construction (wrong length/encoding), not on an explicit type check before attempting
   verification. This is correct today but relies on the underlying crypto libraries
   continuing to reject malformed input safely rather than, say, panicking on a
   wrong-shaped byte slice — worth confirming `TrustedKey.verifySignature` can never
   panic on attacker-controlled signature bytes of arbitrary length (not explicitly
   fuzzed with a panic-recovery harness in this step, unlike `FuzzRootV2`'s
   LoadInitialRoot/Update panic check, which does cover this path incidentally).
5. **`parseAndValidatePayload`'s `require_keytypes` nil-vs-empty distinction** depends on
   `encoding/json`'s documented (but easy to get backwards) behavior that an absent
   field decodes to a nil slice while `[]` decodes to a non-nil empty slice. A future
   refactor that round-trips through a different JSON layer (e.g. a generic
   `map[string]interface{}` pass) could silently collapse this distinction.

## 11. A3 measurement table and conclusion

Throwaway PR #3 (`diagnose-a3-e1-remeasure`, closed without merging), run on GitHub
Actions `ubuntu-24.04`. `AddTracingPolicy` returned at elapsed 478.58ms; the trigger loop
started ~160ms later (the diagnostic's own 200ms subscription-settle sleep). Every one
of 99 triggers (one per ~100ms over 10s) had a matching kernel event:

| Trigger # | Elapsed since AddTracingPolicy | Kernel-to-trigger delta |
| --- | --- | --- |
| 0 | 638ms | 543µs |
| 1 | 740ms | 354µs |
| 5 | 1145ms | 289µs |
| 10 | 1651ms | 382µs |
| 20 | 2665ms | 393µs |
| 32 | 3881ms | 363µs |
| 98 (last) | — | ~350-600µs (consistent throughout) |

**Summary: 99/99 triggers matched, first match at trigger #0, 0 unmatched.** The
kernel-to-trigger delta stayed in a tight 290-600µs band for the entire 10s run, with no
early-trigger gap.

**Conclusion**: delivery latency only, no enforcement gap, confirming the original E1's
778ms "first event" figure (ADR 0020) was observation/delivery latency, not a period
where the new BPF program was not yet acting. No code or design change needed; this
closes R3B-3 per the "if every trigger has an event" branch of the review's own
instructions.

## 12. Crash-point matrix from E1

Not applicable to step 4a (Part E1's fault-injection filesystem layer is step 4b/Part C
scope, for the new `internal/store` package). `TestPersistDir_RestartReadIsAlwaysSupersetOfOldOrNew`
(A4, section 4) is a related but distinct crash-point test for the existing `PersistDir`
function; its matrix is: rename (each addition), removeAll (each stale removal), syncDir
(staging sync, final sync) — all confirmed superset-of-old-or-new at every point.

## 13. Size-limit arithmetic from B4

See `docs/decisions/0002-root-metadata-size-cap.md`'s amendment for the full table and
arithmetic. Summary: ML-DSA-87 SPKI DER ~2614 bytes (~3488 base64) vs. ECDSA P-384's
~120 bytes (~160 base64); ML-DSA-87 signature 4627 bytes (~6172 base64) vs. ECDSA's
≤104 bytes (~140 base64). Worst case (16 ML-DSA-87 signatures + an 18-key hybrid set
across three roles) ≈ 146 KiB; `MaxRootMetadataBytes` raised to 256 KiB (~75% headroom).
`MaxSignaturesPerEnvelope` unchanged at 16.
