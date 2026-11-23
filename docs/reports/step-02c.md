# Step 2c report: guardrail correctness fixes (architect review of fe11a62)

Repo: `github.com/bshlisky/tetragon-relay`, branch `main`. This report covers
`docs/reviews/step-02b-review.md`'s items C1-C7, one commit per item where
isolable. Facts below are generated from the repository and from a pinned
clone of `github.com/cilium/tetragon` at tag `v1.8.0` (commit
`a5a667837d4b1ecd9018797994bb4e39b98702e1`), not written from memory.

## 1. Summary

- **C1 [CRITICAL] fixed:** G1's negative-operator (`NotIn`/`NotPrefix`/
  `NotPostfix`) handling failed open. Root cause: the old `excludesAllBinaries`
  helper reused "could match" functions where an ambiguous value was
  treated as "matches," which is backwards for exclusion — an ambiguous
  `NotIn` value was trivially treated as "excludes everything." Replaced
  with a single reference-semantics function, `matches(operator, values,
  candidate)`, that directly implements Tetragon's own operator evaluation
  (cited file:line per operator) for both positive and negative forms, plus
  an explicit, separate "reject ambiguous values outright" check that no
  longer feeds into the matching logic at all.
- **C2 [HIGH] fixed:** G2 now treats `linux_binprm` and every string/
  byte-buffer-shaped `KProbeArg.Type` as path-typed (previously only `file`/
  `filename`/`path`), and implements the architect's exact directory-aware
  coverage formula, including "`Postfix` on a directory target always
  covers" (undecidable in general; fail closed).
- **C3 [HIGH] fixed:** G3's exec-hook identification is now
  identifier-substring based (`"exec"` or `"bprm"`, case-insensitive)
  across every hook kind, replacing a fixed kprobe/lsmhook-only list that
  missed any execve syscall/tracepoint/uprobe hook.
- **C4 resolved:** confirmed from the pinned source
  (`pkg/selectors/kernel.go:1287-1293`) that `linux_binprm` matchArgs
  values ARE compared as the binary's path string, the same code path as
  `file`/`path`/`string` types — G3 now counts `linux_binprm` matchArgs as
  valid path-typed scoping.
- **C5 added:** new rule G10 rejects `Override` on any hook kind other
  than kprobe/lsmhook (uprobes and tracepoints), since G8 has no capability
  detection for either and the CRD's own doc comment only lists uprobes as
  supporting a *different* override mechanism this project cannot verify.
- **C6 added:** two more protected binaries
  (`/usr/libexec/openssh/sshd-session`, `/usr/lib/systemd/systemd-logind`).
- **C7 resolved:** four open-question resolutions recorded in ADR 0015
  (UpdateState stays rejected, ADR 0013 approved for a future root-format
  change, hostSelector/nodeSelector stay rejected, step 3 must verify
  usrmerge symlinks at agent startup).
- A real gap found and fixed while implementing C1: four protected
  binaries under `/usr/bin/` (`tetra`, `tetragon`, `spire-agent`, `sudo`)
  were missing their `/bin/` usrmerge alias entries; a new test
  (`TestProtectedLists_BothUsrmergeSpellingsPresent`) now catches this
  class of omission automatically.
- 96.8% (`internal/guard`) / 96.0% (`internal/policydoc`, unchanged) / 100%
  (`internal/verify`, unchanged) coverage; `make ci` green locally; pushed
  and confirmed green on GitHub Actions (section 3).

## 2. File tree (changed; no new packages this pass)

```
docs/reviews/step-02b-review.md     (new)
docs/decisions/0014-g10-override-hook-placement.md        (new)
docs/decisions/0015-step-02b-open-question-resolutions.md (new)
docs/decisions/0013-g9-protected-set-extension-proposal.md (status updated)
docs/reports/step-02c.md            (this file)
internal/guard/
  paths.go       (rewritten: matches(), pathCoversPositive(), removed
                  coversEqual/coversPrefix/coversPostfix/excludesAllBinaries/
                  anyBinaryCovered/anyPathCovered/canonicalTargets)
  protected.go   (two new binaries; usrmergeAlias test helper replaces
                  canonicalizeUsrmerge; four missing /bin/ aliases added;
                  tetragon.sock dual-spelled)
  guard.go       (checkSelectorG1, checkSelectorG2, checkG3/isExecHook/
                  execSelectorScoped rewritten; new checkG10)
  errors.go      (RuleG10 added)
  crd_test.go, property_test.go     (new)
  unit_test.go, mutation_test.go, guard_test.go  (updated for new semantics
                  and extended per C1's test list)
internal/policydoc/convert.go       (pathArgTypes expanded per C2, with citations)
cmd/bundlesign-test/, testdata/vectors/  (regenerated; no new vectors needed
                  for this pass, self-check behavior unaffected)
```

## 3. Command output

### `make ci` (tail; full log ~420 lines, fuzz sections elided to start/end)

```
gofmt -l ...; test ! -s ...            -> clean
goimports -l ...; test ! -s ...        -> clean
go vet ./...                           -> clean
golangci-lint run ./...                -> 0 issues.
govulncheck ./...                      -> No vulnerabilities found.
go mod verify                          -> all modules verified
make vendor-check                      -> no diff
verify-crd OK: d99daa68c99faeab6a32ea843ab9a381ea2f63666b26e265bf048ac0ab617869
go test -race -count=1 -cover ./...
    internal/dsse        ok   100.0% of statements
    internal/guard       ok    96.8% of statements
    internal/policydoc   ok    96.0% of statements
    internal/strictjson  ok    98.5% of statements
    internal/trust       ok    97.9% of statements
    internal/verify      ok   100.0% of statements
make coverage (>= 95% gate, all six packages)      -> PASS
make fuzz-short (60s per target, 5 targets)        -> PASS, 0 crashes (FuzzGuard: 2,728,447 execs this run)
make proto (buf generate + diff)                   -> clean (no proto change this pass)
make breaking                                      -> clean
make verify-repro
    reproducible build OK: 6707db098bd45ed0cf33ac06dd8d10654fbdaca6b9502268787346e2d9ee1503
make sbom                                          -> dist/sbom.spdx.json generated
Exit code: 0
```

GitHub Actions `ci` run for the final commit of this pass: **run 45161381388
(success, 5m59s)**, recorded in section 3.1.

### 3.1 Final commit and CI run

Final commit for this step: `9be3a5d` ("Step 2c: guardrail correctness
fixes (architect review of fe11a62)"). GitHub Actions `ci` run:
**https://github.com/bshlisky/tetragon-relay/actions/runs/45161381388**,
status `success`, all 20 steps green (lint, govulncheck, vendor check,
race tests + per-package coverage gate, 60s fuzz smoke across all five
fuzz targets, reproducible build check, proto generate/diff/breaking,
SBOM).

### Per-package coverage (statement, plain `go test`, no `-race`)

| Package | Before (step 2b) | After (step 2c) | Required |
| --- | --- | --- | --- |
| internal/guard | 95.8% | 96.8% | ≥ 95% |
| internal/policydoc | 96.0% | 96.0% (unchanged logic, moved citation) | ≥ 95% |
| internal/verify | 100.0% | 100.0% (unchanged) | ≥ 95% |

## 4. Before/after table for every C1 probe

Every probe the architect reproduced against commit `fe11a62` (before this
pass) and its outcome after the fix:

| Probe | Before (fe11a62) | After (this pass) |
| --- | --- | --- |
| kprobe `security_file_open`, Sigkill, `matchBinaries NotIn [""]` | **ACCEPT (bug)** | `REJECTED_GUARDRAIL` (G1: empty value is unsafe) |
| ... `NotIn ["relative"]` | **ACCEPT (bug)** | `REJECTED_GUARDRAIL` (G1: relative value is unsafe) |
| ... `NotPrefix ["x"]` | **ACCEPT (bug)** | `REJECTED_GUARDRAIL` (G1: relative value is unsafe) |
| ... `NotPrefix` with "-x"-suffixed look-alikes of every protected binary | **ACCEPT (bug)** | `REJECTED_GUARDRAIL` (G1: none of the look-alikes actually prefixes the real protected binaries, so `matches()` still matches each real one) |
| `NotIn` missing exactly one protected binary (all 18, each checked individually) | not tested in step 2b | `REJECTED_GUARDRAIL` for every one (`TestMutation_NegativeOperatorsMissingEachProtectedBinary`) |
| `NotPostfix ["d"]` | not tested in step 2b | `REJECTED_GUARDRAIL` (several protected binaries — `init`, `tetra`, `tetragon`, `spire-agent`, `sudo` — do not end in "d") |
| `NotPostfix` with the computed set of every protected binary's actual final character | not tested in step 2b | **ACCEPT** (correctly computed to genuinely exclude all 18; `TestCheck_G1_NotPostfixCoveringAllLastCharacters`) |
| `NotPrefix ["/usr/"]` | not tested in step 2b | `REJECTED_GUARDRAIL` (excludes everything under `/usr/`, but not `/sbin/init`, a protected binary under a different top-level prefix) |

All eight reproductions (and the property test cross-checking `matches()`
against an independent reference implementation over 20,000 random
operator/value/candidate combinations, plus 5,000 trials cross-checking
`checkSelectorG1`'s decision against the brute-force "exists a protected
binary `matches()`" formula) now behave correctly.

## 5. Mapping: review item → function → tests

| Item | Function(s) | Tests |
| --- | --- | --- |
| C1 | `internal/guard/paths.go: matches, hasUnsafeValue, matchesAnyCandidate`; `guard.go: checkSelectorG1` | `TestCheck_G1` (11 cases), `TestCheck_G1_PostfixAndNotPostfix`, `TestCheck_G1_NotPostfixCoveringAllLastCharacters`, `TestMatches_NegativeOperatorsExcludeCorrectly`, `TestMutation_NegativeOperatorsMissingEachProtectedBinary` (54 mutants), `TestMutation_AmbiguousAndLookAlikeValues` (5 reproductions), `TestProperty_MatchesAgreesWithReference` (20,000 trials), `TestProperty_G1EqualsBruteForce` (5,000 trials), `TestCheckSelectorG1_UnrecognizedOperator`, `TestCRD_MatchBinariesMaxItemsOne`, `TestProtectedLists_BothUsrmergeSpellingsPresent` |
| C2 | `internal/policydoc/convert.go: pathArgTypes`; `internal/guard/paths.go: pathCoversPositive, anyPathCoveredPositive`; `guard.go: checkSelectorG2` | `TestCheck_G2` (5 cases, unchanged + still passing), `TestPathCoversPositive_PrefixNestedInsideProtectedDirectory`, `TestPathCoversPositive_PostfixAlwaysCoversDirectory`, `TestPathCoversPositive_ExactFileTarget`, `TestCheckSelectorG2_UnrecognizedOperator`, `TestG9_ExtraProtectedExtendsPaths` |
| C3 | `internal/guard/guard.go: isExecIdentifier, isExecHook` | `TestIsExecHook_AnyKindWithMatchingIdentifier` (9 cases: kprobe/lsmhook/tracepoint/uprobe, case-insensitivity, non-matching identifiers) |
| C4 | `internal/policydoc/convert.go: pathArgTypes` (linux_binprm included, cited) | `TestCheck_G3/notin_plus_positive_matchArgs_is_scoped` (now declares `type: linux_binprm`), new `notin_plus_positive_matchArgs_on_non_path_type_is_still_unscoped` case |
| C5 | `internal/guard/guard.go: checkG10` | `TestCheck_G10_OverrideOnUprobeRejected`, `TestCheck_G10_OverrideOnTracepointRejected`, `TestCheck_G10_ViaMatchReturnActions` |
| C6 | `internal/guard/protected.go: protectedBinaries` | `TestMutation_EveryProtectedBinaryAndPathIsCaught` (count increased to 29 binary mutants) |
| C7 | ADR 0015 (no code) | — |

## 6. Upstream corpus: changed verdicts (C2)

Re-running all 73 upstream policies through `Parse` + `Check` after C1-C6:
**exactly one verdict changed**, from `ACCEPT` to `REJECTED_GUARDRAIL`:

| File | Before (step 2b) | After (step 2c) | Why |
| --- | --- | --- | --- |
| `lsm_bprm_check.yaml` | ACCEPT | `REJECTED_GUARDRAIL` (G2: `matchArgs Postfix` on a `linux_binprm`-typed arg covers a protected path) | The policy's `Override` selector has `matchArgs: [{index: 0, operator: Postfix, values: ["contrib/tester-progs/nop"]}]` on an index-0 arg typed `linux_binprm`. Step 2b's narrower path-typed set (`file`/`filename`/`path`) did not classify `linux_binprm` as path-typed, so G2 never evaluated this `matchArgs` entry at all — a real gap C2 closes. With `linux_binprm` now path-typed, the architect's own formula ("Postfix on a directory target always covers, since contents are not enumerable") applies: `Postfix` against any protected directory is undecidable in general and is rejected unconditionally. This is a correct, intended consequence of implementing C2 exactly as specified, not a regression: an unscoped `Postfix` on a binary-path argument genuinely could match a file inside a protected directory, and this project has no way to prove otherwise from the policy text alone. |

Every other verdict (68 ACCEPT, 9 `REJECTED_GUARDRAIL` for unscoped G1
violations unrelated to this pass, 6 PARSE-REJECT for schema/allowlist
reasons) is unchanged from `docs/reports/step-02b.md` section 11 — see
that report for the full 73-row table; only the one row above differs.

## 7. Deviations / judgment calls in this pass

1. **G2's `Postfix`-on-directory-target "always covers" rule is broad.**
   As section 6 shows, it now rejects `lsm_bprm_check.yaml`, an upstream
   example. This is the architect's literal formula (item C2), applied
   faithfully; the alternative (trying to decide whether a *specific*
   suffix could plausibly appear inside a protected directory) would
   require either enumerating real filesystem contents (not available at
   verify time) or a heuristic this project would have to invent and
   defend — "reject more" was chosen deliberately here per the working
   agreement.
2. **The negative-operator mutation test (`TestMutation_
   NegativeOperatorsMissingEachProtectedBinary`) computes its expectation
   rather than hardcoding "always rejected."** An earlier version of this
   test assumed building a `NotPrefix` set from "every other protected
   binary's full path" would always leave exactly the target binary
   uncovered; this is false in general because some protected binaries are
   literal prefixes of others (`/usr/bin/tetra` is a prefix of
   `/usr/bin/tetragon`), so excluding "every other binary" via `NotPrefix`
   can *also* incidentally exclude the one binary the test meant to leave
   uncovered. The test now computes the brute-force expectation itself and
   asserts the real guard decision agrees with it, which is both more
   correct and still exercises every protected binary and every negative
   operator.
3. **C4's citation is from `pkg/selectors/kernel.go:1287-1293`, which shows
   `linux_binprm` sharing a code path with `file`/`path`/`string` for
   `Equal`/`NotEqual`, not a literal statement that the compared value is
   "the binary's path."** The additional confirmation that the extracted
   value specifically is the binary's path comes from test names/helpers
   (`kprobe_test.go:5550 TestLinuxBinprmExtractPath`,
   `lsm_test.go:264 WithLinuxBinprmArg(...).WithPath(testBin)`), which this
   project treats as sufficiently strong pinned-source evidence (test code
   is still part of the pinned, tagged source tree) without claiming to
   have read the runtime BPF-side extraction code itself.

## 8. Known limitations (unchanged from step 2b unless noted)

- G3's exec-hook coverage is now broader (identifier substring, C3) but
  still cannot find hooks whose identifier names an exec-related function
  by a name that doesn't contain "exec" or "bprm" (e.g. a custom kprobe on
  a vendor-specific exec wrapper). This is an inherent limitation of a
  substring heuristic, accepted as strictly better than the fixed list it
  replaces.
- G10 rejects uprobe `Override` outright rather than gating it by
  capability, since this project has no detection mechanism for whatever
  uprobe override actually requires (ADR 0014). A future step could add
  real detection and move uprobe `Override` from G10 to G8.
- Step 3 (not this step) must implement the usrmerge-symlink verification
  ADR 0015 requires; until then, `internal/guard`'s protected-binary/path
  matching assumes the standard RHEL 9 usrmerge topology unconditionally.

## 9. Self-review: places most likely to still have a bug

1. **`pathCoversPositive`'s exact-file branch delegates to `matches()`
   directly** rather than having its own directory-vs-file test coverage
   beyond `TestPathCoversPositive_ExactFileTarget`; a reviewer should
   double-check every protected-path entry that is NOT a directory (the
   tetragon.sock paths, `/dev/tpmrm0`, `/dev/tpm0`) against each operator
   at least once.
2. **`cleanAnchoredValues` applies `path.Clean` before matching, but
   `matches()`'s candidates (the `protectedBinaries`/`protectedPaths`
   literals) are never run through `path.Clean` themselves** — they are
   hand-written literals already in clean form, but there is no test that
   would catch a future typo (e.g. a literal containing `//`) silently
   making that one candidate unmatchable.
3. **G2's "has at least one positive operator" rule and G1's matching rule
   are structurally similar but not unified into one function**, unlike G1
   binaries vs. G2 exact-file targets which do share `matches()`; a
   reviewer should confirm `checkSelectorG2`'s hand-rolled positive/negative
   operator switch doesn't drift from `recognizedMatchOperators`'s list if
   either changes independently.
