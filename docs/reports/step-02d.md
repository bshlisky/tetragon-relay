# Step 2d report: remove value normalization from guard matching (review of 5bf5866)

## 1. Summary

- **D1 [CRITICAL] fixed.** `matches()`/`matchesAnyCandidate()`/
  `pathCoversPositive()` no longer clean selector values with `path.Clean`
  before comparing them against protected binaries/paths — comparison is
  now raw-string only, matching Tetragon's own comparison
  (`pkg/selectors/kernel.go:1287-1309`: `writeMatchStrings`/
  `writePrefixStrings`/`writePostfixStrings` never normalize their input).
  Step 2c's `cleanAnchoredValues` made this project's own check believe a
  `NotIn`/`NotPrefix` value like `"/usr/sbin/sshd/"` excluded a protected
  binary that, on a real host, it never would (a trailing slash, doubled
  slash, or `.`/`..` segment is a *different* raw string to Tetragon than
  the path it resembles) — the exact fail-open the architect reproduced.
- In its place, every anchored `matchBinaries`/`matchArgs` value in an
  enforcement selector is now required to already be in canonical form
  (`In`/`Equal`/`NotIn`/`NotEqual`: absolute and `== path.Clean(v)`;
  `Prefix`/`NotPrefix`: `== path.Clean(v)` or `== path.Clean(v)+"/"`;
  `Postfix`/`NotPostfix`: non-empty, no `..`, and no `//`/`/./`/`/../`
  substrings), for both positive and negative operators alike, with no
  special-casing — a non-canonical value is unsafe to reason about either
  way. Violations name the offending value, truncated to
  `limits.MaxReasonBytes` (128 bytes).
- All four of the architect's exact probes, plus each applied to a single
  binary inside an otherwise-exact exclusion list, are now rejected; the
  fully exact, canonical list is still accepted (section 2).
- The G1 property test was rewritten from scratch per D2: its reference
  implementation (`referenceBinaryMatches`/`referenceIsCanonicalValue`)
  shares no code with `internal/guard`, and its generator produces
  non-canonical spellings ~40% of the time (exceeding the 30% floor);
  10,000 trials all agree with the from-scratch reference, in both
  directions.
- The negative mutation sweep (step 2c) is extended with the same four
  non-canonical spellings (264 additional mutants); upstream corpus
  verdicts are unchanged (no corpus policy uses a non-canonical path
  spelling).
- `internal/guard` coverage: 96.8%. `make ci` green locally and on GitHub
  Actions (run number in section 4).

## 2. Probe table

| Probe (NotIn/NotPrefix with every protected binary written non-canonically) | Before (5bf5866) | After (this pass) |
| --- | --- | --- |
| `NotIn` with every value as `"/usr/sbin/sshd/"`-style (trailing `/`) | **ACCEPT (bug)** | `REJECTED_GUARDRAIL` (G1: non-canonical value) |
| `NotIn` with every value as `"//usr/sbin/sshd"`-style (doubled leading `/`) | **ACCEPT (bug)** | `REJECTED_GUARDRAIL` (G1: non-canonical value) |
| `NotIn` with every value as `"/usr/./sbin/sshd"`-style (`.` segment) | **ACCEPT (bug)** | `REJECTED_GUARDRAIL` (G1: non-canonical value) |
| `NotPrefix` with every value as `"/usr/sbin/sshd/"`-style (trailing `/`) | **ACCEPT (bug)** | `REJECTED_GUARDRAIL` (G1: non-canonical value) |
| Each of the above applied to exactly one binary inside an otherwise-exact list (18 binaries x 4 spellings = 72 cases) | not tested in step 2c | `REJECTED_GUARDRAIL` in every case (`TestG1_NonCanonicalValuesFailOpenRepro_SingleBinary`) |
| `NotIn` with every protected binary spelled exactly (control case) | ACCEPT | **ACCEPT** (unchanged; proves the rejections above are about spelling, not list breadth) |

## 3. Mapping: item → function → tests

| Item | Function(s) | Tests |
| --- | --- | --- |
| D1 | `internal/guard/paths.go: isCanonicalAnchoredValue, isCanonicalPostfixValue, firstNonCanonicalValue`; `matches`/`matchesAnyCandidate`/`pathCoversPositive` (cleaning removed); `guard.go: checkSelectorG1, checkSelectorG2`; `errors.go: truncateValue` | `TestG1_NonCanonicalValuesFailOpenRepro` (4 probes), `TestG1_NonCanonicalValuesFailOpenRepro_SingleBinary` (72 cases), `TestG1_ExactCanonicalListAccepted`, `TestTruncateValue_LongValueTruncated` |
| D2 (property test rewrite) | `property_test.go: referenceBinaryMatches, referenceAnyBinaryMatches, referenceIsCanonicalValue, mutateSpelling` | `TestProperty_G1RawStringSemantics` (10,000 trials, 39.9% non-canonical values generated) |
| D2 (mutation sweep extension) | `noncanonical_test.go: TestMutation_NonCanonicalSpellingInNegativeSweep` | 264 mutants (3 operators x 4 spellings x 18 protected binaries), decisions cross-checked against the same independent reference functions |
| D2 (corpus re-run) | — | `TestCorpusProbe_ParseAndGuard`: all 73 verdicts unchanged from step 2c (no corpus policy uses a non-canonical path spelling, so this is expected) |

## 4. Command output

```
make ci
  gofmt/goimports/go vet/golangci-lint       -> clean, 0 issues
  govulncheck                                -> No vulnerabilities found.
  go mod verify / vendor-check                -> clean
  verify-crd                                 -> OK: d99daa68c99faeab6a32ea843ab9a381ea2f63666b26e265bf048ac0ab617869
  go test -race -count=1 -cover ./...
      internal/dsse        100.0%
      internal/guard        96.8%
      internal/policydoc    96.0%
      internal/strictjson   98.5%
      internal/trust        97.9%
      internal/verify      100.0%
  make coverage (>= 95% gate, all six packages) -> PASS
  make fuzz-short (60s x 5 targets)           -> PASS, 0 crashes
  make proto (generate + breaking)            -> clean
  make verify-repro
      reproducible build OK: 0fc80478083701d3153cd9504e78a15c94ccf622c234c91af1ba45c92c5f4a7d
  make sbom                                  -> dist/sbom.spdx.json generated
Exit code: 0
```

Final commit for this step: `<filled in after push>`. GitHub Actions `ci`
run: `<filled in after push>`.

## 5. Self-review

1. `Postfix`/`NotPostfix` values are intentionally NOT required to be
   absolute (a bare filename like `"tetragon.sock"` is legitimate), so
   `isCanonicalPostfixValue` is a strictly weaker check than
   `isCanonicalAnchoredValue`; a reviewer should confirm no caller ever
   accidentally applies the anchored check to a Postfix value or vice
   versa (both are keyed off the same `operator` string in
   `firstNonCanonicalValue`, so a typo in that switch would be easy to
   miss without the dedicated per-operator tests this pass added).
2. The `Prefix`/`NotPrefix` "one trailing slash is also canonical" carve-out
   means `"/usr/sbin/sshd/"` is now a *legal* `NotPrefix` value (unlike for
   `NotIn`) — it simply doesn't exclude `/usr/sbin/sshd` itself (no raw
   string ends up matching), which the raw `matches()` comparison already
   gets right without any special-casing, but a reviewer should double
   check this interaction is intentional and not an oversight: the
   property test's generator (`mutateSpelling`) produces this exact value
   as one of its "non-canonical" cases, and the test correctly treats it as
   canonical-but-unsafe (rejected via the `referenceAnyBinaryMatches` path,
   not the canonical-value path) rather than failing to compile a correct
   expectation — see `TestProperty_G1RawStringSemantics`'s passing run for
   this exact case class.
3. `TestMutation_NonCanonicalSpellingInNegativeSweep` had to be written
   against a computed expectation (not "always rejected") for the same
   reason step 2c's sweep did: protected binaries that are literal
   prefixes/suffixes of each other (`tetra`/`tetragon`,
   `/sbin/X`/`/usr/sbin/X`) mean an untouched neighboring entry can
   accidentally exclude the mutated target regardless of its own spelling.
   This is a real, expected property of raw prefix/suffix matching, not a
   test bug, but it is also the single place in this pass most likely to
   mask a real regression if a reviewer doesn't realize some apparent
   "accepts" could be the independent reference functions themselves
   having a subtle bug rather than `internal/guard` being correct.
