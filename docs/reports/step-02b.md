# Step 2 report (Parts B–D): policy ingestion, schema validation, guardrails

Repo: `github.com/bshlisky/tetragon-relay`, branch `main`. Facts below are
generated from the repository and from a pinned clone of
`github.com/cilium/tetragon` at tag `v1.8.0` (commit
`a5a667837d4b1ecd9018797994bb4e39b98702e1`, "Prepare for v1.8.0 release",
2026-10-30 — the latest stable Tetragon release at the time this step was
done), not written from memory.

Final commit for this step: `83dab97`. GitHub Actions `ci` run for that
commit: **run #6** (https://github.com/bshlisky/tetragon-relay/actions/runs/45072811244),
conclusion `success`.

## 1. Summary

- New package `internal/policydoc` (Part B): turns one policy's YAML text
  (already sha256-verified by `internal/verify`) into an immutable, typed
  `*Doc` via YAML hardening, CRD schema validation (schema closed by
  injecting `additionalProperties:false`), a policy-level allowlist,
  deterministic canonical JSON, a typed model, an independent
  action-completeness cross-check, and bundle-name binding.
- New package `internal/guard` (Part C): the real guardrail engine,
  `G1`–`G9`, run in the pinned `G7,G6,G8,G1,G2,G3,G4,G5` order against
  `internal/policydoc.Doc` values.
- `internal/verify` wired to call both (Part C0): `PolicyParser` (new
  interface) and a rewritten `Guardrails` interface
  (`Check(guard.GuardContext, []*policydoc.Doc) error`); `G8` violations
  map to the new `CodeRejectedCapability`, everything else to
  `CodeRejectedGuardrail`; a nil `PolicyParser` fails closed like a nil
  `Guardrails`/`EpochSource` already did.
- Vendored `third_party/tetragon/v1.8.0/cilium.io_tracingpolicies.yaml`
  (hash-checked in CI by `make verify-crd`) and the full upstream
  `examples/tracingpolicy/` corpus (73 files) under `testdata/upstream/`.
- Four new ADRs: 0011 (yaml.v3 + jsonschema/v5 dependencies), 0012 (new
  threat T-27: YAML parser differential, and its mitigation), 0013 (G9
  trust-root field placement, proposed only, not implemented).
- 45 verify vectors (40 existing, re-signed because the generator's
  placeholder policy YAML became a real TracingPolicy, + 4 new: schema
  failure, name mismatch, guardrail rejection, capability rejection), all
  self-checked against the real `internal/verify` + `internal/guard` code
  at generation time; a 5th new scenario (nil `PolicyParser`) is a direct
  Go test, no vector needed.
- `internal/policydoc` 96.0%, `internal/guard` 95.8%, `internal/verify`
  100.0% statement coverage; `FuzzPolicyParse` and `FuzzGuard` added to
  both the 60s CI smoke (`make fuzz-short`) and the 15-minute nightly
  workflow.
- `make ci` passes from the current `HEAD` (commit `b08072d` at the time
  of this report); full log excerpted below.

## 2. File tree (new/changed, excluding `vendor/`)

```
internal/policydoc/
  doc.go errors.go yamlharden.go jsonconv.go schema.go allowlist.go
  model.go convert.go crosscheck.go
  parse_test.go unit_test.go internal_test.go smoke_test.go fuzz_test.go
  corpus_probe_test.go
internal/guard/
  interfaces.go errors.go actions.go protected.go paths.go guard.go
  guard_test.go unit_test.go mutation_test.go benchmark_test.go
  fuzz_test.go fakes_test.go corpus_probe_test.go
third_party/tetragon/v1.8.0/
  README.md crd.go cilium.io_tracingpolicies.yaml
testdata/upstream/            (73 example policies + MANIFEST.tsv + README.md)
testdata/vectors/
  policy_schema_failure.json policy_name_mismatch.json
  guardrail_rejection_unscoped_sigkill.json capability_rejection_override.json
  (+ 41 existing vectors, re-signed)
docs/decisions/0011..0013-*.md
docs/reports/step-02b.md      (this file)
internal/verify/              (interfaces.go, input.go, result.go, verify.go,
                                verify_test.go, edge_test.go, bench_test.go,
                                fuzz_test.go — all modified)
internal/strictjson/strictjson.go  (foldKey exported as FoldKey)
internal/limits/limits.go     (new YAML-hardening and G4 size-limit constants)
cmd/bundlesign-test/vectors.go     (real policy YAML, new vector-generation blocks)
.github/workflows/nightly-fuzz.yml (FuzzPolicyParse, FuzzGuard added)
Makefile                      (verify-crd target; coverage/fuzz-short cover both new packages)
```

## 3. Command output

### `make ci` (tail; full log ~450 lines, fuzz sections elided to start/end)

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
    internal/guard       ok    95.8% of statements
    internal/policydoc   ok    96.0% of statements
    internal/strictjson  ok    98.5% of statements
    internal/trust       ok    97.9% of statements
    internal/verify      ok   100.0% of statements
make coverage (>= 95% gate, all six packages)     -> PASS
make fuzz-short (60s per target, 5 targets)        -> PASS, see table below
make proto (buf generate + diff)                   -> clean
make breaking                                      -> clean (no proto change this step)
make verify-repro
    reproducible build OK: 8596acca2d16cfdaef8385d1fc7f4e8f3af76ce0c5a42e059f4e15708f9b0745
make sbom                                          -> dist/sbom.spdx.json generated
Exit code: 0
```

### Per-package coverage (statement, `-covermode=count`, plain `go test`, no `-race`)

| Package | Coverage | Required |
| --- | --- | --- |
| internal/dsse | 100.0% | ≥ 95% |
| internal/strictjson | 98.5% | ≥ 95% |
| internal/trust | 97.9% | ≥ 95% |
| internal/verify | 100.0% | ≥ 95% |
| internal/policydoc | 96.0% | ≥ 95% |
| internal/guard | 95.8% | ≥ 95% |

### Fuzz runs (60s each, this `make ci` run, 10 workers)

| Target | Package | Execs | New interesting (base → total) | Crashes |
| --- | --- | --- | --- | --- |
| `FuzzStrictJSON` | internal/strictjson | 216,450 | 513 → 531 | 0 |
| `FuzzVerifyEnvelope` | internal/verify | 5,021,313 | 699 → 728 | 0 |
| `FuzzRootUpdate` | internal/trust | 349,256 | 448 → 476 | 0 |
| `FuzzPolicyParse` | internal/policydoc | 1,538,650 | 230 → 416 | 0 |
| `FuzzGuard` | internal/guard | 1,250,514 | 188 → 252 | 0 |

A standalone 60s run of `FuzzPolicyParse` alone (not competing with other
packages' fuzzers for CPU) reached 1.5M+ execs with 0 crashes, confirming
`FuzzVerifyEnvelope`'s neighboring packages were not starving these two new
targets.

### Benchmark (`internal/guard`, `-benchtime=20x`, Apple M2 Pro, no `-race`)

```
BenchmarkCheck_WorstCase-10    20    2749592 ns/op    83968 B/op    1280 allocs/op
```

`TestCheck_WorstCasePerformance` (best of 7 attempts, same input: 256
hooks, 4096 selector values, the largest allowed bundle) is a hard test
gate, excluded under `-race` by a `//go:build !race` tag (same precedent as
`internal/verify/bench_test.go`, step 1 review A4) since the race
detector's instrumentation overhead (~95ms measured) has nothing to do
with `Check`'s real cost (~2.7ms):

```
Check on the largest allowed bundle (256 hooks, 4096 selector values), best of 7: 2.676625ms
```

Well under the 50ms budget.

### golangci-lint / govulncheck

```
0 issues.
No vulnerabilities found.
```

## 4. Mapping: B/C/G item → function → tests → vectors

| Item | Function(s) | Tests | Vectors |
| --- | --- | --- | --- |
| B1 (YAML hardening) | `internal/policydoc/yamlharden.go: parseHardenedYAML, checkRawBytes, hardenedYAML.walk/walkMapping, isYAML11Ambiguous` | `TestParse_B1_*` (14 structural cases + 11 ambiguous-scalar cases), `TestWalkMapping_*`, `TestParseHardenedYAML_*` (internal_test.go white-box cases for defensive branches) | none dedicated (B1 failures are policydoc-internal; `policy_schema_failure` vector exercises B4, not B1) |
| B2 (duplicate-key re-check) | `internal/policydoc/doc.go: Parse` → `strictjson.CheckNoDuplicateKeys` | covered transitively by every B1 duplicate-key test; `TestDecodeGeneric_InvalidJSON` | — |
| B3 (CRD schema, closed) | `internal/policydoc/schema.go: compileTracingPolicySchema, closeSchema, validateAgainstSchema` | `TestParse_B3_SchemaRejects*`, `TestExtractOpenAPIV3Schema_Errors`, `TestCompileTracingPolicySchema_*` | `policy_schema_failure` |
| B4 (allowlist) | `internal/policydoc/allowlist.go: checkAllowlist` | `TestParse_B4_Allowlist` (6 cases), `TestCheckAllowlist_NilSpec` | `policy_schema_failure` (podSelector) |
| B5 (canonical form) | `internal/policydoc/jsonconv.go: canonicalJSON, toCanonicalValue, renderNumber` | `TestParse_NumberPreservation*`, `TestParse_FloatAndBoolAndNullScalars`, `TestRenderNumber_*`, `TestDoc_CanonicalSHA256` | — |
| B6 (typed model) | `internal/policydoc/model.go`, `convert.go: buildHooks, resolveSelector` | `TestParse_Valid`, `TestSmoke_*`, `TestParse_B6_IntegerOverflowRejectedByTypedModel`, `TestParse_UnknownMacro`, `TestParse_MacroMergesActions`, `TestBuildHooks_UnknownMacroPropagatesForEveryHookKind` | — |
| B7 (completeness cross-check) | `internal/policydoc/crosscheck.go: checkActionCompleteness, genericActionWalk, typedModelActionWalk` | `TestCheckActionCompleteness_Mismatch`, `TestCheckActionCompleteness_SameLengthDifferentContent`, `TestCheckActionCompleteness_Match`, `TestTypedModelActionWalk_MatchReturnActions` | — |
| B8 (name binding) | `internal/policydoc/doc.go: Parse` (metadata-name section) | `TestParse_B8_NameBinding` | `policy_name_mismatch` |
| C0 (PolicyParser wiring) | `internal/verify/verify.go: Verify` (step 11's `in.PolicyParser.Parse` call) | `TestVerify_NilPolicyParserRejectsClosed`; every `TestVectors_Verify` case now round-trips through the real parser | all 45 vectors |
| C0 (Guardrails signature + G8→REJECTED_CAPABILITY) | `internal/verify/verify.go: Verify` (step 12) | `TestVerify_GuardrailCalledLastAndOnlyOnOtherwiseValid` | `guardrail_rejection_unscoped_sigkill`, `capability_rejection_override` |
| G1 | `internal/guard/guard.go: checkG1, checkSelectorG1`, `paths.go: anyBinaryCovered, excludesAllBinaries` | `TestCheck_G1` (11 cases incl. usrmerge alias, trailing slash, traversal, matchPIDs=1, followChildren), `TestCheck_G1_NotInCoversAll_Passes`, `TestCheck_G1_PostfixAndNotPostfix`, `TestCheckSelectorG1_UnrecognizedOperator` | `guardrail_rejection_unscoped_sigkill` |
| G2 | `internal/guard/guard.go: checkG2, checkSelectorG2`, `paths.go: anyPathCovered, coversPrefix/coversPostfix` | `TestCheck_G2` (5 cases incl. Prefix "/", Prefix "/var", Postfix on the Tetragon socket, Not*-only), `TestCoversPrefix_NestedInsideProtectedDirectory`, `TestCoversPostfix_DirectoryTarget`, `TestG9_ExtraProtectedExtendsPaths` | — |
| G3 | `internal/guard/guard.go: checkG3, isExecHook, execSelectorScoped` | `TestCheck_G3` (5 cases, including the G1-vs-G3 ordering interaction — see section 10), `TestCheck_G3_RuleIsG3Specifically`, `TestCheck_G3_NonExecHookUnaffected`, `TestIsExecHook_NonKProbeNonLsm` | — |
| G4 | `internal/guard/guard.go: checkG4, selectorValueCount` | `TestCheck_G4_HookCountLimit`, `TestCheck_G4_SelectorValueLimit`, `TestSelectorValueCount_AllFields`, `TestCheck_WorstCasePerformance`, `BenchmarkCheck_WorstCase` | — |
| G5 | `internal/guard/guard.go: checkG5, docHasEnforcement` | `TestCheck_G5_MonitorFirst` (4 subtests: monitor-mode-skips, enforce-rejects, enforce-seen-allows, history-error-fails-closed), `TestCheckG5_SkipsPoliciesWithoutEnforcement` | — |
| G6 | `internal/guard/guard.go: checkG6` | `TestCheck_G6_InvalidMode` | — |
| G7 | `internal/guard/guard.go: checkG7`, `actions.go: isKnownAction` | `TestCheck_G7_UnknownAction_LogicUnit`, `TestCheck_G7_AllRealActionsAccepted` | — |
| G8 | `internal/guard/guard.go: checkG8, selectorUsesOverride` | `TestCheck_G8_CapabilityGating`, `TestCheck_G8_LsmHookRequiresLSMBPF`, `TestCheck_G8_NoCapabilitiesConfigured` | `capability_rejection_override` |
| G9 | `internal/guard/interfaces.go: ProtectedSetSource`; `guard.go: extraBinaries/extraPaths` | `TestCheck_G9_ExtraProtectedExtendsG1AndG2`, `TestG9_ExtraProtectedExtendsPaths`, `TestExtraPaths_NilAndSet` | — (no bundle-level vector possible by design; see ADR 0013) |
| Mutation property test | — | `TestMutation_EveryProtectedBinaryAndPathIsCaught`: 27 mutants (16 protected binaries + 11 protected paths), all rejected | — |
| Parser-differential / stability | `internal/policydoc` canonical JSON re-parse | folded into `FuzzPolicyParse`: every accepted input's canonical JSON is re-parsed and its `CanonicalSHA256` compared; `TestDoc_CanonicalSHA256` checks stability across two `Parse` calls | — |

## 5. Invariants / threats addressed

- **INV-1** ("no TracingPolicy is loaded unless signature, target, epoch,
  expiry, schema, guardrails all hold"): B1–B8 and G1–G9 are exactly the
  "schema" and "guardrails" halves of this invariant that step 1 left as
  interfaces; `TestVectors_Verify`/`TestVectors_Verify_PinnedOrder` still
  pin the overall order with PolicyParser/Guardrails now real.
- **T-12** (single insider approves destructive policy): G1–G3's
  protected-binary/path/exec-denial checks are the last line stopping a
  signed, approved bundle from being catastrophic, independent of
  approval-process controls (section 7.1) this step does not touch.
- **T-16** (catastrophic but validly signed policy locks out the fleet):
  directly addressed by G1 (sshd/systemd/tetragon/relayd/chronyd/
  spire-agent/sudo/auditd/journald protected) and G5 (monitor-first), both
  implemented and tested end to end through `internal/verify`.
- **T-27** (new, ADR 0012): YAML parser differential between this agent's
  parser and Tetragon's own. Mitigated by B1 rejecting every
  YAML-1.1-ambiguous unquoted scalar and B5's canonical JSON being the
  bytes Step 3 must send to Tetragon (not the original YAML), so there is
  no second parse step downstream where a second parser's resolution could
  diverge.

## 6. Deviations from the prompt / architecture doc, with reasons

1. **`FollowFD`/`UnfollowFD`/`CopyFD` do not exist in the pinned version.**
   The prompt's observe-action list names them; `pkg/selectors/kernel.go:50,52,54`
   in the pinned source marks them deprecated and they are absent from
   `actionTypeTable` (`kernel.go:67-81`), so no YAML spelling of them
   resolves to a real action. `internal/guard/actions.go` documents this
   and treats any occurrence as unknown (G7), which is also what
   `internal/policydoc`'s CRD-schema-driven enum already enforces one
   layer earlier.
2. **`UpdateState` (new in Tetragon 1.8) is treated as unknown/rejected**,
   not as observe, even though `kernel.go`'s own `HasEnforcementAction`
   doesn't call it enforcement either. Per "ambiguity: implement the
   interpretation that rejects more" — this project did not analyze
   whether `UpdateState`'s cross-selector state mutation could be abused to
   make guard's per-selector analysis miss something, so it is rejected
   rather than guessed to be safe.
3. **G3's exec-hook list is incomplete by necessity, not by choice.** No
   execve-syscall or execve-tracepoint hook name usable from a
   user-authored `TracingPolicy` was found anywhere in the pinned source or
   the 73-file example corpus; the only `sys_execve` occurrence
   (`pkg/sensors/base/base.go:36`) is Tetragon's own always-on base sensor,
   not something a policy can hook. G3 currently only covers
   `security_bprm_check`/`security_bprm_creds_for_exec` kprobes and
   `bprm_check_security`/`bprm_creds_for_exec` lsmhooks (the latter two
   spellings are this project's judgment call, not a confirmed fact — see
   open question 1).
4. **"Positive matchArgs on the filename" (G3) is implemented as "any
   positive matchArgs on the hook," not specifically on a filename-typed
   argument.** `linux_binprm` (the arg type `security_bprm_check` actually
   uses, per every example in the corpus) is not itself one of the
   path-typed `KProbeArg.Type` values (`file`/`filename`/`path`), and no
   pinned-source evidence tells us which `resolve:` sub-path or arg index
   Tetragon itself would consider "the filename" for this hook. Rather
   than guess, any positive-operator `matchArgs` entry is accepted as
   sufficient scoping (open question 2).
5. **G8 only gates `Override` on kprobes and lsmhooks**, per the prompt's
   literal wording; `Override` on uprobes (which the CRD's own doc comment
   says is also supported, with different sub-mechanisms — symbol/address/
   offset override, not kernel-level `ALLOW_ERROR_INJECTION`) is not
   capability-gated here (open question 3).
6. **G1/G2's "Kubernetes-only selector" interpretation of "namespace
   selectors."** The pinned CRD has no field literally named "namespace
   selector"; `podSelector`/`containerSelector`/`hostSelector`/
   `nodeSelector` (`tracing_policy_types.go:106-134`) are treated as the
   Kubernetes-only set per the "reject more" rule — see
   `internal/policydoc/allowlist.go`'s doc comment.
7. **G9 has no runtime `Check`-time rule of its own.** It is enforced
   entirely by the `ProtectedSetSource` interface's shape (a bundle has no
   path to it) rather than a rejection path; ADR 0013 proposes, but does
   not implement, where its data would actually live in signed root
   metadata.
8. **G1 always running before G3 makes part of G3's literal wording
   unreachable.** G1 unconditionally requires `matchBinaries` on every
   enforcement selector (not just exec-hook ones); by the time G3 runs,
   `matchBinaries` is already guaranteed non-empty (and, if `NotIn`/
   `NotPrefix`, already guaranteed to exclude every protected binary). So
   "G3 is satisfied purely via `matchArgs`, with no `matchBinaries` at all"
   can never actually occur through `Check`'s pinned order; G3's real,
   reachable value is rejecting a `NotIn`/`NotPrefix` selector that is
   G1-safe yet still unscoped (`TestCheck_G3`'s `notin_alone_is_unscoped_for_g3`
   case proves this is live code, not dead code — it is reachable, just not
   via a `matchBinaries`-absent path).
9. **`cmd/bundlesign-test`'s `validPolicyYAML` and several of its existing
   vector-generation call sites had to change** (not just additions) to
   keep self-checking meaningfully once `internal/verify` calls the real
   `internal/policydoc.Parse`: the old placeholder
   `apiVersion/kind/metadata` stub with no `spec` would be rejected by B3
   (the CRD requires `spec`); `duplicate_policy_names`' two policies had
   mismatched `metadata.name`/declared-name pairs that would now trip B8
   before the duplicate-name check the vector is meant to exercise. All 45
   vectors were regenerated and re-self-checked.

## 7. Dependencies added and justification

See ADR 0011. `gopkg.in/yaml.v3` v3.0.1 (2022; `yaml.Node` API for B1's
structural hardening) and `github.com/santhosh-tekuri/jsonschema/v5` v5.3.1
(2023; B3's CRD schema validation). Both are leaf dependencies (`go mod
graph` shows only `gopkg.in/yaml.v3`→`gopkg.in/check.v1`, a test-only
dependency not vendored into the build).

## 8. Known limitations; what is stubbed behind interfaces

- `internal/guard.HostCapabilities` (G8), `PolicyHistory` (G5), and
  `ProtectedSetSource` (G9) are interfaces with fakes only; real kernel
  capability detection is step 3, persistence is step 4, and the signed
  trust-root extension mechanism is proposed (ADR 0013) but not
  implemented.
- The transparency-log inclusion proof (architecture doc section 7.4 step
  4) remains unimplemented from step 1; unaffected by this step.
- G3's exec-hook coverage and "positive matchArgs on the filename" are
  both narrower/looser than the prompt's literal wording, for the reasons
  in section 6, items 3–4.
- Five `internal/policydoc` lines (in `Parse`'s own body: `canonicalJSON`'s
  error branch, the B2 re-check's error branch, `decodeGeneric`'s error
  branch, the "document is not a JSON object" branch, and
  `checkActionCompleteness`'s call site) are structurally unreachable
  through `Parse` given B1's own guarantees (the same category of
  documented-uncovered defensive code as
  `internal/trust.DeriveKeyID`'s uncovered error path from step 1); the
  underlying functions themselves (`checkActionCompleteness`,
  `decodeGeneric`, etc.) are unit tested directly.
- `make breaking`'s baseline is unchanged this step (no proto edits).

## 9. Open questions for the architect

1. Which exact kprobe/lsmhook/tracepoint hook name(s) does Tetragon v1.8.0
   use for `security_bprm_creds_for_exec` / `bprm_creds_for_exec`, and is
   there any user-addressable execve syscall/tracepoint hook at all? This
   project found no example or other pinned-source confirmation of either.
2. For `security_bprm_check`/`bprm_check_security` (arg type
   `linux_binprm`), which argument index or `resolve:` sub-path should G3
   treat as "the filename" the prompt's wording refers to? Currently any
   positive `matchArgs` entry is accepted.
3. Should G8 also gate `Override` on uprobes? The CRD documents uprobe
   override as a different mechanism (symbol/address/offset substitution,
   not `ALLOW_ERROR_INJECTION`); if it needs its own capability check, what
   detects it?
4. Is `UpdateState` safe to eventually classify as observe, or does its
   cross-selector state-mutation semantics need its own guard rule (e.g.
   bounding which states an enforcement decision elsewhere in the policy
   can be made to depend on)?
5. Does the real G9 implementation belong in root metadata as ADR 0013
   proposes, or somewhere else (e.g. a dedicated signed artifact)?
6. `hostSelector`/`nodeSelector` were folded into "Kubernetes-only
   selectors" for B4 by this project's interpretation (section 6, item 6);
   does the architect agree these two should also be rejected outright, or
   should `nodeSelector` (which only affects where a policy is *loaded*,
   not what it *matches*) be treated differently on a single-host agent
   where "which nodes" is moot but arguably harmless?

## 10. Self-review: 5 places a reviewer is most likely to find a bug

1. **The G1/G3 ordering interaction (section 6, item 8).** It took a failed
   test run to discover that G1's unconditional `matchBinaries` requirement
   makes part of G3's literal wording unreachable; a reviewer should
   double check `TestCheck_G3`'s `notin_alone_is_unscoped_for_g3` case
   actually exercises G3's logic and isn't accidentally passing because G1
   fired first (it isn't — `ruleOf(t, err) != RuleG3` is asserted
   explicitly in `TestCheck_G3_RuleIsG3Specifically`).
2. **`coversPrefix`/`coversPostfix`'s bidirectional matching
   (`internal/guard/paths.go`).** The "nested inside" direction
   (`strings.HasPrefix(nv, t)`) was added after the straightforward
   "ancestor" direction alone missed a real case during development; a
   reviewer should check this logic against more adversarial Prefix/Postfix
   combinations than the ones in `TestCheck_G1`/`TestCheck_G2`.
3. **`closeSchema`'s generic `additionalProperties:false` injection**
   (`internal/policydoc/schema.go`) assumes every object-shaped schema node
   with `properties` and no explicit `additionalProperties` should be
   closed. If a future CRD version adds a legitimate open-ended struct
   field without using `additionalProperties` to express it, this would
   silently over-reject rather than under-reject — safe-by-default, but
   worth re-verifying against the next pinned CRD version at upgrade time.
4. **`renderNumber`'s re-rendering path** (`internal/policydoc/jsonconv.go`)
   for YAML numeric literals that aren't already valid JSON syntax (hex,
   underscore-grouped, `+`-prefixed): this re-derives the value via
   `yaml.v3`'s own resolution rather than preserving the literal text,
   which is a deliberate, documented exception to "numbers preserved
   exactly as parsed" (B5) — a reviewer should confirm this exception is
   narrow enough (it only applies to non-JSON-syntax numeric literals, not
   ordinary decimal ones) and doesn't inadvertently affect the common case.
5. **Usrmerge alias canonicalization is a fixed 3-rule function
   (`canonicalizeUsrmerge`)**, not derived from any live filesystem state;
   if a host's actual symlink topology ever differs from the assumed
   `/var/run→/run`, `/sbin→/usr/sbin`, `/bin→/usr/bin` mapping, a
   protected-binary/path match could be missed. This is inherent to doing
   the check statically at verify time (before any host-specific
   information is available) and is not something this step can fix, but
   it is a real residual-risk assumption worth flagging for the architect.

## 11. Upstream corpus results (73 files, `Parse` then `Check`)

58 ACCEPT, 6 PARSE-REJECT (schema/allowlist), 9 GUARD-REJECT. Every
rejection is correct and expected: the upstream examples are illustrative
of Tetragon *capability*, not written to pass a production security
review, and several deliberately use unscoped `Sigkill`/`Override` to keep
the example short.

| File | Result | Rule/reason |
| --- | --- | --- |
| bpf.yaml | ACCEPT | — |
| cves_cve-2023-2640-overlayfs-ubuntu.yaml | GUARD-REJECT | G1: `security_inode_copy_up_xattr` enforcement selector has no matchBinaries |
| cves_cve-2024-3094-xz-ssh.yaml | ACCEPT | — |
| cves_cve-2026-65960.yaml | GUARD-REJECT | G1: `security_socket_connect` enforcement selector has no matchBinaries |
| datagram*.yaml (4 files) | ACCEPT | — |
| dev_hard_start_xmit.yaml, dev_queue_xmit.yaml | ACCEPT | — |
| dns-only-specified-servers.yaml | GUARD-REJECT | G1: `ip_output` enforcement selector has no matchBinaries |
| fd_install_*.yaml (4 files) | ACCEPT | — |
| fentry.yaml | PARSE-REJECT | B4: `fentries` is not an allowed hook type |
| filename_monitoring*.yaml (2 files) | ACCEPT | — |
| hardlink-observe.yaml | ACCEPT | — |
| hardlink-override.yaml | GUARD-REJECT | G1: `sys_linkat` enforcement selector has no matchBinaries |
| host-changes_*.yaml (2 files) | ACCEPT | — |
| killer.yaml, kprobe_commit_creds.yaml | ACCEPT | — |
| list-*.yaml (4 files) | ACCEPT | — |
| loader.yaml | PARSE-REJECT | B4: `spec.loader` is not an allowed hook mechanism |
| lsm_bprm_check.yaml, lsm_file_open.yaml, lsm_track_grandparent.yml | ACCEPT | — |
| modules-nohost.yaml | PARSE-REJECT | B4: `podSelector` is a Kubernetes-only selector |
| open_dnsrequest.yaml, open_geturl.yaml, openat_write.yaml | ACCEPT | — |
| override-security.yaml | GUARD-REJECT | G1: `security_inode_mkdir` enforcement selector has no matchBinaries |
| process-credentials_creds-capability-usage.yaml | ACCEPT | — |
| process-credentials_process-creds-changed.yaml, -installed.yaml | ACCEPT | — |
| process-credentials_process.credentials.changes.at.syscalls.yaml | PARSE-REJECT | B8/limits: `metadata.name` contains dots, disallowed by `PolicyNamePattern` (step 1) |
| process-exec_process-exec-elf-begin.yaml | ACCEPT | — |
| raw_syscalls.yaml, rawtp.yaml | ACCEPT | — |
| sandbox_linux-namespaces_kill_unprivileged_user_namespace*.yaml (2 files) | GUARD-REJECT | G1: `create_user_ns` enforcement selector has no matchBinaries |
| security-socket-connect*.yaml (2 files) | ACCEPT | — |
| security_bprm_check.yaml, security_inode_follow_link.yaml | ACCEPT | — |
| stack_traces.yaml, symlink-observe.yaml | ACCEPT | — |
| symlink-override.yaml | GUARD-REJECT | G1: `sys_symlinkat` enforcement selector has no matchBinaries |
| sys_*.yaml (5 files) | ACCEPT | — |
| tcp-accept.yaml, tcp-connect-only-local-addrs.yaml | ACCEPT | — |
| tcp-connect-only-private-addrs.yaml | GUARD-REJECT | G1: `tcp_connect` enforcement selector has no matchBinaries |
| tcp-connect-with-selectors.yaml, tcp-connect.yaml, tcp-listen.yaml | ACCEPT | — |
| tty.yaml, tty_54.yaml | ACCEPT | — |
| uprobe*.yaml (4 files) | ACCEPT | — |
| usdt-set.yaml, usdt.yaml | PARSE-REJECT | B4: `usdts` is not an allowed hook type |
| write.yaml | ACCEPT | — |

## 12. Every place the CRD schema allows additional properties, and how it was closed

A search of the vendored `cilium.io_tracingpolicies.yaml` found 25
occurrences of the `additionalProperties` keyword, all of them legitimate
`map[string]T`-shaped fields (e.g. Kubernetes label-selector `matchLabels`,
`selectorsMacros`), already declaring a value sub-schema — these were left
untouched. Every *other* object-shaped schema node that has `properties`
but does not declare `additionalProperties` — which, per the JSON Schema
spec (not Kubernetes' own structural-schema pruning semantics, which this
library does not implement), defaults to `true` and would silently accept
arbitrary unknown sibling keys — is closed by
`internal/policydoc/schema.go: closeSchema`, a generic post-processing
pass over the decoded schema document run once at
`compileTracingPolicySchema` time. This covers every struct-shaped field in
the CRD: `TracingPolicySpec` itself and every nested
`KProbeSpec`/`TracepointSpec`/`UProbeSpec`/`LsmHookSpec`/`KProbeSelector`/
`ArgSelector`/`BinarySelector`/`ActionSelector`/`PIDSelector`/`ListSpec`/
`OptionSpec`/`EnforcerSpec`/`State` object, none of which declared
`additionalProperties` in the vendored file. `metadata` (`type: object`
with no `properties` at all) is the one schema node `closeSchema`
deliberately leaves fully open — B8 validates `metadata.name` directly
rather than through the schema, since `metadata` is genuinely Kubernetes
`ObjectMeta`-shaped and this project does not model or restrict its other
fields (labels, annotations, etc.).

## 13. Every Tetragon fact relied on, with pinned-source citation

- Action enum and the four deprecated/removed action types:
  `pkg/selectors/kernel.go:48-81` (constants + `actionTypeTable`).
- Enforcement/observe split: `pkg/selectors/kernel.go:2339-2349`
  (`HasEnforcementAction`).
- `ActionSelector.action` CRD enum (confirms the 13-action set at the
  schema level too): `pkg/k8s/apis/cilium.io/v1alpha1/types.go:382`.
- `TracingPolicySpec` field list (`kprobes`, `tracepoints`, `loader`,
  `uprobes`, `lsmhooks`, `usdts`, `fentries`, `podSelector`,
  `containerSelector`, `hostSelector`, `nodeSelector`, `lists`,
  `enforcers`, `options`, `selectorsMacros`, `state`):
  `pkg/k8s/apis/cilium.io/v1alpha1/tracing_policy_types.go:83-159`.
- `BinarySelector`/`KProbeSelector`/`PIDSelector`/`ArgSelector`/
  `ActionSelector`/`KProbeArg` field shapes:
  `pkg/k8s/apis/cilium.io/v1alpha1/types.go:75-481`.
- `KProbeArg.Type` enum, including path-typed values `file`/`filename`/
  `path`: `types.go:79`.
- `matchBinaries`/`matchParentBinaries` are `MaxItems=1`:
  `types.go:180-187`.
- `matchActions` is capped at 3 per selector:
  `pkg/selectors/kernel.go:1707-1708`.
- `matchPIDs` values capped at 4 (matching the kernel's `selector_match()`
  iteration count): `pkg/selectors/kernel.go:371` and its comment.
- `matchNamespaces`/`matchNamespaceChanges` values capped at 4:
  `pkg/selectors/kernel.go:1725`.
- `EnforcerSpec{Calls []string}`: `types.go:708-711`.
- `OptionSpec{Name, Value string}`: `types.go:637-643`.
- Example hook names: `security_bprm_check` (kprobe) —
  `examples/tracingpolicy/security_bprm_check.yaml:7`; `bprm_check_security`
  (lsmhook) — `examples/tracingpolicy/lsm_bprm_check.yaml:8`.
- Tetragon gRPC socket path `/var/run/tetragon/tetragon.sock`: architecture
  doc section 9.1 (not a Tetragon source citation, but the basis for the
  `coversPostfix` "tetragon.sock" protected-path test case).
- CRD top-level `required: [metadata, spec]` (no required sub-fields of
  `spec`): derived directly from the vendored
  `third_party/tetragon/v1.8.0/cilium.io_tracingpolicies.yaml`, confirmed
  by a one-off Go program during this step (not itself committed).
- Tag/commit provenance: `git ls-remote`/`git log` against
  `https://github.com/cilium/tetragon` at tag `v1.8.0` →
  `a5a667837d4b1ecd9018797994bb4e39b98702e1`.
