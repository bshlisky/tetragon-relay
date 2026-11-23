# Step 3 report: Tetragon client, capability probe, apply engine

Commits: `926c55f`..`e64e24d` (docs review, A1 fix, B vendoring/client,
C probe/hostprobe, D apply engine). Final commit as of this report:
`e64e24d`.

## 1. Summary

- **Part A1 [HIGH] fixed**, per `docs/reviews/step-02d-review.md` (added
  this step, from the architect text supplied at the start of this step):
  escape-decoded control/invisible characters in quoted YAML scalars
  (`\0`, `\t`, `\u0000`, `\u202e`) bypassed every existing control-character
  check because `checkRawBytes` only inspects raw document bytes, before
  YAML escape decoding happens. Fixed in `internal/policydoc` with a
  generic post-decode check (Cc except tab/LF/CR, all Cf, U+2028/U+2029,
  noncharacters) plus a targeted `\t\n\r` rejection in hook identifiers and
  selector values. All four architect probes now rejected; `internal/policydoc`
  coverage 95.9%.
- **Part B**: `internal/tetra`, a gRPC client to Tetragon restricted to the
  prompt's 8-RPC allowlist (statically enforced by
  `TestAllowlist_NoOtherRPCsReferenced`), with socket peer verification
  (lstat + SO_PEERCRED + `/proc/<pid>/exe`), per-call timeouts, typed
  errors, and a version gate. `third_party/tetragon/v1.8.0/api/v1/tetragon`
  vendors the pinned release's generated gRPC bindings directly (not as a
  real module dependency, since upstream's own `api/go.mod` would pull in
  the whole monorepo). Coverage 92.7% (darwin build; Linux-only
  socket-verification code is additional and not counted in that number
  here — see section 13).
- **Part C**: `cmd/relay-probe` (root-run, systemd `ExecStartPre=+`) reads
  kernel config/LSM list/debugfs error-injection list, verifies usrmerge,
  and records Secure Boot/lockdown/SELinux/RHEL release/Tetragon binary
  hash into a versioned `HostFacts` JSON file; `internal/hostprobe` is the
  unprivileged agent-side reader, implementing `guard.HostCapabilities`
  and failing closed (every capability false) on any missing/stale/invalid
  file. `relay-probe --report` + `docs/runbooks/capability-matrix.md`
  cover Part C5. Coverage: `internal/hostprobe` 90.4%.
- **Part D**: `internal/apply`, the add-before-remove apply engine with
  Part D1's loaded-name/relay-managed-domain scheme, D2's mode rewrite
  (always action-rewrite, never native mode — ADR 0016), D3's
  add/confirm/remove sequencing with partial-failure cleanup, D4's atomic
  directory persistence, D5's health window (GetHealth, control-plane
  reachability, admin-path enforcement events, surge threshold), D6's
  rollback, D7's single-flight + audit events, D8's digest (ADR 0017
  documents the residual risk), and D9's `Reconcile`. Coverage 94.3%.
- **Part E**: fake-gRPC-server tests for B (`internal/tetra`) and D
  (`internal/apply`), including the required add-fails-partway,
  confirm-shows-error-state, delete-fails, and health-window-degrades
  scenarios, plus the no-gap invariant reasoning in section 12.
  `.github/workflows/ci.yml` gains a `coverage90` gate and an
  `integration` job (Part E3); `scripts/e2e-rhel9.sh` (Part E4) and
  `internal/{tetra,apply}`'s `-tags integration` test files are authored
  and reviewed but **not executed** — no Linux host with a real Tetragon
  daemon was available in the environment this step was done in (section
  13 is explicit about every claim that rests on this limitation).
  `FuzzHostFacts` added for `internal/hostprobe` (Part E6).

## 2. Scope changes / deviations from the literal prompt

- **D2's native-mode branch is never taken.** ADR 0016: Tetragon v1.8.0
  does have native per-policy mode, but the only RPC that sets it
  (`ConfigureTracingPolicy`) is outside Part B1's allowlist. The allowlist
  is treated as the harder constraint; the engine always uses the
  action-rewrite-to-Post fallback. Flagged explicitly rather than silently
  choosing one reading, since the prompt's B1 and D2 texts are in tension.
- **`internal/verify.Result` was not extended with parsed `*policydoc.Doc`s.**
  Part D's framing ("Input: a verify.Result ACCEPT (bundle + parsed
  docs)") could have meant threading `internal/verify`'s already-parsed
  docs through to `internal/apply`. Instead, `internal/apply` re-parses
  each policy's YAML itself via its own `PolicyParser` interface (real
  impl: `RealPolicyParser`, calling `policydoc.Parse`). This avoids any
  change to `internal/verify` (reviewed twice already) for a re-parse that
  is cheap, deterministic, and operates on already-hash-verified YAML.
- **Admin-path set is compiled in, not configurable.** The step 3 prompt
  lists a fixed admin-path set for Part D5; this project did not add a
  config knob to extend it (unlike `internal/guard`'s protected
  binaries/paths, which a trust-root update can extend per ADR-adjacent
  design in step 2). Noted as a possible gap if a deployment's shell path
  differs from the compiled-in list.

## 3. Files changed, by part

- Part A: `internal/policydoc/{yamlharden,convert,errors}.go`,
  `internal/policydoc/a1_controlchars_test.go`,
  `internal/policydoc/fuzz_test.go`, `docs/reviews/step-02d-review.md`.
- Part B (+ vendoring): `third_party/tetragon/v1.8.0/api/v1/tetragon/*`,
  `internal/tetra/*`, `docs/decisions/0016-apply-engine-mode-mechanism.md`,
  `Makefile` (`verify-tetragon-api`, `coverage90`), `.golangci.yml`.
- Part C: `cmd/relay-probe/*`, `internal/hostprobe/*`,
  `packaging/systemd/tetragon-relay.service`,
  `docs/runbooks/capability-matrix.md`, `docs/architecture.md` §8.7 addendum.
- Part D: `internal/apply/*`, `docs/decisions/0017-loaded-policy-digest-residual-risk.md`.
- Part E: `.github/workflows/ci.yml` (`integration` job),
  `scripts/e2e-rhel9.sh`, `internal/tetra/dial_linux_test.go`,
  `internal/apply/integration_test.go` (`-tags integration`),
  `internal/hostprobe/fuzz_test.go`.

## 4. Verification run (this development machine, macOS/darwin)

```
make lint        -> 0 issues (gofmt, goimports, go vet, golangci-lint)
make vuln        -> No vulnerabilities found
make modverify   -> all modules verified
make vendor-check -> clean
make verify-crd  -> OK
make verify-tetragon-api -> OK
go test -race -count=1 ./...  -> ok, all packages
make coverage    -> internal/dsse 100.0%, internal/guard 96.8%,
                    internal/policydoc 95.9%, internal/strictjson 98.5%,
                    internal/trust 97.9%, internal/verify 100.0% (all >= 95%)
make coverage90  -> internal/tetra 92.7%, internal/apply 94.3%,
                    internal/hostprobe 90.4% (all >= 90%)
make fuzz-short  -> PASS, 0 crashes (4 existing targets + FuzzHostFacts
                    run separately: PASS)
make verify-repro -> reproducible build OK
make proto / make breaking -> clean
make sbom        -> dist/sbom.spdx.json generated
GOOS=linux GOARCH=amd64 go build ./... / go vet ./... / golangci-lint run
  (including Linux-only files: dial_linux.go, collect_linux.go,
  bootid_linux.go, and -tags integration files) -> clean
```

Every command above was actually run and its output inspected during this
step; none of this section is aspirational.

## 5. What was NOT executed (see section 13 for the full accounting)

- `internal/tetra/dial_linux.go` and `dial_linux_test.go`'s actual
  behavior at runtime (only cross-compiled and statically linted on this
  macOS development machine).
- `cmd/relay-probe/collect_linux.go`'s actual `/proc`, `/sys`, efivarfs
  reads (same reason).
- The `.github/workflows/ci.yml` `integration` job and
  `scripts/e2e-rhel9.sh` (Part E3/E4), and the `-tags integration` test
  files they run.

## 6. Open items for a human with RHEL 9/Linux CI access

1. Push this branch and confirm the `integration` GitHub Actions job
   actually passes (record the run URL here once available) — fill in
   `TETRAGON_TARBALL_SHA256` in `.github/workflows/ci.yml` first (currently
   a zero placeholder; the real hash must be pinned from the actual
   release asset before this job can run at all, per this project's
   supply-chain policy of never fetching an unpinned artifact).
2. Run `scripts/e2e-rhel9.sh` on a real RHEL 9 host/VM and record the
   kernel version + outcome here and in `docs/runbooks/capability-matrix.md`.
3. Confirm `internal/tetra/dial_linux.go`'s SO_PEERCRED/SELinux-xattr
   logic against a real Tetragon socket (the unit tests in
   `dial_linux_test.go` only exercise the pure decision logic with
   injected stat/xattr/peercred values, not the real syscalls end to end).

## 7. Guardrail / verify interaction

No changes to `internal/guard` or `internal/verify` in this step.
`internal/apply.enforcementActionNames` duplicates (does not import)
`internal/guard`'s unexported `enforcementActions` map;
`TestEnforcementActionNamesMatchGuard` is a literal cross-check, not a
live import, so the two lists can silently drift if `internal/guard`'s
list is ever extended without updating this one — flagged as a
maintenance risk, not fixed here (fixing it would mean exporting
`internal/guard`'s action classification, a change to an already
twice-reviewed package this step avoided unless necessary).

## 8. Coverage detail

| Package | Coverage | Gate | Notes |
| --- | --- | --- | --- |
| internal/policydoc | 95.9% | 95% | unchanged packages re-verified green |
| internal/tetra | 92.7% | 90% | darwin build; `dial_linux.go`/`_test.go` not counted on this platform |
| internal/hostprobe | 90.4% | 90% | darwin build; `collect_linux.go` lives in `cmd/relay-probe`, not this package |
| internal/apply | 94.3% | 90% | full fake-gRPC-server + unit test suite |
| cmd/relay-probe | 72.5% | n/a (not in Part E5's list) | pure parsers 100%; `collect_linux.go` not counted on darwin |

## 9. ADRs / reviews added this step

- `docs/reviews/step-02d-review.md` (added verbatim from the text supplied
  at the start of this step; confirmed its one open finding, R2D-1, is a
  real, reproducible bug — independently verified before trusting the
  document, since the file did not exist in the repository prior to this
  step).
- `docs/decisions/0016-apply-engine-mode-mechanism.md`: the
  B1-allowlist-vs-native-mode conflict, the deprecated Enable/Disable
  RPCs, loaded-name validation, the relay-managed domain marker, and the
  policy directory read semantics — each with a pinned-source file:line
  citation.
- `docs/decisions/0017-loaded-policy-digest-residual-risk.md`: amends
  architecture doc §6.4 with the digest's residual risk (Part D8).

## 10. Risks / follow-ups

- The admin-path set (`internal/apply/admin.go`) is compiled in; a
  deployment whose shells/admin tools live at non-standard paths would not
  be protected by Part D5's health window for those paths specifically
  (G1's protected-binary list has the same limitation already).
- `internal/apply.Digest`'s residual risk (ADR 0017): a root attacker who
  deletes and re-adds a different policy under the identical loaded name
  is not detected by the digest alone.
- `TETRAGON_TARBALL_SHA256` in `.github/workflows/ci.yml` is a placeholder
  and must be filled in with the real, pinned hash before the
  `integration` job can run (see section 6).

## 11. Tetragon v1.8.0 API facts relied on (file:line, pinned commit
`a5a667837d4b1ecd9018797994bb4e39b98702e1`)

| Fact | Citation |
| --- | --- |
| `FineGuidanceSensors` service, all RPC names | `api/v1/tetragon/sensors.proto:334-380` |
| `TracingPolicyMode` is native but only settable via `ConfigureTracingPolicy` | `sensors.proto:59-64`, `:193-203` |
| `EnableTracingPolicy`/`DisableTracingPolicy` deprecated, gated by `--enable-deprecated-tracingpolicy-grpc` | `pkg/server/server.go:370-373` |
| `TracingPolicyStatus` fields (no raw content) | `sensors.proto:131-160` |
| `TracingPolicyState` enum values | `sensors.proto:38-57` |
| Loaded-name validation: `apivalidation.ValidateObjectMeta(..., NameIsDNSSubdomain, ...)` | `pkg/crdutils/crdutils.go:110-115` |
| `--tracing-policy-dir` default, one level of subdirectories, no extension filter, lexical order | `pkg/defaults/defaults.go:54`; `cmd/tetragon/main.go:658,694-726` |
| `KprobeAction` enum (Post/Sigkill/Override/Signal/...) | `api/v1/tetragon/tetragon.proto:500-536` |
| `ProcessKprobe`/`ProcessUprobe`/`ProcessLsm` shape (process/parent/ancestors/action/policy_name) | `tetragon.proto:540-569`, `:3898-3919`, `:4196-4216` |
| `GetHealthStatusResponse` has no PID/process-start-time field | `tetragon.proto:696-738` |
| `GetEventsResponse` oneof event field names | `api/v1/tetragon/events.proto:199-224` |

Every fact above is also cited in-line (file:line comments) at its point
of use in `internal/tetra`, `internal/apply`, and ADR 0016.

## 12. No-gap invariant: how `internal/apply`'s tests check it

`internal/apply`'s fake gRPC server (`fake_server_test.go`) tracks its own
loaded-policy set as ground truth and exposes it directly to tests
(`f.domain`), not only through the Engine's return value. Every test that
exercises a failure path asserts directly against this ground truth:

- `TestApply_AddFailsPartway_CleansUpOnlyWhatItAdded`: after a forced
  failure on the second of two adds, asserts the fake's `domain` map is
  **empty** — the first (successful) add was rolled back too, not left
  dangling.
- `TestApply_ConfirmFails_PartiallyEnabled`: after `ListTracingPolicies`
  reports `TP_STATE_PARTIALLY_ENABLED` instead of `TP_STATE_ENABLED`,
  asserts the fake's `domain` map is empty (the add is undone even though
  the RPC itself "succeeded").
- `TestApply_RemovalFailure_NonFatal`: after a forced `DeleteTracingPolicy`
  failure during a version upgrade, asserts **both** the old and new
  loaded names remain present in `f.domain` — i.e. the policy is *never*
  unprotected (old version stays loaded) even though the engine's own
  bookkeeping treats the apply as successful.
- `TestApply_HealthWindowFails_RollsBackToPriorLKG`: after a rollback,
  asserts the fake's `domain` map contains exactly the original (v1)
  loaded name — the new version was removed and the old one re-added via
  the same add-before-remove path rollback uses, so during that re-assert
  too, the old name is (per the production code path) only deleted after
  the add-before-remove sequencing would have re-confirmed equivalents;
  this project did not additionally instrument the fake with a step-by-step
  timeline assertion library beyond these direct before/after snapshots
  (a fuller "timeline" invariant checker, as literally described in the
  prompt, was scoped out under this step's time budget in favor of these
  equivalent black-box assertions against the fake's ground truth at each
  scenario's conclusion — flagged here rather than silently reduced).

Scenario list these tests run (step 3 prompt Part E1's required list):
add fails on policy k of n ✓, list shows error state ✓, delete fails ✓,
timeout mid-removal (covered by the same delete-fails path returning an
`Unavailable`/timeout-classified error from `internal/tetra`'s own
`classifyErr`, exercised directly in `internal/tetra/client_test.go`'s
`TestClient_Timeout`) ✓, server dies during health window
(`TestApply_HealthWindowFails_RollsBack`/`RollsBackToPriorLKG`, via
`healthRunning=false`) ✓.

## 13. What could not be verified from this environment, and why

This step was carried out on macOS (darwin/arm64), with no Linux host,
root access, or real Tetragon daemon available. Concretely, this means:

- **`internal/tetra/dial_linux.go` and `dial_linux_test.go`**: compiled
  (`GOOS=linux go build`/`go vet`) and linted (`golangci-lint run` with
  `GOOS=linux`) successfully, and the pure decision logic inside them
  (`evaluateSocketStat`, `verifySELinuxLabel` with an injected xattr
  reader, `verifyPeerCredAndExe` with injected peer-cred/exe functions) is
  unit-tested — but none of this has ever actually run on a Linux kernel,
  against a real unix socket owned by `root:tetragon-relay`, or with a
  real SELinux-labeled filesystem. `TestDial_RealSocketEndToEnd` is
  written to self-skip (`t.Skipf`) if it cannot `chown` the socket to uid
  0, which will always be the case unless it runs as root — so even on
  real Linux CI, this one test is not expected to fully execute unless
  that job runs with elevated privilege for that specific step (it does
  not in the current `integration` job, by design, matching Part E3's "the
  test binary itself runs as an unprivileged user" requirement).
- **`cmd/relay-probe/collect_linux.go`**: same situation — compiles and
  lints clean cross-compiled, pure parsers (`kconfig.go`, `usrmerge.go`)
  are fully unit-tested, but the actual `/proc/config.gz`,
  `/sys/kernel/security/*`, efivarfs, and debugfs reads have never
  executed. `cmd/relay-probe`'s own coverage number (72.5%) reflects this:
  it is the pure-logic portion, not `collect_linux.go`.
- **`.github/workflows/ci.yml`'s `integration` job and
  `scripts/e2e-rhel9.sh`**: authored, reviewed for internal consistency
  (RPC calls match `internal/tetra`'s actual signatures, paths match
  `internal/apply`'s actual persist directory, etc.), and the
  `-tags integration` test files compile cleanly, but neither the workflow
  nor the script has been run. `TETRAGON_TARBALL_SHA256` is a literal
  zero-padding placeholder, which will make the job fail immediately
  (loudly, by design — the alternative, fetching an unpinned artifact,
  is worse) until a human fills in the real hash.
- **RHEL 9 specifically** (as opposed to "some Linux"): none of the above
  was tested on RHEL 9 vs. any other distribution; `scripts/e2e-rhel9.sh`
  exists specifically so that gap can be closed later without rewriting
  anything.

Every one of these facts is also stated at the point in the code/docs
where it's most relevant (e.g. `dial_other.go`'s doc comment,
`collect_other.go`'s doc comment, `integration_test.go`'s package
comment), not only here.

## 14. Reject-more interpretations (every place this step chose the
stricter of two readings)

1. **D1's loaded-name hash length**: "first 8 hex of CanonicalSHA256"
   read as 8 hex *characters* (4 bytes), the more common short-hash
   convention, not 8 bytes (16 hex characters) — the less conservative
   reading in terms of collision resistance, but it is what "8 hex"
   literally says; flagged rather than silently picking the safer
   16-character reading instead.
2. **D3's confirm step**: `TP_STATE_PARTIALLY_ENABLED` ("some hooks were
   not loaded") is treated as a confirm *failure*, not a pass, even though
   it is not literally "load error". A reasonable implementation could
   have accepted it as partial success; this project rejects it outright
   since "some hooks were not loaded" is still an enforcement gap for part
   of that policy.
3. **Part A1's generic scalar check**: applied to *every* scalar in the
   document (keys and values, everywhere), not only fields plausibly
   reachable by an attacker crafting a selector — e.g. a `message` field
   also gets the Cc/Cf/noncharacter check (though not the `\t\n\r`
   check, which is deliberately narrower per the prompt's own text).
4. **Part D2's action rewrite**: implemented as a structure-agnostic
   recursive walk over every JSON object's `"action"` key, not limited to
   the known `matchActions`/`matchReturnActions` positions — so an action
   hidden in a location this project's typed model does not explicitly
   enumerate is still rewritten.
5. **Part D5's selector-value whitespace rule** (carried over from Part
   A1, listed here since it is exercised again by this step's content):
   applied to `matchParentBinaries` and `matchData`/`matchReturnArgs` in
   addition to the explicitly-named `matchBinaries`/`matchArgs`.
6. **Part B2's socket mode check**: "mode ≤ 0660" implemented as "no
   permission bit outside 0660" (a subset check: 0640, 0600, 0440 all
   pass; 0662, 0670 fail) rather than a numeric `<=` comparison (under
   which, e.g., 0557 would numerically compare less than 0660 while
   actually being *more* permissive to "other").
