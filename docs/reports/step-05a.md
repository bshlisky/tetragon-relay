# Step 5a report: TPM primitives (sealed key, monotonic counter, host signing key)

## 1. Summary

- Part A (step-04c-review.md follow-ups), both closed, one commit each:
  - **R4C-1**: `reverifyDomainLKG` no longer treats a missing `RawEnvelope`/`RootVersion`
    as a "pre-R4B-2 record" to skip; it is now `store.ErrTampered`, closing the fail-open
    branch the review identified.
  - **R4C-2**: `internal/trust` gained `(*Root).ProvenanceVerifier`, a signature check that
    ignores root metadata expiry (unlike `TargetsVerifier`); `reverifyDomainLKG` now uses it,
    so an expired historical root no longer skips the signature check — it is audited as
    staleness only. A module-wide AST test
    (`TestProvenanceVerifier_OnlyCalledFromAgentReverify`) enforces that only
    `internal/agent`'s re-verification ever calls it.
  - ADR 0025 moved from Proposed to Accepted, with a new "Amendments" section documenting
    both fixes. ADR 0024 was already Accepted.
- Part B: ADR 0026 records the architect decision to seal the store's HMAC key to the TPM
  **without** a PCR 7 policy — PCR 7 does not stop the offline-rescue-media attack it was
  meant for (a signed rescue image produces the same PCR 7), and would make every host's
  store unreadable after a routine Secure Boot `dbx` update. The TPM NV counter (Part C3) is
  the real rollback defense and is unaffected by this decision.
- Part C: new `internal/tpm` package, all four primitives built and tested against a real
  software TPM (swtpm), not a mock:
  - **C1**: `github.com/google/go-tpm` v0.9.8 (the `tpm2` "TPMDirect" API), vendored, ADR
    0027. Device access is a plain `transport.TPM`, so the same command-building code runs
    against the real `/dev/tpmrm0` (`OpenDevice`/`linuxtpm.Open`, no platform-specific build
    files needed) and against swtpm dialed over TCP in tests. CI installs swtpm and runs
    `internal/tpm`'s full suite for real (not skipped) on every push.
  - **C2 (KeySealer)**: first boot generates a 48-byte key, seals it under a
    deterministically-recreated SRK (ECC P-256, no persistent handle, ADR 0027 §4), persists
    the blob with the same write-temp/fsync/rename/fsync-dir discipline `internal/store`
    uses. `Unseal` re-derives the key from the TPM every call (never caches it); failure is
    the typed `ErrUnsealFailed`, distinct from `ErrSealedBlobMissing` and from
    `store.ErrTampered`.
  - **C3 (MonotonicCounter)**: a TPM NV counter at a fixed, documented owner-range handle
    (`0x01500020`). `ProvisionCounter` (owner-authorized, relay-probe only) is idempotent and
    refuses a pre-existing index with the wrong attributes; `OpenCounter`/`Read`/`Increment`
    (relayd, read/increment only) validate those same attributes on every open.
    `TestCounter_DeleteAndRedefineNeverGoesBackward` proves, against a real TPM, the
    spec-cited guarantee that a counter re-initializes to the highest value any counter ever
    held on that TPM, so delete+redefine can never roll it back (section 12).
  - **C4 (HostSigner)**: a `crypto.Signer` backed by a non-exportable (fixedTPM, fixedParent,
    sensitiveDataOrigin, sign-only) ECC key, P-384 preferred via `TPM2_TestParms` detection,
    P-256 fallback (ADR 0028), never a software key. Rotation creates a new key at a new blob
    path without touching the old one; `RetireHostSigner` is a separate, explicit removal.
    `TPM2_Duplicate` is proven to fail against the key (non-exportability).
  - **C5**: `internal/agent.BuildTPMComponents` is the only place `internal/agent`'s non-test
    code constructs a `store.KeySealer`/`store.MonotonicCounter`; there is no runtime flag
    that selects the fakes instead. It takes an already-open TPM connection (rather than
    opening `/dev/tpmrm0` itself) so its logic is fully unit-testable against swtpm; the
    device-open step — and the "refuse to start without a TPM" behavior — is relayd `main()`'s
    job (step 6, not yet built; see "Known limitations").
- Part D: `internal/tpm/store_roundtrip_test.go` is the required D1 round-trip: a genuine
  `internal/store.Store` opened against the real `*tpm.KeySealer`/`*tpm.Counter`, surviving a
  simulated restart, plus a test proving a restored older backup of the store directory is
  detected as tamper via the real TPM counter. CI installs swtpm and gates `internal/tpm` at
  ≥90% coverage (D4); `scripts/e2e-rhel9.sh` gained a TPM section (D3, section 13).
- No deviations from the architecture beyond what ADR 0026 explicitly supersedes (the PCR 7
  clause in section 8.11, Part B's whole point). One new third-party dependency:
  `github.com/google/go-tpm` v0.9.8 (ADR 0027).

## 2. File tree of what was added or changed (since 742bfa3)

```
.github/workflows/ci.yml                     (+swtpm install, +internal/tpm coverage gate, +verbose real-TPM run)
Makefile                                     (+tpm-test, +coverage-tpm targets)
docs/
  decisions/0025-lkg-raw-envelope.md         (Proposed -> Accepted, +Amendments section: R4C-1/R4C-2)
  decisions/0026-store-key-sealing-without-pcr-policy.md       (new, Accepted)
  decisions/0027-tpm-library-and-software-tpm.md               (new, Accepted)
  decisions/0028-host-signing-key-curve-fallback.md            (new, Accepted)
  prompts/step-05a.md                        (new, committed verbatim)
  reports/step-05a.md                        (this file)
  reviews/step-04c-review.md                 (new, committed verbatim)
cmd/
  relay-probe/main.go, main_test.go          (+--provision-tpm, --tpm-device)
internal/
  agent/
    tpmwiring.go                             (new: BuildTPMComponents, ErrTPMRequired)
    tpmwiring_internal_test.go               (new, real swtpm)
    reverify.go, reverify_test.go            (R4C-1, R4C-2 fixes + regression tests)
  trust/
    root.go                                  (+ProvenanceVerifier)
    trust_test.go                            (+TestRoot_ProvenanceVerifier_IgnoresExpiry)
    provenance_restriction_test.go           (new: AST-based call-site restriction)
  tpm/                                        (new package)
    doc.go, errors.go, device.go, srk.go, seal.go, counter.go, signer.go
    swtpm_test.go                            (new: per-test swtpm launcher)
    fault_test.go, fault_paths_test.go       (new: faultTPM/alwaysFailCommand fault injection)
    seal_test.go, counter_test.go, signer_test.go
    coverage_extra_test.go, coverage_extra2_test.go, coverage_extra3_test.go
    store_roundtrip_test.go                  (new: D1 round-trip + rollback test)
    e2e_real_device_test.go                  (new, build tag tpm_e2e: real-device round trip)
packaging/systemd/
  tetragon-relay.service                     (+ExecStartPre=+relay-probe --provision-tpm)
  unit_test.go                               (+TestProductionUnit_ProvisionsTPMBeforeHostFacts)
scripts/e2e-rhel9.sh                         (+TPM section)
go.mod, go.sum, vendor/github.com/google/go-tpm/...  (new dependency, vendored)
```

## 3. Command output

### Local verification (macOS/Darwin, this development machine, with swtpm installed via Homebrew)

Unlike prior steps, this machine has `swtpm` installed (`brew install swtpm`), so
`internal/tpm` and `internal/agent`'s new tests ran for real locally, not just on GitHub
Actions.

```
$ gofmt -l $(...); goimports -l $(...)                       # clean
$ go vet ./...; go vet -tags tpm_e2e ./internal/tpm/...       # clean
$ golangci-lint run ./...                                     # 5 pre-existing unused findings, internal/tetra/_linux.go only (unchanged from step-04c)
$ govulncheck ./...                                            # No vulnerabilities found
$ go mod verify; make vendor-check; make verify-crd; make verify-tetragon-api   # all OK
$ go build ./...; go build -tags tpm_e2e ./internal/tpm/...    # clean
$ go test ./...                                                 # ok, all packages (internal/tpm: 30s, real swtpm)
$ make tpm-test                                                 # 36 tests, all PASS against real swtpm
$ make coverage                                                 # all >=95% (see table)
$ make coverage90                                               # internal/tetra 86.0% (pre-existing, macOS-only; unchanged from step-04c);
                                                                 # apply/hostprobe/agent all pass (agent: 90.9%, with swtpm)
$ make coverage-tpm                                             # internal/tpm: 91.5% (>=90%)
```

GitHub Actions (authoritative) run numbers are in the table below.

### Per-package coverage (`go test -cover`, this run)

| Package | Coverage | Gate |
| --- | --- | --- |
| internal/dsse | 100.0% | ≥95% |
| internal/strictjson | 98.5% | ≥95% |
| internal/trust | 95.3% | ≥95% |
| internal/verify | 99.5% | ≥95% |
| internal/policydoc | 95.9% | ≥95% |
| internal/guard | 96.8% | ≥95% |
| internal/store | 95.7% | ≥95% |
| internal/tetra | 86.0% local (linux-only tests excluded on darwin) / passing on GitHub Actions | ≥90% |
| internal/apply | 92.1% | ≥90% |
| internal/hostprobe | 90.4% | ≥90% |
| internal/agent | 90.9% | ≥90% |
| **internal/tpm** | **91.5%** | **≥90% (new, D4)** |

### GitHub Actions run numbers (this step's commits, branch `main`)

| Commit | ci | integration |
| --- | --- | --- |
| `85831a8` docs: step 4c review + step 5a prompt | 45560677332 success | (docs-only) |
| `f388054` trust: ProvenanceVerifier | — (pushed with the next) | — |
| `8e94570` R4C-1/R4C-2 fixes | — (pushed with the next) | — |
| `a786573` ADR 0025 Accepted | 45560677332 success (covers all three above) | — |
| `6f64402` ADR 0026 | — (pushed with the next) | — |
| `f714cf7` TPM primitives (Part C1-C4) | 45564433490 success | — |
| `f7d7ca5` C5/D1 wiring | — (pushed with the next) | — |
| `af87735` relay-probe --provision-tpm | — (pushed with the next) | — |
| `c7a9a6c` CI: install swtpm, coverage-tpm | 45566370848 **failure (YAML syntax)** | — |
| `fcb2872` CI: fix YAML syntax error | 45566488392 success | — |
| `a3da005` e2e-rhel9.sh TPM section (**final commit**) | 45567145960 success | **45567145960 success** |

The one red run (`45566370848`) was a YAML syntax error in a new step name (an unquoted
colon-quote sequence), caught immediately by GitHub's pre-flight workflow-file check (the job
never started) and fixed in the very next commit; no test or gate ever failed.

### Fuzz, benchmarks, govulncheck

No fuzz target's seed corpus or behavior changed this step; `make fuzz-short` ran clean on
every green `ci` run in the table above. No new benchmarks. `govulncheck` reports no
vulnerabilities, locally and on every green `ci` run, including with the new `go-tpm`
dependency.

## 4. Mapping: item → functions → tests

| Item | Functions | Tests |
| --- | --- | --- |
| R4C-1 (missing raw envelope is tamper) | `reverifyDomainLKG` | `TestStartup_ReverifyLKG_NoRawEnvelopeIsTampered`, `TestStartup_ReverifyLKG_ZeroRootVersionIsTampered` |
| R4C-2 (ProvenanceVerifier) | `(*trust.Root).ProvenanceVerifier`, `reverifyDomainLKG` | `TestRoot_ProvenanceVerifier_IgnoresExpiry`, `TestStartup_ReverifyLKG_ExpiredHistoricalRootStillVerifiesAndSucceeds`, `TestStartup_ReverifyLKG_ExpiredHistoricalRootStillDetectsTamper`, `TestProvenanceVerifier_OnlyCalledFromAgentReverify` |
| C1 (TPM access, swtpm) | `OpenDevice`, `startSWTPM` (test helper) | every test in `internal/tpm`, all against a real swtpm |
| C2 (KeySealer) | `NewKeySealer`, `(*KeySealer).Unseal`, `sealedObjectTemplate`, `writeFileAtomic` | `TestKeySealer_*` (12 tests: round trip, missing/corrupt/tampered blob, CreateSRK/seal/load/unseal command failures) |
| C3 (MonotonicCounter) | `ProvisionCounter`, `OpenCounter`, `(*Counter).Read/Increment`, `validateCounterIndex` | `TestCounter_*`, `TestProvisionCounter_*` (10 tests: provision/open/read/increment, delete+redefine, attribute mismatch, every command-failure path) |
| C4 (HostSigner) | `NewOrLoadHostSigner`, `detectSigningCurve`, `(*HostSigner).Sign`, `RotateHostSigner`, `RetireHostSigner` | `TestHostSigner_*`, `TestDetectSigningCurve_*`, `TestSign_*`, `TestLoadHostSigner_*` (14 tests: sign+verify, persistence, non-duplicable, rotation/retire, P-384/P-256/neither detection, every command-failure path) |
| C5 (agent wiring) | `agent.BuildTPMComponents` | `TestBuildTPMComponents_*` (3 tests, real swtpm) |
| D1 (store round trip) | `store.Open` with `*tpm.KeySealer`/`*tpm.Counter` | `TestStoreRoundTrip_RealSealerAndCounterSurviveSimulatedRestart`, `TestStoreRoundTrip_RollbackOfOlderCopyIsDetectedViaRealCounter` |
| D2 (fault tests) | `faultTPM`, `alwaysFailCommand` (test decorators) | 20 tests forcing `CreatePrimary`/`Create`/`Load`/`Unseal`/`NVDefineSpace`/`NVIncrement`/`NVRead`/`NVReadPublic`/`TestParms`/`Sign` to fail individually |
| C3 provisioning (relay-probe) | `provisionTPMCounter` | `TestRun_ProvisionTPM_MissingDeviceFails`; `TestProductionUnit_ProvisionsTPMBeforeHostFacts` |
| D3 (e2e) | `TestTPMRealDeviceRoundTrip`, `TestHostSignerRealDeviceCurveDetection` (build tag `tpm_e2e`) | run only by `scripts/e2e-rhel9.sh`'s new TPM section |

## 5. Invariants and threats addressed

- **T-13/T-24 extended to the store HMAC key and host identity key**: the HMAC key is now
  genuinely TPM-sealed (not a fake), closing the step-04b/04c "everything in `internal/store`
  still sits behind fake interfaces" limitation for `KeySealer`. The host signing key
  (step 5b's mTLS client will consume it) is created non-exportable from day one.
- **Rollback protection (step-04b's primary invariant) is now backed by a real TPM NV
  counter**, not `FakeMonotonicCounter`: `TestStoreRoundTrip_RollbackOfOlderCopyIsDetectedViaRealCounter`
  is the first evidence this project has that the actual rollback defense — not just its
  interface contract — holds against a real TPM.
- **A missing or falsified sealed/counter index is distinguished from store tampering**:
  `ErrUnsealFailed`/`ErrSealedBlobMissing` (KeySealer) and `ErrCounterNotProvisioned`/
  `ErrNVIndexAttributeMismatch` (Counter) let an operator tell "TPM or provisioning problem"
  apart from "store contents altered," while `internal/store`/`internal/agent` still treat
  either as fail-closed (docs/prompts/step-05a.md C2's own requirement).
- **ADR 0026 corrects a design that would have failed BOTH ways**: PCR 7 sealing neither
  stopped the attack it was meant for (signed rescue media) nor tolerated routine, desirable
  maintenance (`dbx` updates) — this step replaces it with a design whose actual security
  property (key cannot be used off this TPM) and actual rollback defense (the NV counter) are
  both still intact and independently testable.

## 6. Deviations from this prompt or the architecture

- **CI job placement (C1/D1)**: the prompt offers "a TPM job (or a step in integration)"; this
  step adds the swtpm install and `internal/tpm`'s steps to the existing `ci` job instead of
  either. Reason: `internal/agent`'s own pre-existing `coverage90` gate (step 4b, unrelated to
  this step) already runs inside `ci`, and this step's new `internal/agent` tests
  (`BuildTPMComponents`) need swtpm to clear that gate — installing swtpm once, in `ci`, keeps
  both internal/tpm's own gate and internal/agent's pre-existing one correct without
  duplicating the install step across two jobs or needing `integration`'s real-Tetragon
  machinery (an unrelated concern) to also carry a TPM dependency.
- **Architecture doc 8.11's section numbering vs. the prompt's "8.10"**: the prompt's Part B
  cites "architecture 8.10" for the PCR 7 sealing sentence; the current `docs/architecture.md`
  has that sentence in section 8.11 ("Self-protection and tamper evidence"), not 8.10
  ("Telemetry pipeline inside the agent") — the document's own section numbers shifted since
  the prompt was written against an earlier revision. ADR 0026 cites the correct, current
  section (8.11) and quotes the sentence verbatim so there is no ambiguity about which text
  it supersedes.
- No other deviations. R4C-1/R4C-2 were implemented exactly as the review specified; ADR 0026
  was written and reasoned through before any TPM code was written, per the working
  agreement's "when a finding changes the design, stop and ask" (Part B's PCR-7 reversal is
  exactly that kind of design-changing finding, and it is the architect's OWN instruction in
  this prompt, not a deviation this session introduced unilaterally).

## 7. Dependencies added

| Dependency | Why | ADR |
| --- | --- | --- |
| `github.com/google/go-tpm` v0.9.8 | TPM 2.0 command/response encoding (the `tpm2` "TPMDirect" API) and device transports (`linuxtpm`, `tcp`) | ADR 0027 |

Vendored under `vendor/github.com/google/go-tpm/`. No cgo; no `go-tpm-tools` (ADR 0027
explains why swtpm was chosen over that cgo-based alternative).

## 8. Known limitations

- **`BuildTPMComponents` has no real caller yet.** Like ADR 0023's `Reenroller`, this step
  builds the interface and its full logic (tested against a real TPM) ahead of the component
  that will call it in production: relayd's `main()` (step 6) must call
  `tpm.OpenDevice("/dev/tpmrm0")`, pass the result to `agent.BuildTPMComponents`, and refuse
  to start if either step fails. This step cannot demonstrate that refusal end-to-end because
  `cmd/relayd` is still the step-1 stub (`main.go`: "not yet implemented beyond --version").
- **SPIRE node attestation, X.509-SVID enrollment, and the mTLS client are out of scope**
  (step 5b, as the prompt specifies) — `HostSigner` is built and tested as a standalone
  `crypto.Signer`, but nothing yet constructs a `tls.Certificate` from it or dials anything.
- **TPM-based remote attestation (PCR quotes) is out of scope** (5b or later, per the
  prompt); this step's TPM usage is entirely local (sealing, counting, signing), never
  attesting the host's boot state to a remote verifier.
- **`internal/agent`'s real-TPM tests depend on `swtpm` being on `PATH`**, same as
  `internal/tpm`'s own tests: they `t.Skip` (not fail) without it. CI always installs it
  (section 3); a local `go test ./...` run without `swtpm` installed will skip these specific
  tests rather than fail, which is by design (docs/decisions/0027) but means a contributor
  without `swtpm` locally will not see `internal/agent`'s `coverage90` gate's true number
  until CI runs.
- **`internal/tpm/e2e_real_device_test.go` has never been executed** (build tag `tpm_e2e`,
  requires real hardware or a vTPM this development environment does not have) — see section
  13.
- Every known limitation from `docs/reports/step-04c.md` section 8 not specifically closed
  above (the relayd `main()` orchestration gaps, `internal/apply.Engine` not itself calling
  `RecordEpoch`/`RecordMonitorNames`) is unchanged by this step.

## 9. Open questions for the architect

1. `BuildTPMComponents` takes an already-open `transport.TPM` rather than a device path, so
   its own logic is fully unit-testable against swtpm (section 8). Is the resulting split —
   `internal/tpm.OpenDevice` (thin, real-hardware-only) vs. `agent.BuildTPMComponents`
   (fully tested) — the right boundary for step 6's relayd `main()` to build against, or
   should `internal/agent` own the device-open call itself (accepting that
   `OpenRealTPMComponents`-shaped code would then carry an untestable branch, as an earlier,
   reverted version of this step's code did)?
2. ADR 0026 (no PCR policy) relies on the TPM NV counter, not sealing, as the actual
   rollback defense. Should a future ADR revisit binding the counter's own NV index
   definition to a policy (e.g. requiring platform authorization in addition to owner
   authorization) as defense in depth against an attacker who has both root AND can reach the
   TPM's owner hierarchy, or is that explicitly out of scope given T-02/T-04's existing "root
   on the host is out of scope" posture?
3. Host facts (architecture doc `Hello` message) do not yet carry `HostSigner.Curve()` (ADR
   0028): this step builds the primitive and notes the wiring is step 5b's job (the mTLS
   client that actually sends `Hello`). Should a placeholder field be reserved in the
   `Hello`/host-facts schema now, so step 5b does not need a proto/schema-widening step of
   its own just for this one field?

## 10. Self-review: 5 places a reviewer is most likely to find a bug

1. **`Counter.Read`'s "unwritten index reads as 0" special case** (`counter.go`): correct
   per the TPM 2.0 spec (an unwritten counter would otherwise fail `TPM2_NV_Read` with
   `TPM_RC_NV_UNINITIALIZED`), and tested (`TestCounter_ProvisionOpenReadIncrement`'s
   "factory value" assertion), but it means `Read()` cannot distinguish "genuinely never
   incremented" from a hypothetical future TPM/firmware bug that cleared the `Written` bit
   on an index that WAS previously incremented — the only defense against that specific
   scenario is `internal/store`'s own generation-vs-counter comparison catching the
   resulting mismatch as tamper, not anything in this package.
2. **`KeySealer`/`HostSigner` both re-create the SRK and re-load the target object on EVERY
   call** (`seal.go`, `signer.go`): this is deliberate (C2: "keep it in one place only," and
   avoids caching a loaded object handle across calls that a concurrent TPM user could flush
   out from under this process), but it means every `Unseal`/`Sign` call is several TPM round
   trips, not one — a reviewer focused on relayd's apply-path latency budget (architecture
   doc 8.13: "< 3s excluding health window") should confirm this does not become a bottleneck
   once wired into the actual apply path, which this step does not exercise end to end.
3. **`counterAttributesMatch`'s explicit field-by-field comparison, deliberately excluding
   `Written`/`*STClear` bits** (`counter.go`): correct (section 10 item 1's own caveat
   notwithstanding), but a future TPM attribute this package does not yet know about (a new
   `TPMA_NV` bit from a spec revision) would silently NOT be checked, since this function
   enumerates fields rather than comparing the whole struct — a deliberate choice (comparing
   the whole struct would reject on `Written` changing, which is expected/dynamic) but one a
   reviewer should re-verify against the TPM 2.0 spec's current `TPMA_NV` definition if this
   package is ever updated for a new go-tpm version.
4. **`faultTPM`/`alwaysFailCommand`'s command-code detection reads bytes `cmd[6:10]` directly**
   (`fault_test.go`): this hardcodes the TPM command header's layout (tag 2 bytes, size 4
   bytes, command code 4 bytes) rather than using any go-tpm-exposed parsing helper (none
   exists at this layer); if a future go-tpm major version changes this on-wire layout (it
   will not, since it is the TPM 2.0 spec's own fixed header, not a go-tpm implementation
   detail), these test helpers would need updating, not production code.
5. **`BuildTPMComponents`'s lack of a real caller** (section 8): the function and its tests
   are a reasonable bet on what step 6's relayd `main()` will need, but until that code
   exists, there is no end-to-end evidence that "agent refuses to start without a TPM in
   production" actually holds — only that the two pieces it depends on
   (`tpm.OpenDevice`'s error return, `agent.BuildTPMComponents`'s error return) are each
   individually correct.

## 11. TPM implementation used in CI and the TPM facts it reported

- **Implementation**: swtpm (software TPM, `github.com/stefanberger/swtpm`), installed via
  `apt-get install -y swtpm swtpm-tools` on the `ci` job's `ubuntu-24.04` runner (ADR 0027
  explains the choice over the cgo-based `go-tpm-tools` simulator). Each test in
  `internal/tpm`/`internal/agent` spawns its own swtpm subprocess with an isolated
  `t.TempDir()` state directory and ephemeral TCP ports, dialed via
  `github.com/google/go-tpm/tpm2/transport/tcp`.
- **TPM facts** (from this swtpm instance, as exercised by the test suite):
  - Manufacturer/firmware: not queried via `tpm2_getcap` in CI (that tool is not installed
    there; it is swtpm's own built-in libtpms core, version matching whatever
    `apt-get install swtpm` resolves to on `ubuntu-24.04` at the time of the run — not a
    meaningful "manufacturer" in the hardware-TPM sense).
  - Supported ECC curves: both P-384 and P-256 (`TestDetectSigningCurve_PrefersP384`,
    `TestDetectSigningCurve_FallsBackToP256WhenP384Unavailable` — the latter forces a
    simulated P-384-unavailable condition via fault injection, since this particular swtpm
    build genuinely supports both).
  - NV counter behavior: confirmed spec-compliant (section 12).

## 12. NV-counter deletion/redefinition citation and test result

**Citation**: Will Arthur, David Challener, Kenneth Goldman, *A Practical Guide to TPM 2.0*
(Apress, 2015), Chapter 11, "NV Indexes," "NV Counter Index": "An NV counter is a 64-bit
value that can only increment. At the beginning of the first increment command, it's
initialized to the largest value that any counter has ever had on the TPM. This includes
counter indexes currently defined and counters that were defined in the past but are no
longer on the TPM. Thus a counter can never roll back, even by deleting and re-creating the
index." This matches the TCG Trusted Platform Module Library Specification, Family "2.0,"
Part 1 (Architecture)'s own description of NV counter semantics (the "largest value any
counter has ever held" global-monotonicity rule), which the book's authors (two of whom are
TPM 2.0 spec editors) are restating in prose.

**Test result**: `TestCounter_DeleteAndRedefineNeverGoesBackward`
(`internal/tpm/counter_test.go`) provisions a counter, increments it three times, then
`TPM2_NV_UndefineSpace`s and re-`ProvisionCounter`s (redefines) the same index, and asserts
the next `Increment()` returns a value strictly greater than the value immediately before the
delete. **PASS**, against a real TPM 2.0 implementation (swtpm): the guarantee holds as
cited, confirmed empirically, not just assumed from the spec text.

## 13. Whether e2e-rhel9.sh's TPM section was run, and on what hardware

**Not run.** This development environment (macOS, no RHEL 9 host/VM, no physical TPM or
configured vTPM proxy device) cannot execute `scripts/e2e-rhel9.sh` at all (consistent with
every prior step's report — see docs/reports/step-03.md section 13 — this script has never
been executed as part of this project's work). The TPM section specifically
(`internal/tpm/e2e_real_device_test.go`, build tag `tpm_e2e`) additionally requires a real
TPM 2.0 device or vTPM at `/dev/tpmrm0` (or `$TPM_E2E_DEVICE`), which this session's swtpm
(a userspace TCP-socket TPM, not exposed as a `/dev` node) also does not provide. Running
this script — both its pre-existing Tetragon integration section and this step's new TPM
section — on real RHEL 9 hardware/VM access (with a physical TPM 2.0 or a configured vTPM
proxy device) remains an explicit remaining action item for whoever has that access,
exactly as it has been since step 3.
