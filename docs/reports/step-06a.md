# Step 6a report (partial): First actions, Part A, Part B (+B6/B7), Part C, Part D

Per docs/prompts/step-06a.md's working agreement ("session size: if the work clearly will
not fit one session, finish a coherent part, get CI green, write the report for what is
done, and stop. Never stop mid-item"): First actions, Part A (A1-A3), Part B (the config
loader, plus the architect's two follow-up hardening items B6/B7), Part C (relayd
assembly) and Part D (the state machine and control-message dispatcher) are complete,
each commit green on GitHub (ci + integration). Part E (beyond B5's FuzzConfig, already
done) -- state-machine/handler unit tests are already included with D above, but
`cmd/testcontroller` scripted multi-message sequences (E2) and the E3 systemd-sandbox
integration suite are **not yet done** -- see section 9.

## 0. Updates since the first partial report

- **B6** (architect review): `internal/config.Load` now opens relay.yaml with
  `O_NOFOLLOW` and performs every check (regular file, mode, owner, group) against the
  open file descriptor's `Stat()`, not a separate path-based `Lstat`/`Stat` pair -- closing
  the check-then-open race the original implementation left.
- **B7** (architect review): `internal/config.Load` additionally refuses an
  attacker-writable or non-root-owned parent directory, opened the same descriptor-based
  way (`O_DIRECTORY|O_NOFOLLOW`).
- **Part D1**: `internal/agent.StateMachine`, a table-driven implementation of
  architecture doc 8.3/8.4's ten states, transcribed edge for edge, plus one documented
  extension (`EventDegradedCondition`) for D2's explicit cert-expiry rule.
- **Part D2**: `internal/agent.ControlLoop.HandleControllerMessage`, the message
  dispatcher for every member of `ControllerMessage`'s closed oneof, ADR 0032's seq
  enforcement (`SeqTracker`), `BuildHeartbeat`, and `CheckCertExpiry`.
- **Part C**: `cmd/relayd/main.go` assembles the startup sequence this repository's
  components already implement into a running process, with production-only TPM-device
  and no-test-enroller restrictions (C2/C3) and `sd_notify`/watchdog/clean-shutdown (C4).

See sections 2-8 below for the full, updated detail (file tree, command output, mapping,
invariants, deviations, dependencies, limitations) covering every item above; section 9
lists exactly what remains.

## 1. Summary

- **First actions**: committed `docs/prompts/step-06a.md` and
  `docs/reviews/step-05b-review.md` verbatim (`4992be9`); confirmed `make ci` reproduces the
  one pre-existing, documented, macOS-only lint finding (`internal/tetra/config.go`'s five
  `unused` findings, unchanged since step-04c, green on GitHub Actions) before any change.
- **A1 (R5B-1)**: `internal/controlclient.Config` now has a required `Clock func()
  time.Time` field; `VerifyConnection` uses it as `x509.VerifyOptions.CurrentTime` instead
  of the zero value. New boundary tests cover not-yet-valid, exactly-`NotBefore`,
  mid-validity, exactly-`NotAfter`, and just-expired.
- **A2 (Q2)**: ADR 0031 (Accepted) records that Go's `crypto/tls` with `VerifyConnection`
  is the long-term control-channel TLS implementation (no code change; see docs/reviews/
  step-05b-review.md's own answer).
- **A3 (Q3)**: ADR 0032 (Accepted) pins `seq` numbering: the first message on a stream is
  `seq = 1`, every following message is exactly the previous plus 1, per direction.
  `internal/testcontroller.Server.Connect` enforces this on the first `AgentMessage`
  (`Terminate{PROTOCOL_ERROR}` otherwise) and sends its own first message at `seq = 1`.
  `docs/server-contract.md` sections 1.1, 4 and 8 are updated accordingly. Full enforcement
  of every later message needs the multi-message control loop (agent side: Part D, not yet
  built).
- **B (config loader)**: new `internal/config` package. `Load` refuses to read
  `relay.yaml` unless it is a regular file, not a symlink, owned by root, group
  `tetragon-relay`, mode no more permissive than `0640`. Parsing reuses a newly extracted
  `internal/yamlharden` package (the hardened YAML ingestion rules, moved out of
  `internal/policydoc` with no behavior change -- see section 6), then a strict
  (`KnownFields`) typed decode so the schema is closed. Every required field has no
  default; `Config.Digest()` is the SHA-256 of the exact bytes read
  (`Hello.config_digest`); `Config.SecurityRelaxations()` reports any configured setting
  that relaxes a security check.

## 2. File tree of what was added or changed (since `440b7a0`)

```
docs/
  decisions/0031-go-crypto-tls-verifyconnection-long-term.md   (new, Accepted)
  decisions/0032-seq-numbering-starts-at-one.md                (new, Accepted)
  prompts/step-06a.md                                          (new, committed verbatim)
  reviews/step-05b-review.md                                   (new, committed verbatim)
  reports/step-06a.md                                          (this file)
  server-contract.md                                           (A3: seq rule updated)
internal/
  controlclient/
    config.go, config_test.go           (+Clock field, ErrNoClock)
    tlsconfig.go, tlsconfig_test.go     (+clock boundary tests)
    client_test.go, integration_test.go (+Clock: time.Now at every call site)
  testcontroller/
    server.go, server_test.go           (A3: first-seq enforcement + test)
  yamlharden/                            (new package, extracted from internal/policydoc)
    doc.go, errors.go, harden.go, harden_internal_test.go
  policydoc/
    yamlharden.go                       (now a thin delegate to internal/yamlharden)
    errors.go                           (B1 sentinels now alias internal/yamlharden's)
    internal_test.go, unit_test.go      (4 white-box walker tests moved to internal/yamlharden)
  config/                                (new package)
    doc.go, errors.go, schema.go, load.go, validate.go
    load_test.go, validate_test.go, fuzz_test.go
  limits/limits.go                      (+MaxConfigFileBytes, MaxConfigFileMode,
                                          DefaultHeartbeatInterval, DefaultCollector*,
                                          DefaultIdentityKeyRotation)
Makefile                                 (+FuzzConfig in fuzz-short; internal/config in
                                          COVER90_PKGS)
.github/workflows/nightly-fuzz.yml       (+FuzzConfig matrix entry)
internal/
  config/
    load.go, load_test.go, errors.go     (B6: O_NOFOLLOW descriptor-based checks;
                                          B7: checkParentDir/validateParentDirInfo)
    fileinfo_stub_test.go                (new: synthetic os.FileInfo for owner/group
                                          branch coverage without root)
  agent/
    state.go, state_test.go              (new: Part D1 StateMachine)
    controlloop.go, controlloop_test.go  (new: Part D2 ControlLoop dispatcher)
    snapshot.go, snapshot_test.go        (new: RealSnapshotProvider)
    identityrotator.go, identityrotator_test.go (new: RealIdentityRotator)
cmd/relayd/
  main.go                                (Part C: full startup sequence assembly)
  certutil.go                            (new: PEM cert-bundle loader)
  sdnotify.go                            (new: minimal sd_notify, no new dependency)
  tpmdevice.go, tpmdevice_const.go,
  tpmdevice_testtpm.go                   (new: C3's production-vs-testtpm TPM device policy)
  enroller.go                            (new: C2's always-refuses noEnroller)
```

## 3. Command output

```
$ gofmt -l $(...); goimports -l $(...)                         # clean
$ go vet ./...                                                  # clean
$ golangci-lint run ./...                                       # 5 pre-existing unused
                                                                  # findings, internal/tetra
                                                                  # only (macOS-only,
                                                                  # unchanged since step-04c;
                                                                  # GitHub Actions ci is green)
$ golangci-lint run ./internal/controlclient/... ./internal/testcontroller/...
  ./internal/yamlharden/... ./internal/policydoc/... ./internal/config/... ./internal/limits/...
  # 0 issues
$ govulncheck ./...                                              # No vulnerabilities found
$ go build ./...; go test ./...                                  # ok, all packages
$ go test -run=NONE -fuzz=FuzzConfig -fuzztime=10s ./internal/config/...   # no crashes found
$ make coverage90
  internal/tetra           (unchanged)
  internal/apply           (unchanged)
  internal/hostprobe       (unchanged)
  internal/agent           (unchanged)
  internal/identity        (unchanged)
  internal/controlclient   96.9%  (clock injection added no uncovered branch)
  internal/config          92.6%  (new, >=90%)
$ go test -count=1 -covermode=count -coverprofile=/tmp/pd.out ./internal/policydoc/...
  total: 95.6%   (unchanged gate, >=95%; proves the yamlharden extraction did not regress
                   policydoc's own coverage or behavior)
```

### GitHub Actions run numbers (this step's commits, branch `main`)

| Commit | ci | integration |
| --- | --- | --- |
| `4992be9` docs: step 5b review + step 6a prompt | (pending at time of writing; docs-only) | — |
| `8a201cd` A1: clock injection | 45634885077 success | 45634885077 success |
| `f9c78f1` A2: ADR 0031 | (docs-only; bundled with next push) | — |
| `6d53964` A3: seq pinning | 45635641617 success | 45635641617 success |
| `9b231a3` B2: yamlharden extraction | 45637254652 success | 45637254652 success |
| `bcec04e` B: config loader | 45639114690 success | 45639114690 success |
| `1376ff1` B6: O_NOFOLLOW descriptor checks | 45681050094 success | 45681050094 success |
| `42b736e` B7: parent directory checks | 45681283349 success | 45681283349 success |
| `4605d43` D1: state machine | (bundled with D2's push) | — |
| `4e92677` D2: control loop dispatcher | 45682914393 success | 45682914393 success |
| `d815833` C: relayd assembly | 45684683356 success | 45684683356 success |

## 4. Mapping: item -> functions -> tests

| Item | Functions | Tests |
| --- | --- | --- |
| A1 (clock injection) | `controlclient.Config.Clock`, `BuildTLSConfig`'s `VerifyConnection` | `TestVerifyConnection_ClockBoundaries`, `TestConfig_Validate/no_clock` |
| A2 (ADR 0031) | n/a (docs only) | n/a |
| A3 (seq pinning) | `testcontroller.firstSeq`, `(*Server).Connect`'s seq check | `TestConnect_FirstSeqMustBeOne` (3 subtests) |
| B2 (yamlharden extraction) | `yamlharden.Parse` and its unexported helpers; `policydoc.parseHardenedYAML` (now a delegate) | `internal/yamlharden`'s own white-box suite (moved verbatim); `internal/policydoc`'s full, unmodified black-box `Parse` suite (95.6% coverage, unchanged gate) |
| B1 (file source checks) | `config.checkFileSourceable`, `readConfigFile` | `TestCheckFileSourceable_*` (8 tests, 2 root-gated and skipped on a non-root runner), `TestReadConfigFile_*` |
| B2 (parsing, this package) | `config.parse` (yamlharden + strict yaml.v3 decode) | `TestParse_UnknownField_Rejected`, `TestParse_UnknownNestedField_Rejected`, `TestParse_NotAMapping_Rejected`, `TestParse_Empty_Rejected`, `TestParse_AmbiguousUnquotedScalar_Rejected` |
| B3 (schema/required fields) | `config.validateAndBuild` and its per-section helpers | `TestValidateAndBuild_EveryRule` (24 subtests, one per rejection), `TestValidateAndBuild_OptionalPositiveOverridesAccepted`, `TestParse_ValidConfig_DefaultsApplied` |
| B4 (config digest) | `(*Config).Digest` | `TestParse_Digest_IsSHA256OfExactBytes` (including a copy-not-alias check) |
| B5 (fuzz) | `FuzzConfig` | wired into `make fuzz-short` and `.github/workflows/nightly-fuzz.yml` |
| B6 (O_NOFOLLOW descriptor checks) | `config.openConfigFile`, `checkOpenedConfigFile`, `validateConfigFileInfo` | `TestOpenConfigFile_*` (9 tests), `TestValidateConfigFileInfo_AllBranches` (9 subtests via `fileInfoStub`) |
| B7 (parent directory checks) | `config.checkParentDir`, `validateParentDirInfo` | `TestCheckParentDir_*` (6 tests), `TestValidateParentDirInfo_AllBranches` (7 subtests) |
| D1 (state machine) | `agent.StateMachine`, `transitions` | `TestEveryDocumentedTransition` (17 edges incl. the new `EventDegradedCondition` ones), `TestForbiddenTransitions` (every other (state,event) pair), `TestTerminateRevoked_ValidFromEveryState` |
| D2 (control loop) | `agent.ControlLoop.HandleControllerMessage`, `SeqTracker`, `OutboundSeq`, `BuildHeartbeat`, `CheckCertExpiry` | `TestHandleControllerMessage_*` (11 tests), `TestSeqTracker*`, `TestBuildHeartbeat*`, `TestCheckCertExpiry_*` |
| C (relayd assembly) | `main.run`, `openTPMDevice` (prod/testtpm), `buildEnroller`/`noEnroller`, `sdNotify`, `agent.RealSnapshotProvider`, `agent.RealIdentityRotator` | `TestRealSnapshotProvider_*`, `TestRealIdentityRotator_*`; `main.run` itself is glue code exercised end-to-end only by a real (root, TPM-equipped) host -- see section 11 |

## 5. Invariants and threats addressed

- **A1** closes the specific gap the review named: certificate-validity edges are now
  deterministic and testable, and in production the agent's own notion of "now" (not the
  wall clock read mid-verification) governs trust decisions, matching ADR 0008's clock-
  injection convention used elsewhere in this project.
- **A3 / ADR 0032** removes an ambiguity INV-3-adjacent to the control channel's integrity:
  before this, two independently-implemented sides (this repository's agent, and a future
  gateway built elsewhere, per docs/server-contract.md's own framing) could each choose a
  different, individually-reasonable starting `seq` and silently disagree about what a
  "gap" even means.
- **B1's ownership/mode checks** are this project's first enforcement of architecture doc
  8.5's filesystem table for a file the agent itself reads at startup (rather than one it
  only ever writes, like the store): relay.yaml is the host's own configuration of record
  (identity trust domain, controller/collector SPIFFE IDs, allowed scopes), and an
  attacker who could substitute or loosen it without root could redirect the agent's trust
  decisions entirely.
- **B2's closed schema** means a typo or an attacker-supplied extra key in relay.yaml is a
  hard failure, never a silently-ignored no-op -- consistent with this project's "ambiguity:
  implement the interpretation that rejects more" rule.
- **The yamlharden extraction (B2 of this step)** is a pure refactor with no new security
  surface: `internal/policydoc`'s own full test suite (black-box `Parse` tests, including
  `TestParse_A1_*`'s architect-review-R2D-1 probes) is completely unmodified and still
  passes at its existing 95% coverage gate, which is the proof the prompt asked for that
  behavior did not change.

## 6. Deviations from this prompt or the architecture

- **`internal/config` schema extraction change (B2 "no behavior change to policydoc")**:
  the four white-box tests that called `hardenedYAML`'s unexported `walk`/`walkMapping`
  methods directly (`TestWalk_UnexpectedKindAndUnbalancedMapping`,
  `TestParseHardenedYAML_TopLevelNotMapping`, `TestWalkMapping_AliasAsKey`,
  `TestParseHardenedYAML_TooManyNodes`, `TestWalkMapping_KeySideRejections`,
  `TestParseHardenedYAML_SyntaxError`) and one (`TestCheckRawBytes_ControlChars`) that
  called `checkRawBytes` directly moved into `internal/yamlharden`'s own test file,
  unchanged apart from the package clause and `parseHardenedYAML` -> `Parse`: Go's
  unexported-method visibility is per-package, so a type alias could not have kept them
  callable from `internal/policydoc` without exporting the walker (the user explicitly
  asked that the walker stay unexported; see the session's own checkpoint exchange).
  `internal/policydoc`'s remaining test suite -- every black-box `Parse` test, plus the
  white-box tests unrelated to the walker -- is completely unmodified.
- **`identity.trust_domain` is a new required relay.yaml field**, not present in
  architecture doc 8.6's literal example. `internal/identity.Config.TrustDomain` has no
  other source in this repository (`docs/reports/step-05b.md` section 6 / section 9's open
  question 1); this step answers that question by adding the field.
- **`redaction.drop_env` is renamed `keep_env` (inverted polarity)**. Architecture doc
  8.6's example writes `drop_env: true`, but a Go bool's zero value is `false`: an operator
  who omits the field would get `drop_env: false` (environment variables kept), the
  opposite of the "zero/absent value is the secure behavior" rule this project requires.
  `keep_env` (default `false`, meaning "drop the environment") fixes this the same way
  `internal/tetra.Config.AllowSELinuxDisabled` already does for its own field.
- **`tetragon.allow_selinux_disabled` is new** (not in architecture doc 8.6's YAML
  example, though its existence as a concept is implied by `internal/tetra.Config`'s own
  field of the same name and section 8.7's addendum). Wiring it from `internal/tetra`'s
  caller (relayd's startup, Part C) through to that existing field is listed as a
  remaining Part C item (section 9).
- **No single-pass hardening-plus-typed-decode API.** `config.parse` calls
  `yamlharden.Parse` (hardening) and then a separate `yaml.NewDecoder(...).KnownFields(true)`
  typed decode, parsing the same bytes twice. `internal/yamlharden` was deliberately kept
  to exactly the hardening API `internal/policydoc` already needed (returning a
  `*yaml.Node`, not a typed struct), so introducing a combined API now would have widened
  the scope of the B2 extraction itself; the double-parse cost is negligible for a file
  this small, read once at startup.

## 7. Dependencies added

None. `internal/yamlharden` and `internal/config` both use only `gopkg.in/yaml.v3`
(already a dependency, step 2) plus the standard library.

## 8. Known limitations

- **`cmd/relayd`'s control stream is never driven in this step.** `main.run` builds every
  component (store, TPM, Tetragon client, apply engine, cert manager) but does not call
  `internal/controlclient.Dial` or start `ControlLoop`'s message loop: doing so needs a
  client certificate, and this build's `buildEnroller` always refuses to enroll (C2). A
  host with a chain persisted by some future real enrollment flow would still have no code
  path in this binary that dials out with it yet. This is the single largest gap between
  "the components exist and are tested" and "the agent actually reaches STEADY," and is
  the main reason E3's "clean start to STEADY with heartbeats arriving" scenario cannot be
  demonstrated without first closing it.
- **`RealIdentityRotator.Rotate` is unimplemented** (returns a named error): rotating onto
  a brand-new TPM key needs `internal/tpm.RotateHostSigner`, which `internal/agent`
  deliberately has no import of in this file (matching `identity.CertManager`'s own
  TPM-decoupling); wiring it is a small, well-scoped follow-up.
- **No reconnect/backoff orchestration loop exists.** `controlclient.DialBackoff` and
  `agent.ControlLoop`'s dispatcher both exist and are tested in isolation, but nothing yet
  ties them together into the actual "dial, Hello, loop messages, on disconnect back off
  and redial" loop architecture doc 6.3 describes; this is what Part E2/E3 would exercise
  once built.
- **`internal/testcontroller`'s seq enforcement only covers the first message.** The full
  per-direction rule (every later message, not just the first) now has an agent-side
  counterpart (`SeqTracker`, Part D2) but still needs the reconnect loop above to be
  exercised against a real multi-message stream.
- **No separate controller CA bundle field in relay.yaml.** `main.run` reuses
  `cfg.EnrollmentTrustBundle` for both identity enrollment and (if the control stream were
  driven) the controller's own TLS verification -- the same test-only simplification
  `docs/reports/step-05b.md`'s own integration test already uses, now also present in
  production wiring. Flagged as an open question (section 10) rather than fixed silently.
- Every known limitation from `docs/reports/step-05b.md` section 8 not specifically closed
  above remains (no production Enroller, in particular).

## 9. What remains (Part E of docs/prompts/step-06a.md)

Not started:

- **E2** -- extending `cmd/testcontroller` so it can drive scripted multi-message
  sequences (heartbeat expectations, `StateRequest`, `RotateIdentity`, every `Terminate`
  reason, out-of-order `seq`, oversize messages, unknown types) against a real stream.
- **E3** -- the integration suite running `relayd` as a real process under the production
  systemd unit's sandbox settings (`User=`, empty capabilities, `ProtectSystem=strict`,
  `ReadWritePaths`, `ProtectProc=invisible`), with swtpm (via the new `testtpm` build tag)
  through a real Tetragon and the test controller. This needs the reconnect/control-loop
  orchestration gap (section 8) closed first for the "clean start to STEADY" scenario to
  be meaningful; the other scenarios (SIGTERM leaves policies unchanged, a production
  build stays UNENROLLED and still enforces LKG) are already exercisable against what
  exists today.
- Coverage: `internal/config` (93.8%) and `internal/agent` (92.9%) both already meet the
  >=90% gate as of this report; E1 (state machine and handler unit tests) is, in effect,
  already done (section 4's D1/D2 rows) even though E2/E3 are not.

The reconnect/control-loop orchestration gap (section 8) is the natural next piece of
work: a `RunSession` function tying `controlclient.Dial`, `SendHello`,
`ControlLoop.HandleControllerMessage`, `BuildHeartbeat` (on a 15 s ticker) and
`DialBackoff` together, driven by a real enrolled identity. A fresh session picking this
report up should start there, since E2/E3 cannot produce meaningful evidence without it.

## 10. Open questions for the architect

1. Should `tetragon.allow_selinux_disabled` in relay.yaml be the only source
   `internal/tetra.Config.AllowSELinuxDisabled` is ever set from in production, or should
   relayd's startup sequence (Part C) additionally require some other confirmation (e.g.
   a separate `--i-understand-this-is-insecure` flag) before honoring it? This step only
   built the config-side surface and left the wiring for Part C.
2. `identity.spire_server` is currently optional in relay.yaml's schema (not in Part B3's
   explicit required-field list) even though architecture doc 5.2 describes SPIRE as the
   recommended path. Should it become required when `identity.provider == "spire"`
   (cross-field validation), or does Part C's "no production Enroller exists yet" scope
   note make that moot until a real SPIRE integration exists to consume it?
3. Should relay.yaml gain a separate `controller.ca_bundle` (or similar) field distinct
   from `identity.trust_bundle`, now that `cmd/relayd/main.go` actually wires a value into
   both roles? Section 8 flags this as the production code now repeating the integration
   test's own documented simplification rather than only tests doing so.

## 11. Self-review: the 5 places a reviewer is most likely to find a bug

1. **`checkFileSourceable`'s TOCTOU window** between the `Lstat` check and `readConfigFile`'s
   later `os.Open`: a symlink swap between the two calls is not re-checked by `readConfigFile`
   itself (it only reopens by path). This mirrors `internal/apply/persist.go`'s own
   "operator-configured, not attacker-controlled" path trust model, but relay.yaml's path
   comes from a command-line flag an attacker with local code execution as a non-root user
   cannot control (root already owns the process), so the practical risk is low; still
   worth the architect's explicit sign-off given this is the first time this project reads
   (not just writes) a security-critical file by path at startup.
2. **`lookupGroupGID`'s test-seam variable is package-level, mutable global state**,
   shared across any tests that run in parallel within `internal/config` (none currently
   call `t.Parallel()`, but a future test added without noticing this convention could
   introduce a race). Documented in the variable's own comment; not changed structurally
   because every sibling package (`internal/apply`, `internal/hostprobe`) uses the
   identical pattern already.
3. **`validEndpoint`'s `net.SplitHostPort`-based check** accepts some strings a stricter
   validator might reject (e.g. a bare IPv6 address without a port is correctly rejected,
   but it does not verify the host is a valid IP or hostname shape beyond non-empty) --
   deliberately permissive since `internal/controlclient.Config` and
   `internal/testcontroller.Config` themselves do no stronger validation on endpoints
   today either.
4. **`defaultArgvPatterns` fully replaces (never merges with) a configured
   `redaction.argv_patterns` list.** An operator who sets one custom pattern loses the
   three built-in ones, which could reduce redaction coverage below the architecture
   example's defaults; documented in `schema.go`'s comment as a deliberate simplification
   given redaction patterns are expected to eventually come from signed trust metadata
   (step 7), not local config.
5. **`MaxConfigFileMode = 0640`'s bitwise check (`mode&^0640 != 0`) accepts `0000`
   through `0640` inclusive, including modes an operator might not intend (e.g. `0040`,
   group-read-only with no owner read at all)** -- any mode that is a SUBSET of 0640's
   bits passes, which is correct per the prompt's literal "mode at most 0640" but is worth
   the architect confirming is the intended interpretation versus "exactly 0640".
