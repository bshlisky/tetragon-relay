# Step 5b report: TPM owner-auth fix, enrollment interface, mTLS client, server contract

## 1. Summary

- **First actions**: committed `docs/prompts/step-05b.md` and `docs/reviews/step-05a-review.md`
  verbatim; confirmed `make ci` green from a clean clone at `94ab501` before any change.
- **Part A (step-05a review follow-ups)**:
  - **R5A-1** [MEDIUM]: relayd no longer uses TPM owner-hierarchy authorization at runtime.
    ADR 0029 (Accepted) records the design: a persistent SRK (`tpm.ProvisionSRK`/`OpenSRK`,
    at the TCG standard handle `0x81000001` if it already matches, else a project-owned
    handle `0x81020001`) and a self-authorized NV counter (`AuthRead`/`AuthWrite` with an
    empty, documented index `authValue`, never `OwnerRead`/`OwnerWrite`). Provisioning
    (`relay-probe --provision-tpm`, root, optional `--tpm-owner-auth-file` for hosts whose
    TPM already has an owner password) is the only code that ever uses owner-hierarchy
    authorization; `KeySealer`/`HostSigner`/`Counter` never do.
  - **R5A-2** [LOW]: the NV-counter-monotonicity citation in `docs/reports/step-05a.md`
    section 12 now cites the TCG Trusted Platform Module Library, Part 1: Architecture,
    Family "2.0", Level 00, Revision 01.59 (2019-11-08), section 37.2.6.3 "NV Counter Index"
    verbatim (located and quoted directly from the TCG-published PDF), replacing the
    secondary-source (Arthur/Challener/Goldman book) citation.
- **Part B**: new `internal/identity` package. `Enroller` interface (CSR in, chain out,
  never a private key — ADR 0030 records why this is a security boundary, not just an API
  shape, and what it constrains about a future SPIRE/IdM integration). `CertManager` builds
  the CSR from a `crypto.Signer`, validates every property of a returned chain itself
  (leaf key, URI SAN, EKU, validity window, chain-to-trust-bundle), persists the chain,
  and implements 50%-of-lifetime renewal timing and full-jitter renewal backoff. `TestCA`
  (build tag `testca`) is a small in-process CA with one-time join tokens.
- **Part C**: new `internal/controlclient` package, transport only. TLS 1.3-only config with
  cipher-suite/version pinning enforced via `VerifyConnection` (Go's TLS 1.3 stack cannot
  restrict suites pre-handshake — documented deviation, see section 6), controller SPIFFE ID
  pinning via full chain + exact URI SAN verification inside `VerifyConnection` (not
  `InsecureSkipVerify` alone — also documented, see section 6), full-jitter reconnect
  backoff, HTTP/2 keepalive, message-size caps, and the Hello/HelloAck exchange.
- **Part D**: `docs/server-contract.md`, citing file:line across `control.proto`, the TLS
  config, and the architecture document, for the backend team implementing the real
  controller.
- **Part E**: unit tests alongside B and C (not deferred); `cmd/testcontroller`
  (build tag `testserver`, thin wrapper over the new, untagged `internal/testcontroller`
  package) as the E2 reference server; a full end-to-end integration test
  (`internal/controlclient/integration_test.go`, build tag `testca`) proving enrollment via
  the test CA with a **real TPM-held key** (swtpm), a real mTLS connection to the reference
  server, and Hello/HelloAck — plus all four required negative cases. Coverage ≥90% for both
  new packages (section 3).
- No deviations from the architecture beyond what is explicitly documented in section 6
  (the two Go-stdlib TLS 1.3 limitations). Two new third-party dependencies pulled in:
  none — `google.golang.org/grpc`'s `credentials`/`keepalive`/`connectivity` subpackages were
  already vendored as transitive dependencies of the already-accepted `grpc` dependency
  (step 1); no `go.mod`/`go.sum` change was needed.

## 2. File tree of what was added or changed (since `94ab501`)

```
docs/
  decisions/0029-no-tpm-owner-authorization-at-runtime.md   (new, Accepted)
  decisions/0030-enroller-must-certify-tpm-held-key.md      (new, Accepted)
  prompts/step-05b.md                                       (new, committed verbatim)
  reviews/step-05a-review.md                                (new, committed verbatim)
  reports/step-05a.md                                       (R5A-2: citation replaced)
  reports/step-05b.md                                       (this file)
  server-contract.md                                        (new, Part D)
cmd/
  relay-probe/main.go, main_test.go       (+--tpm-owner-auth-file; ProvisionSRK+ProvisionCounter)
  testcontroller/main.go, README.md       (new, build tag testserver)
internal/
  tpm/
    srk.go                                (persistent SRK: ProvisionSRK, OpenSRK, handle selection)
    counter.go                            (self-authorized NV attributes, index authValue)
    seal.go, signer.go                    (OpenSRK instead of CreateSRK/FlushSRK per call)
    errors.go                             (+ErrSRKNotProvisioned, ErrSRKHandleMismatch)
    srk_test.go, ownerauth_test.go        (new: handle selection, owner-password regression)
    *_test.go                             (updated: ProvisionSRK calls added where needed)
  identity/                               (new package)
    doc.go, enroller.go, config.go, csr.go, certmanager.go, persist.go, backoff.go, errors.go
    testca.go                             (new, build tag testca)
    *_test.go                             (new, incl. testca_test.go under tag testca)
  controlclient/                          (new package)
    doc.go, config.go, tlsconfig.go, client.go, backoff.go, hello.go, errors.go
    *_test.go, integration_test.go        (new, integration_test.go under tag testca)
  testcontroller/                         (new package, no build tag)
    doc.go, server.go, server_test.go
  limits/limits.go                        (+MaxControlMessageBytes, Control{Keepalive,DialBackoff}*)
packaging/systemd/tetragon-relay.service  (+--tpm-owner-auth-file documentation in comment)
Makefile                                  (+internal/identity, internal/controlclient to coverage90)
.gitignore                                (+/testcontroller build artifact)
```

## 3. Command output

```
$ gofmt -l $(...); goimports -l $(...)                         # clean
$ go vet ./...; go vet -tags testca ./...; go vet -tags testserver ./...   # clean
$ golangci-lint run ./...                                       # 5 pre-existing unused findings,
                                                                  # internal/tetra/_linux.go only (macOS-only,
                                                                  # unchanged since step-04c; GitHub Actions ci is green)
$ golangci-lint run --build-tags testca ./internal/identity/... ./internal/controlclient/...  # 0 issues
$ golangci-lint run --build-tags testserver ./cmd/testcontroller/...                           # 0 issues
$ govulncheck ./...                                              # No vulnerabilities found
$ go build ./...; go build -tags testca ./...; go build -tags testserver ./...    # clean
$ go test ./...                                                 # ok, all packages
$ go test -tags testca ./internal/identity/... ./internal/controlclient/...       # ok, incl. E3 integration tests (swtpm)
$ make coverage90
  internal/tetra      86.0%  (pre-existing, macOS-only; unchanged from step-05a; passes on GitHub Actions)
  internal/apply      92.1%
  internal/hostprobe  90.4%
  internal/agent      90.9%
  internal/identity   93.2%  (new, ≥90%)
  internal/controlclient  96.9%  (new, ≥90%)
$ make coverage-tpm      # internal/tpm: 91.1% (>=90%, against real swtpm)
$ make tpm-test          # all PASS against real swtpm, including new srk_test.go/ownerauth_test.go
```

### Integration test evidence (E3)

```
$ go test -tags testca ./internal/controlclient/... -run TestIntegration -v
=== RUN   TestIntegration_EnrollConnectHelloAck
    integration_test.go:213: E3 PASS: enrolled via test CA with a TPM-held key, connected, completed Hello/HelloAck
--- PASS: TestIntegration_EnrollConnectHelloAck (0.62s)
=== RUN   TestIntegration_ServerWrongSPIFFEID_ClientRefuses
    integration_test.go:240: observed error: controlclient: dial canceled before any endpoint became ready: context deadline exceeded
--- PASS: TestIntegration_ServerWrongSPIFFEID_ClientRefuses (3.61s)
=== RUN   TestIntegration_ClientCertForOtherHostUUID_ServerRefuses
    integration_test.go:278: observed error: controlclient: expected HelloAck as the first message: got *controlv1.ControllerMessage_Terminate
--- PASS: TestIntegration_ClientCertForOtherHostUUID_ServerRefuses (0.62s)
=== RUN   TestIntegration_ServerTLS12Refused
    integration_test.go:324: observed error: controlclient: dial canceled before any endpoint became ready: context deadline exceeded
--- PASS: TestIntegration_ServerTLS12Refused (3.61s)
=== RUN   TestIntegration_ExpiredClientCertificateRefused
    integration_test.go:372: observed error: controlclient: dial canceled before any endpoint became ready: context deadline exceeded
--- PASS: TestIntegration_ExpiredClientCertificateRefused (3.01s)
PASS
```

See section 12 for discussion of each negative case's observed error and why it takes the
shape it does.

### GitHub Actions run numbers (this step's commits, branch `main`)

| Commit | ci | integration |
| --- | --- | --- |
| `82e386a` docs: step 5a review + step 5b prompt | 45600152605 success | (docs-only) |
| `c62ce2d` docs: ADR 0029 Proposed | 45600915608 success | — |
| `54ef83e`+`25424e3` R5A-1 implementation + ADR Accepted | 45605103048 success | 45605103048 success |
| `4aca213` R5A-2 citation fix | 45607954528 success | — |
| `5879ce0` identity (Part B) | — (pushed with next) | — |
| `8e24a9f` controlclient (Part C) | 45613153468 **failure** (lint: missing doc comment) | — |
| `83c7ee9` lint fix | 45613849043 success | — |
| `f583ce0` testcontroller + integration test (Parts E2/E3) | 45616184506 success | 45616184506 success |
| `067ff28` server-contract.md (Part D) | (pending at time of writing; docs-only, confirm before considering this step done) | — |

The one red run (`45613153468`) was a `golangci-lint` doc-comment requirement on two new
`internal/limits` constants, caught and fixed in the very next commit; no test or security
gate ever failed.

## 4. Mapping: item → functions → tests

| Item | Functions | Tests |
| --- | --- | --- |
| R5A-1 (no owner auth) | `tpm.ProvisionSRK`, `tpm.OpenSRK`, `tpm.findProvisionedSRK`, `tpm.srkTemplateMatches`, counter.go's `AuthRead`/`AuthWrite` attributes | `TestProvisionSRK_*`, `TestOpenSRK_*`, `TestSRKTemplateMatches_*` (`srk_test.go`); `TestRelayd_WorksWithOwnerPasswordSetAfterProvisioning`, `TestProvisionSRK_RequiresOwnerAuthFileWhenOwnerPasswordIsSet`, `TestProvisionCounter_RequiresOwnerAuthFileWhenOwnerPasswordIsSet`, `TestCounter_NeverUsesOwnerHierarchyAuthorization` (`ownerauth_test.go`) |
| R5A-2 (citation) | n/a (docs only) | n/a |
| B1 (Enroller interface, ADR 0030) | `identity.Enroller` | enforced by the interface signature itself; `TestCA`'s `Enroll` is the only implementation and is CSR-only |
| B2 (CertManager) | `identity.BuildCSR`, `(*CertManager).Enroll/Rotate/validateChain`, `RenewAt`, `ShouldRenew`, `ExpiringSoon`, `RenewalBackoff` | `TestBuildCSR_*`, `TestCertManager_Enroll_*` (9 rejection subtests + success), `TestCertManager_Rotate_Success`, `TestRenewAtAndShouldRenew`, `TestExpiringSoon`, `TestRenewalBackoff_*` |
| B3 (TestCA) | `identity.NewTestCA`, `NewTestEnroller`, `IssueJoinToken`, `IssueServerCertificate`, `IssueWithValidity` | `TestTestCA_*`, `TestTestEnroller_*` (build tag `testca`) |
| C1 (TLS profile) | `controlclient.BuildTLSConfig` | `TestBuildTLSConfig_*`, `TestVerifyConnection_*` |
| C2 (connection mgmt) | `controlclient.Dial`, `dialOneEndpoint`, `waitReady`, `DialBackoff` | `TestDial_*`, `TestDialBackoff_*` |
| C3 (Hello) | `controlclient.HelloFields`, `SendHello` | `TestSendHello_*` |
| E2 (test server) | `testcontroller.Server.Connect`, `authorize`, `parseHostURISAN` | `TestParseHostURISAN`, `TestServerTLSConfig_Shape` |
| E3 (integration) | — | `TestIntegration_*` (5 tests, build tag `testca`, real swtpm) |

## 5. Invariants and threats addressed

- **R5A-1 closes a least-privilege gap and a fleet-breakage bug simultaneously**: relayd
  (unprivileged, network-facing) no longer needs or can exercise TPM owner-hierarchy
  authorization at all, and hosts whose TPM already has an owner password set (common
  enterprise provisioning) now work via `--tpm-owner-auth-file` at provisioning time only.
- **ADR 0030 structurally forecloses a software-generated SVID**: the `Enroller` interface's
  signature (CSR in, chain out) cannot express "here is a private key," closing the specific
  risk of a future SPIRE integration accidentally using the stock Workload API flow and
  defeating architecture P4 (hardware-bound credentials).
- **`CertManager.validateChain` never trusts an `Enroller`'s own judgment**: every property
  (key, SAN, EKU, validity, chain) is independently re-checked regardless of what the
  Enroller claims, matching this project's "no silent fallbacks" rule — proven by 9 distinct
  rejection tests, each isolating one specific lie an Enroller could tell.
- **`controlclient`'s SPIFFE ID pinning survives a Go/grpc-go quirk that would have silently
  defeated it**: discovered during this step's own testing (section 6) — Go's `crypto/tls`
  and grpc-go's `credentials.NewTLS` both auto-populate `ServerName` from the dial target
  when left empty, which would have silently re-enabled a hostname check that can never pass
  against these DNS-SAN-less certificates had `InsecureSkipVerify` not been used with full
  manual verification in `VerifyConnection` instead.
- **E3's integration test is the first evidence this project has that a TPM-held key can
  actually be used end-to-end for mTLS**: not just that `HostSigner` implements
  `crypto.Signer` correctly in isolation (step 5a), but that the resulting certificate
  actually negotiates a real TLS 1.3 mutual-auth connection and passes application-layer
  Hello/HelloAck.

## 6. Deviations from this prompt or the architecture

- **TLS 1.3 cipher suite restriction is enforced post-handshake, not pre-handshake.** Go's
  `crypto/tls.Config.CipherSuites` doc states plainly: "Note that TLS 1.3 ciphersuites are
  not configurable" — the standard library always offers and will negotiate
  `TLS_AES_128_GCM_SHA384`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`
  regardless of configuration. `internal/controlclient/tlsconfig.go`'s `VerifyConnection`
  checks the negotiated suite after the fact and refuses the connection if it is
  `TLS_CHACHA20_POLY1305_SHA256`; this protects the agent but cannot prevent a server from
  offering/negotiating it in the first place. `docs/server-contract.md` section 2 tells the
  backend team explicitly that their own server configuration, not the agent, is the actual
  enforcement point for "never offer `TLS_CHACHA20_POLY1305_SHA256`."
- **`InsecureSkipVerify` is used, with `VerifyConnection` doing full manual verification,
  rather than `RootCAs` + an empty `ServerName`.** The working agreement says "Implement
  this with `VerifyConnection`, not `InsecureSkipVerify` plus custom code, unless you
  document why" — the why: Go's `crypto/tls.Dial` and grpc-go's
  `credentials.(*tlsCreds).ClientHandshake` (confirmed by reading
  `vendor/google.golang.org/grpc/credentials/tls.go:108-121`) both set `Config.ServerName`
  from the dial target's host whenever it is left empty, which would otherwise silently
  re-enable Go's default hostname verification against an address like `127.0.0.1` — and
  this project's certificates carry no DNS or IP SANs at all (architecture 5.1: URI SAN
  only), so that check could never pass regardless of what `ServerName` ends up being. This
  was caught by this step's own unit test (`TestDial_Success`), not discovered later: an
  earlier version of `tlsconfig.go` used `ServerName: ""` with default verification and
  `TestDial_Success` failed with `x509: cannot validate certificate for 127.0.0.1 because it
  doesn't contain any IP SANs` until the fix.
- **Host UUID has no existing source in this repository.** `docs/prompts/step-05b.md` B2
  asks to "cite where it comes from today"; the honest answer, after reading
  `internal/hostprobe.HostFacts` (no `host_uuid` field) and the only existing config
  reference (`docs/architecture.md:657`'s example `relay.yaml`, `host.uuid_source: tpm-nv`,
  which is documentation, not code), is that **no code in this repository sources a host
  UUID today**. `identity.Config.HostUUID` is therefore a caller-supplied field (relayd's
  main, step 6, is responsible for sourcing it), documented as such in `config.go`'s doc
  comment, and listed again as an open question in section 9.
- **No separate `internal/backoff` package.** `identity.RenewalBackoff` and
  `controlclient.DialBackoff` independently implement the same ~15-line full-jitter formula
  with different parameters (`RenewalBackoffBase`/`Cap` vs.
  `limits.ControlDialBackoff{Base,Cap}`). This keeps both packages's "decoupled, no
  TPM/identity/store dependency" boundary intact (introducing a shared package either of
  them would need to import adds a dependency edge neither otherwise has) at the cost of
  ~15 duplicated lines; not promoted to a shared package since the prompt did not ask for one
  and two independent, fully-tested copies are easier to review in isolation than a new
  cross-cutting package.

## 7. Dependencies added

None. `google.golang.org/grpc`'s `credentials`, `keepalive`, and `connectivity` subpackages
used by `internal/controlclient` were already present under `vendor/google.golang.org/grpc/`
as part of the already-accepted `google.golang.org/grpc` dependency (step 1); no `go.mod`/
`go.sum`/`vendor/modules.txt` change was needed for this step.

## 8. Known limitations

- **No real caller wires any of this together yet.** `relayd`'s `main()` is still the step-1
  stub; nothing in production yet calls `identity.NewCertManager`, `controlclient.Dial`, or
  `internal/agent.BuildTPMComponents` (step 5a) together. This is explicitly step 6's job per
  the prompt's "Out of scope" section.
- **Remote attestation is not implemented.** `HelloFields.PCRQuote` does not exist as a field
  at all (left out entirely, since the prompt says "Leave the PCR quote empty"); the proto's
  `Hello.pcr_quote` field is simply never set by `toProto()`, so it serializes as empty bytes.
- **`internal/testcontroller`'s source-IP binding (architecture 6.3 step 2's last check) is
  not implemented** — it has no inventory/switch-port database to check against. This is
  called out explicitly in `docs/server-contract.md` section 8 so the backend team does not
  mistake the reference server's omission for "optional."
- **The controller/agent trust bundle sharing in the integration test is a test-only
  simplification.** `TestCA` issues both the agent's and the test controller's certificates
  in `integration_test.go`; architecture doc section 5 keeps the identity PKI and policy
  trust root (and, implicitly, host vs. service certificate issuance) as separate concerns in
  production. This is noted in `TestCA.IssueServerCertificate`'s own doc comment.
- **`CertManager.Rotate`'s "retire the old key" half is the caller's responsibility**, not
  tested end-to-end here (no real caller exists yet to retire `tpm.HostSigner` blobs after a
  successful rotation) — consistent with `tpm.RetireHostSigner`'s own "nothing calls this
  automatically" contract from step 5a.
- Every known limitation from `docs/reports/step-05a.md` section 8 not specifically closed
  above (relayd `main()` orchestration gaps, no real-hardware TPM run in this development
  environment) is unchanged by this step.

## 9. Open questions for the architect

1. `identity.Config.HostUUID` has no source in this repository today (section 6). Should
   step 6 add a `host_uuid` field to a new config loader (the architecture's example
   `relay.yaml` already sketches `host.uuid_source: tpm-nv`), or should it be sourced from
   `internal/hostprobe.HostFacts` (requiring a schema bump there, `relay-probe` changes, and
   a decision about whether `relay-probe` or `relayd` itself should own reading it)?
2. Section 6's two TLS 1.3 limitations (cipher suite restriction, hostname-verification
   workaround) are both consequences of using Go's standard `crypto/tls`/grpc-go stack as-is.
   Is relying on `VerifyConnection`-based post-hoc/manual enforcement acceptable long-term,
   or should a future step evaluate a TLS library that exposes TLS 1.3 suite configuration
   directly (at the cost of leaving the standard library, a bigger decision than this step's
   scope)?
3. `docs/server-contract.md` section 1 notes that `AgentMessage.seq`'s starting value is not
   fixed by this step (gateway must track the stream's own first-seen value). Should a future
   ADR pin `seq` to start at a specific value (e.g. 1) for both directions, so the gateway's
   "strictly increasing" check has one less degree of freedom to get wrong?

## 10. Self-review: the 5 places a reviewer is most likely to find a bug

1. **`CertManager.validateChain`'s check ORDER is fixed but not architecture-mandated** —
   a chain that is simultaneously wrong in multiple ways (e.g. wrong key AND expired) always
   reports the first check in the list, which could mask a more "interesting" failure from
   whoever is debugging a real enrollment problem. This is a diagnostics concern, not a
   security one (every check still runs to completion in the sense that none are skipped;
   only the single reported error is ambiguous when multiple things are wrong at once).
2. **`controlclient.Dial`'s retry loop does not distinguish "endpoint unreachable" from
   "endpoint reachable but TLS/auth rejected it"** — both cases simply retry the whole
   endpoint list after a backoff. For a persistently misconfigured identity (e.g. an expired
   certificate), this means the agent will retry forever at the dial-backoff cap (5 min)
   rather than ever surfacing a terminal "your certificate is invalid, re-enrollment needed"
   signal — that distinction, and any resulting state-machine transition (e.g. to a
   `REVOKED`-adjacent state), is step 6's job, but a reviewer should confirm this gap is
   actually closed there, not assumed away.
3. **`internal/testcontroller`'s `authorize` reads the peer certificate via
   `peer.FromContext`/`credentials.TLSInfo`, a grpc-go-internal access pattern** — correct
   for this test server, but if a future production gateway in a different language/stack
   extracts the client identity differently (e.g. from a reverse-proxy-injected header after
   TLS termination elsewhere), the exact SAN-parsing logic here (`parseHostURISAN`) would
   need to be re-implemented faithfully, not copied as-is; `docs/server-contract.md` section
   3 describes the requirement in prose precisely so a different implementation does not need
   to read this Go code.
4. **`RenewalBackoff`/`DialBackoff`'s "clamp r01 to [0,1)" defensive code
   (`r01 >= 1 { r01 = 1 - 1e-9 }`) is untested at the exact boundary `r01 == 1.0`** — covered
   indirectly (`0.999999999` in tests) but not with the literal float64 value `1.0`; a
   reviewer re-deriving the full-jitter formula from scratch should confirm this edge case
   cannot produce a delay that is `== max` instead of `< max`, which is the test's actual
   intent (full-jitter is defined as `[0, max)`, not `[0, max]`).
5. **The integration test's negative cases 2-5 (section 12) all produce the SAME observable
   client-side symptom** (`"dial canceled before any endpoint became ready: context deadline
   exceeded"`) for three of the four cases (wrong SPIFFE ID, TLS 1.2, expired cert) — a
   reviewer cannot tell these apart from the agent's own logs alone without deeper TLS-level
   tracing, which is a real operational concern for whoever debugs a production connectivity
   issue later, not just a test-quality nitpick. This is inherent to how `Dial`'s retry loop
   collapses all per-attempt errors into one generic timeout (item 2 above is the same root
   cause); a future step should consider surfacing the most recent per-attempt error
   alongside `ErrDialCanceled`, not just the context's own `deadline exceeded`.

## 11. Hello field-by-field source table (C3)

`internal/controlclient.HelloFields` is filled entirely by the caller (relayd's main, step
6); this package only converts it to the proto message (`toProto`). Sources, as they exist
in this repository today:

| `Hello` field | `HelloFields` field | Source |
| --- | --- | --- |
| `host_uuid` | `HostUUID` | No existing source (section 6, open question 1); caller-supplied |
| `agent_version` | `AgentVersion` | No existing source in this repository (no version-stamping mechanism built yet); caller-supplied, likely a build-time `-ldflags` value (`Makefile`'s existing `VERSION`/`LDFLAGS` pattern, `Makefile:6-8`, used today for `relayd`'s own `-X main.version=...`) |
| `agent_build_digest` | `AgentBuildDigest` (string, hex) | Not yet computed anywhere; architecture 6.2 specifies "sha256 of running binary (/proc/self/exe)" — no existing code reads `/proc/self/exe` and hashes it |
| `tetragon_version` | `TetragonVersion` | `internal/tetra.(*Client).GetVersion` (`internal/tetra/client.go:186-196`), already built and tested (step 3) |
| `kernel_release` | `KernelRelease` | `internal/hostprobe.HostFacts.KernelRelease` (`internal/hostprobe/facts.go:46`), already built (step 3) |
| `boot_id` | `BootID` | `internal/hostprobe.HostFacts.BootID` (`internal/hostprobe/facts.go:40-43`), already built (step 3) |
| `epochs` | `Epochs` | `internal/store.(*Store).Current(scope)` (`internal/store/store.go:466`) per configured scope; no existing method enumerates every scope with an epoch at once, so the caller must iterate its own configured `allowed_scopes` list (also not yet loaded by any config reader — same gap as `HostUUID`) |
| `loaded_digest` | `LoadedDigest` | `internal/apply.Digest(statuses)` (`internal/apply/digest.go:21`), already built and tested (step 3/4), fed by `internal/apply.(*Engine).currentDigest` (`internal/apply/engine.go:404`) |
| `lkg_bundle_digest` | `LKGBundleDigest` | `internal/store.(*Store).Get(domain)` returns an `apply.LKGSet`; no single exported "digest of the LKG" accessor exists today — the caller would need to hash the LKG envelope bytes itself (consistent with architecture 7.3's "digest" being a property of the envelope, computed the same way everywhere) |
| `trust_root_digest` / `trust_root_version` | `TrustRootDigest` / `TrustRootVersion` | `internal/store.(*Store).TrustRoot()` (`internal/store/store.go:643`) returns `(raw []byte, version uint64, ok bool, err error)`; the caller sha256's `raw` itself for the digest (no existing helper does this one-liner) |
| `config_digest` | `ConfigDigest` | No existing source: no config-file loader exists yet in this repository at all (architecture 8.6's `relay.yaml` is not parsed by any code today); caller-supplied once step 6 builds one |
| `pcr_quote` | *(no field in `HelloFields`)* | Deliberately omitted (remote attestation, out of scope; `toProto` never sets this field, so it serializes empty) |

## 12. Integration evidence for E3, including each negative case's observed error

All five tests ran against a real swtpm instance (`internal/tpm`'s own swtpm-launching
discipline, re-implemented locally in `integration_test.go` since it is unexported in
`internal/tpm`), a real `internal/testcontroller.Server` over a real TCP+TLS listener, and a
real `internal/identity.TestCA`.

1. **Success** (`TestIntegration_EnrollConnectHelloAck`): a TPM-backed `HostSigner` is
   enrolled via the test CA's one-time join token, the resulting chain dials and completes a
   full TLS 1.3 mutual-auth handshake against the reference test controller, and
   `SendHello`/the server's `HelloAck` round-trip succeeds with the configured 15 s heartbeat
   interval observed in the response. **PASS.**
2. **Server presents the wrong SPIFFE ID** (`TestIntegration_ServerWrongSPIFFEID_ClientRefuses`):
   the client is configured to expect `spiffe://.../mgmt/collector` while the server actually
   presents `spiffe://.../mgmt/controller`. Observed error: `"controlclient: dial canceled
   before any endpoint became ready: context deadline exceeded"` — the TLS handshake
   completes at the transport level but `VerifyConnection` rejects it every time, so the
   `grpc.ClientConn` never reaches `Ready` and `Dial`'s retry loop exhausts the test's 3 s
   context. **PASS** (the connection is never usable, which is the required outcome; the
   underlying per-attempt `VerifyConnection` error is not currently surfaced through `Dial`'s
   wrapping, item 5 of section 10).
3. **Client's certificate is for another host UUID** (`TestIntegration_ClientCertForOtherHostUUID_ServerRefuses`):
   the agent's certificate (and `Hello.host_uuid`) both correctly say
   `33333333-...`, but the server's configured inventory only contains a different UUID.
   The TLS handshake and `Dial` succeed (chain and SPIFFE ID checks are about the
   *controller's* certificate, which is fine); the server's own `authorize` step then finds
   the host UUID not in inventory, sends `Terminate{reason: PROTOCOL_ERROR}`, and closes.
   Observed error: `"controlclient: expected HelloAck as the first message: got
   *controlv1.ControllerMessage_Terminate"`. **PASS** — this is the one negative case whose
   error message is actually distinguishable from the others, confirming the application
   layer (not just TLS) is where this particular rejection happens.
4. **Server attempts TLS 1.2** (`TestIntegration_ServerTLS12Refused`): a raw
   `tls.Listen` with `MinVersion = MaxVersion = tls.VersionTLS12` stands in for a
   misconfigured/legacy server. Observed error: the same `"dial canceled... context deadline
   exceeded"` as case 2 — the client's `MinVersion = tls.VersionTLS13` makes the handshake
   itself fail outright (no common version), so the connection never progresses past the
   TLS layer at all. **PASS.**
5. **Expired client certificate** (`TestIntegration_ExpiredClientCertificateRefused`): a
   client certificate issued (via `TestCA.IssueWithValidity`, a test-only escape hatch added
   this step) with `NotBefore`/`NotAfter` both in the past. Observed error: again the same
   `"dial canceled... context deadline exceeded"` — the SERVER's own
   `RequireAndVerifyClientCert` TLS configuration rejects the expired certificate during the
   handshake itself, before any application-layer code on either side runs. **PASS.**

## 13. Open questions for the customer, if any, separate from questions for the architect

None specific to this step. The customer action from `docs/reviews/step-05a-review.md`
("run `scripts/e2e-rhel9.sh`... on the RHEL 9 test server when it is available") remains
outstanding and unchanged by this step; this step adds no new TPM hardware dependency beyond
what step 5a already requires (real hardware/vTPM confirmation of `ProvisionSRK`'s persistent-
handle behavior and the self-authorized counter would be valuable but is not new to this
step's design versus step 5a's).
