# ADR 0027: TPM library, device access, SRK template and NV counter handle

## Status

Accepted.

## Context

`docs/prompts/step-05a.md` Part C1 requires a documented choice of TPM library, a documented
test environment running against a real TPM 2.0 implementation in CI (not just a mocked
interface), and fixed, documented templates/handles for the SRK and the rollback-protection
NV counter so a reviewer does not have to reverse-engineer them from code.

## Decision

### 1. Library: `github.com/google/go-tpm` v0.9.8, the `tpm2` ("TPMDirect") package

Architecture doc section 8.1 already names `go-tpm` as "the standard way to use TPM keys as
a signer for TLS." The module ships two TPM 2.0 APIs:

- `legacy/tpm2`: the original, function-per-command API.
- `tpm2` ("TPMDirect"): a newer API that maps every TPM 2.0 command 1:1 to a Go struct with
  an `Execute` method, introduced specifically to be more composable and to track the TPM
  spec's own structure more closely (the module's own v0.9.0 release notes: "introduces the
  API that was proposed in 2022 as 'TPMDirect'... maps TPM commands to Go structs instead of
  funcs, allowing greater composability").

This project uses `tpm2` (TPMDirect), not `legacy/tpm2`: `docs/prompts/step-05a.md` C1 names
the package as "`github.com/google/go-tpm` (the `tpm2` package)" and TPMDirect is the
actively developed API family (the legacy package exists for migration compatibility, not
as the recommended starting point for new code). Vendored under `vendor/github.com/google/
go-tpm` per architecture doc 8.12 ("dependencies vendored").

### 2. Device access: a `transport.TPM` abstraction, not a custom one

Every TPM primitive in `internal/tpm` (`CreateSRK`, `KeySealer`, `Counter`, `HostSigner`)
takes a `github.com/google/go-tpm/tpm2/transport.TPM` (a one-method `Send([]byte)
([]byte, error)` interface) rather than this project defining its own device abstraction.
This is deliberate: it is both this package's "unit tests use an interface" seam (C1) and
the exact same type production code uses to talk to the real device, so there is no
translation layer between what a test exercises and what production code sends.

- **Production**: `OpenDevice("/dev/tpmrm0")` (`internal/tpm/device.go`), which delegates to
  `go-tpm`'s `tpm2/transport/linuxtpm.Open`. Architecture doc section 8.6 already requires
  `/dev/tpmrm0` only (the kernel resource manager), never `/dev/tpm0`; `linuxtpm.Open`'s own
  precondition check (`os.Stat` + `ModeDevice`) refuses a non-device path outright.
  `linuxtpm.Open` has no Linux-specific build constraint (despite its package name, it is
  `//go:build !windows`, confirmed by reading `vendor/github.com/google/go-tpm/tpm2/
  transport/linuxtpm/linuxtpm.go`): it is a plain `os.OpenFile` against the given path, so
  `internal/tpm` needs no platform-specific build files at all — it simply fails at runtime,
  not at build time, on a platform without that device file.
- **Tests**: a real swtpm process dialed over TCP via `go-tpm`'s own `tpm2/transport/tcp`
  package (see section 3). The exact same command-building code in `internal/tpm` runs
  against both; only the transport differs.

### 3. Test TPM: swtpm (software TPM), not the go-tpm-tools simulator

`docs/prompts/step-05a.md` C1 requires choosing between a software TPM (swtpm) or the
`go-tpm-tools` simulator (a cgo binding to Microsoft's reference implementation), with the
cgo trade-off justified if that path is taken.

**Chosen: swtpm** (`github.com/stefanberger/swtpm`, packaged for RHEL 9 as `swtpm` and for
this project's macOS development machine via Homebrew), run as a subprocess per test with
its own isolated state directory and TCP ports, dialed via `go-tpm/tpm2/transport/tcp`
(the de-facto TPM-over-TCP wire protocol the TCG reference simulator and swtpm's own
`--server type=tcp`/`--ctrl type=tcp` modes both implement).

Reasons:

- **No cgo.** Architecture doc 8.1 and 8.12 commit this project to a single, statically
  linked, reproducible-build Go binary with no runtime dependencies; `go-tpm-tools`'
  simulator package requires cgo (it links `libtpms`/the TCG reference implementation's C
  code directly into the test binary), which this project's existing build has never needed
  and which would complicate cross-compilation and reproducible-build verification
  (architecture doc 8.12) for marginal benefit over an external swtpm process.
- **swtpm is a full, independent TPM 2.0 implementation** (built on `libtpms`, the same
  reference crypto core `go-tpm-tools`' simulator embeds, but run as a separate process
  communicating over the real wire protocol), so tests exercise actual TPM command
  marshaling/unmarshaling and response parsing end to end — not a mocked interface — which
  is exactly what C1 asks for ("at least one CI job must exercise the real TPM command
  flows").
- **swtpm is what RHEL 9 (this project's deployment target) packages and documents as its
  software TPM for development/CI use** (`swtpm` and `swtpm-tools` RPMs), so the same
  invocation pattern this project's CI uses is reproducible by an engineer debugging locally
  on the actual target OS family, not just on a developer's cgo toolchain.
- **Process isolation per test.** Each test in `internal/tpm` spawns its own swtpm instance
  with a fresh `t.TempDir()` state directory (`internal/tpm/swtpm_test.go`), so tests never
  share TPM state (NV indices, loaded objects) and can run in parallel without interfering
  with each other — closer to how `internal/store`'s own test suite isolates filesystem
  state per test.

**CI**: a dedicated job (`.github/workflows/ci.yml`'s `tpm` job, gated the same way the
existing `integration` job is) installs `swtpm`/`swtpm-tools` via `apt-get` on the Linux
runner and runs `go test ./internal/tpm/...`, so every push genuinely exercises
`internal/tpm` against a live TPM 2.0 implementation, not a mock, on GitHub Actions. This
project's own macOS development machine also has `swtpm` installed (via Homebrew) so the
same tests ran locally during development of this step, against the real command flow.

If the `swtpm` binary is not found on `PATH`, `internal/tpm`'s tests `t.Skip` (not fail):
`go test ./...` stays green on a machine without it, while the CI job (which always
installs it) is the actual enforcement point for "must exercise the real TPM command flows."

### 4. SRK template: ECC P-256, owner hierarchy, no persistent handle

`internal/tpm.SRKTemplate` (`srk.go`) is a restricted ECC P-256 decryption primary key under
the owner hierarchy, `fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth |
restricted | decrypt`, following the TCG "EK Credential Profile" family's conventional SRK
shape. P-256 (not P-384) is used for the SRK specifically because it only ever wraps other
objects' `Create` sensitive areas — it never signs anything or is used off-TPM — so this
project's FIPS 186-4/5 curve-strength requirement for actual signatures (architecture doc
5.1: ECDSA P-384) does not apply to it, and P-256 is the one curve every TPM 2.0
implementation (including constrained/embedded ones) is required to support under the TCG
PC Client Platform TPM Profile, whereas P-384 support is optional (see ADR 0028 for why the
HOST SIGNING key, by contrast, prefers P-384 with a documented P-256 fallback).

Because `SensitiveDataOrigin` is set and the template is fixed, `TPM2_CreatePrimary` against
this exact template under the owner hierarchy derives the identical key deterministically
from the hierarchy's primary seed every time (TCG TPM Library Spec Part 1, "Primary Object
Creation"): `CreateSRK` recreates it fresh on every call, with no persistent handle
(`TPM2_EvictControl`) and no provisioning step at all. This is what ADR 0026 (store key
sealing without a PCR policy) depends on: the same key, every boot, with nothing to
provision and nothing that can go stale.

### 5. NV counter handle

`internal/tpm.DefaultCounterHandle = 0x01500020`, a fixed index in the TCG-registered owner
range (`0x01000000`-`0x01BFFFFF`) that this project owns exclusively. `ProvisionCounter`
(run once by the root-run `relay-probe --provision-tpm`, never by `relayd`) defines it with
`TPMA_NV_COUNTER`, owner read/write only, no platform/auth-value/policy access path; `Open-
Counter`/`Read`/`Increment` (run by the unprivileged `relayd`) validate those exact
attributes on every open and refuse (`ErrNVIndexAttributeMismatch`) a pre-existing index at
that handle with any other shape — a collision with something else, or evidence of
tampering with the index's own definition.

## Consequences

- New third-party dependency: `github.com/google/go-tpm` v0.9.8 (vendored). No other new
  dependency was added for Part C (no cgo, no `go-tpm-tools`).
- `internal/tpm` has no platform-specific (`_linux.go`/`_darwin.go`) build files: `OpenDevice`
  and every TPM-command-building function are platform-agnostic Go that only fails at
  runtime on a platform/path without a real device, by design (section 2).
- CI gains a `swtpm`/`swtpm-tools` package install step in the `tpm` job; no change to any
  existing job's dependencies.
- If a future step needs TPM-based remote attestation (PCR quotes, explicitly out of scope
  for 5a per `docs/prompts/step-05a.md`), it extends `internal/tpm` with the same
  `transport.TPM`-based pattern; nothing here blocks it.
