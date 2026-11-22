# ADR 0001: Dependency policy and the dependencies added in Step 1

## Status

Accepted.

## Context

The prompt requires a one-line justification for every third-party module,
standard library preferred, and explicitly forbids adding a TUF or DSSE
library for this step so that every security-relevant line is reviewable
in-repo.

## Decision

Only two third-party module families are used, both explicitly allowed by
the prompt and both required to generate/compile the protocol buffers:

| Module | Why |
| --- | --- |
| `google.golang.org/protobuf` | Runtime support for generated `.pb.go` code (api/relay/control/v1); there is no standard-library protobuf implementation. |
| `google.golang.org/grpc` | Runtime support for generated `*_grpc.pb.go` client/server stubs; no client/server logic is implemented in this step, only the generated interface. |

Everything else — DSSE envelope parsing, Pre-Authentication Encoding (PAE),
ECDSA P-384 signature verification, the TUF-style root/targets/log trust
model, and strict JSON decoding — is hand-written in `internal/dsse`,
`internal/trust`, and `internal/strictjson` using only the standard library
(`crypto/ecdsa`, `crypto/x509`, `crypto/sha256`, `crypto/sha512`,
`encoding/json`, `encoding/base64`).

Semantic version comparison (`internal/verify/semver.go`) is also hand-written
rather than depending on `golang.org/x/mod/semver`, because that package
expects a leading `v` and does not implement full semver.org prerelease
precedence; the amount of code needed to do this correctly for
`MAJOR.MINOR.PATCH[-prerelease][+build]` is small and fully reviewable.

## Consequences

- No supply-chain exposure from a DSSE or TUF library; the full trust-root
  and signature-verification logic is in this repository and is covered by
  this step's tests and fuzzers.
- Dependencies are vendored (`vendor/`) per architecture doc section 8.12
  ("dependencies vendored; `govulncheck` and SBOM-based CVE scan gate
  releases").
- Future steps (gRPC client/server, TPM, Tetragon socket client) will need
  additional dependencies (e.g. `google.golang.org/grpc` is already present
  for this; a TPM library such as `github.com/google/go-tpm` is anticipated
  by architecture doc section 8.3 but is out of scope here and not added).
