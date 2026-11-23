# Vendored Tetragon gRPC API (v1.8.0)

This directory vendors the generated Go bindings for Tetragon's `FineGuidanceSensors`
gRPC service so `internal/tetra` (step 3 prompt Part B) can talk to a real Tetragon
v1.8.0 daemon without depending on the full `cilium/tetragon` module graph (whose own
`api/go.mod` `replace`s `github.com/cilium/tetragon => ../`, which would otherwise pull
the entire upstream monorepo into this project's build).

## Source

- Repository: `https://github.com/cilium/tetragon`
- Tag: `v1.8.0`, commit `a5a667837d4b1ecd9018797994bb4e39b98702e1` (same commit the CRD in
  the parent directory was vendored from; see `../README.md`).
- Directory: `api/v1/tetragon/` (package `tetragon`, proto `go_package` declares
  `github.com/cilium/tetragon/api/v1/tetragon`, which only affects the protobuf file
  registry path baked into the generated descriptors, not this project's Go import path).
- Retrieved via: `git clone --depth 1 --branch v1.8.0 https://github.com/cilium/tetragon.git`

Files copied verbatim (protoc-gen-go / protoc-gen-go-grpc / protoc-gen-go-json output,
`DO NOT EDIT` headers preserved): `bpf.pb.go`, `capabilities.pb.go`, `events.pb.go`,
`events.pb.json.go`, `sensors.pb.go`, `sensors.pb.json.go`, `sensors_grpc.pb.go`,
`tetragon.pb.go`, `tetragon.pb.json.go`, `types.pb.go`.

Deliberately NOT vendored: `eventlogservice*.go` (a separate gRPC service,
`EventLogService`, not in `internal/tetra`'s RPC allowlist) and the `codegen/`/
`eventchecker` subpackages (test helpers that import the full upstream module and are
not needed to make client calls).

`api/v1/tetragon` itself imports only `google.golang.org/protobuf/...`,
`google.golang.org/grpc/...`, and the Go standard library (confirmed by inspecting every
non-test `import` block before vendoring): it does not depend on any other
`cilium/tetragon` package, so copying just this directory is sufficient and the
`replace` directives in upstream's `api/go.mod` do not apply here.

## File hashes

See `MANIFEST.sha256` (`make verify-tetragon-api` checks it in CI). Any future edit to
these files (including a well-intentioned one) must go through re-vendoring, never a
hand edit, since they are supposed to be exactly what `protoc` produced upstream.

## Re-vendoring procedure

```
git clone --depth 1 --branch <new-tag> https://github.com/cilium/tetragon.git /tmp/tetragon-src
cd /tmp/tetragon-src/api/v1/tetragon
cp bpf.pb.go capabilities.pb.go events.pb.go events.pb.json.go sensors.pb.go \
   sensors.pb.json.go sensors_grpc.pb.go tetragon.pb.go tetragon.pb.json.go types.pb.go \
   <repo>/third_party/tetragon/<new-version>/api/v1/tetragon/
cd <repo>/third_party/tetragon/<new-version>/api/v1/tetragon
shasum -a 256 *.go > MANIFEST.sha256
```

Then: `go mod tidy && go mod vendor` (pulls in any newly-needed
`google.golang.org/protobuf/types/known/...` subpackage), re-run `internal/tetra`'s
`TestAllowlist_NoOtherRPCsReferenced` test, update this README, `internal/limits`'
pinned-version family, and `Makefile`'s `TETRAGON_API_DIR` if the directory name changed,
all in the same commit.

## API facts this project relies on (step 3 prompt section 11; see
docs/reports/step-03.md for the full, consolidated list with every citation)

- `FineGuidanceSensors` service and its RPCs: `sensors.proto:334-380`.
- `TracingPolicyMode` (`TP_MODE_ENFORCE`/`TP_MODE_MONITOR`/`TP_MODE_MONITOR_ONLY`) is a
  native, per-policy, runtime-settable attribute (`sensors.proto:59-64`), but it is only
  settable via `ConfigureTracingPolicy` (`sensors.proto:193-203`), an RPC *not* in this
  package's allowlist (step 3 prompt Part B1). `internal/apply`'s Part D2 therefore uses
  the "rewrite every enforcement action to Post" fallback unconditionally, not the native
  mechanism; see `docs/decisions/0016-apply-engine-mode-mechanism.md`.
- `EnableTracingPolicy`/`DisableTracingPolicy` are deprecated server-side and rejected
  unless the Tetragon daemon is started with `--enable-deprecated-tracingpolicy-grpc`
  (`cilium/tetragon` `pkg/server/server.go:370-373`, not vendored here since it's daemon
  code, not API surface). See the same ADR for how `internal/apply` handles this.
