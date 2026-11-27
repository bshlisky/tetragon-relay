# ADR 0040: zstd (klauspost/compress) and compressed telemetry batches

## Status

Proposed (docs/prompts/step-07b.md Z1–Z3; docs/reviews/step-07a-review.md R7A-1).
Amends ADR 0039 sections 2 and 5 (header v2, payload encoding, batch file format).

## Context

At 5k events/s the spool fills at about 1.1 KiB per event uncompressed
(`BenchmarkStageCompress`, `raw-B/event`). R7A-1 asks for zstd at a fast level,
with `payload_sha256` and the batch hash over the compressed bytes as sent, so a
collector verifies before it decompresses. It also asks for a stated maximum
decompressed size that both sides enforce, against decompression bombs.

## Decision

### 1. Dependency

| Module | Version | Why |
| --- | --- | --- |
| `github.com/klauspost/compress` (package `zstd` only, plus its internal `fse`, `huff0`, `internal/*` and `zstd/internal/xxhash`) | v1.20.5 (2026-11-19, the latest tag on proxy.golang.org at the time of this ADR: `go list -m -versions`) | The Go standard library has no zstd. This is the zstd implementation the Go ecosystem uses (gRPC-ecosystem, Prometheus, containerd). It decodes with explicit memory limits, which a bomb-resistant collector needs (section 3). |

- **Vendored and pinned.** `vendor/` and `go.sum`
  (`h1:rJj5VjH4xQxbnLphg6eqUcDxRFCw1jpMdDY9qXlrwSs=`). `make vendor-check`
  and `go mod verify` run in CI.
- **Its own module requirements are empty.** Its go.mod has `go 1.25` and only
  `retract` directives, so it adds no transitive modules.
- **govulncheck:** `No vulnerabilities found.` (local, with the dependency
  added). It runs on every CI build.
- **SBOM:** `make sbom` (syft, SPDX) lists `github.com/klauspost/compress
  v1.20.5` (checked locally on `dist/sbom.spdx.json`). CI builds the SBOM the
  same way (`anchore/sbom-action`).
- **No cgo.** It does ship Go assembly for amd64 and arm64:
  - the vendored tree has `zstd/seqdec_amd64.s`, `huff0/decompress_amd64.s`,
    `zstd/internal/xxhash/xxhash_amd64.s` and others;
  - `internal/le/unsafe_enabled.go` uses `unsafe` under
    `//go:build (amd64 || arm64 || ppc64le || riscv64) && !nounsafe && !purego`.

  We build with neither tag, which matches the upstream default. The
  reproducible-build check covers it.
- **License:** BSD-3-Clause (`vendor/github.com/klauspost/compress/LICENSE`).
- **Who imports it.** Only `internal/telemetry/batch`, through
  `PayloadEncoder` and `PayloadDecoder`. The agent only encodes. Decoding is
  for collectors: `internal/telemetry/chainverify` and `cmd/e3collector`.

### 2. Header v2 and payload encoding

- **`v` is 2.** Two keys come after `epochs`, always present and in this order:
  `"telemetry_policy_epoch":N,"enc":"none"|"zstd"`.
  - `telemetry_policy_epoch` is 0, the built-in default, until step 7b Part S
    defines signed telemetry policies. It's added now so the format changes
    once.
  - A strict v1 collector rejects unknown keys, so the version bump is what
    tells collectors the format changed.
- **`v` 1 headers stay valid.** A 7a agent's spooled batches are sent unchanged
  after an upgrade, and one chain may hold v1 batches followed by v2 ones.
  - A v1 header has neither key and means `enc: none`.
  - A v1 header with either key, or a v2 header missing one, fails the
    canonical re-serialization check.
- **What gets compressed.** `enc: "zstd"` is allowed only on `events` batches;
  control batches are always `none`.
  - The agent compresses each events payload as one zstd frame (`EncodeAll`,
    `SpeedFastest`, with content size and checksum).
  - It sends `none` when compression doesn't make the payload smaller. In
    `TestSpool_CompressesEventsPayloads`, an incompressible payload is sent as
    `none`.
- **Hashes cover the payload as sent.** That is the compressed bytes when
  `enc` is `zstd`. Receivers check `payload_sha256` and chain the batch hash
  first, and decode only after that.
- **Size limits.**
  - The uncompressed payload the agent builds is still at most
    `limits.MaxTelemetryPayloadBytes` (1 MiB), so a batch on the wire stays
    ≤ 1 MiB.
  - A decoded payload may be at most `limits.MaxTelemetryDecodedPayloadBytes`
    (8 MiB), section 3.

### 3. Decompression bombs

`batch.PayloadDecoder` never produces more than 8 MiB:

- **`WithDecoderMaxMemory(8 MiB)` and `WithDecoderMaxWindow(8 MiB)`.**
  - In v1.20.5's `DecodeAll` (`zstd/decoder.go:411`), a frame whose declared
    content size exceeds the space left is refused before anything is decoded.
  - The decoded total is checked after every frame (`decoder.go:450`).
  - It is also checked after every block, for frames that don't declare a size
    (`zstd/framedec.go:368`).
- **`WithDecodeAllCapLimit(true)` with a destination buffer whose capacity is
  8 MiB.** Output can never grow past the buffer (`framedec.go:373`), so many
  frames together are capped too.

`TestPayloadDecoder_Limit` covers exactly 8 MiB (accepted), and these, which
are rejected with `ErrDecodedTooLarge`:

- 8 MiB + 1 in one sized frame;
- 64 MiB in one sized frame;
- a streamed frame of 8 MiB + 1 that declares no size;
- 1 GiB streamed;
- two frames whose sum is over the limit;
- nine 1 MiB frames.

Every one of these bombs is under 1 MiB compressed. Garbage and truncated
frames are `bad_payload`. `FuzzPayloadDecode` runs in fuzz-short and nightly.

`framedec.go:369` and `:374` call `println` when the limit is hit, without a
debug guard. That would write one line to the collector's stderr per bomb. No
such line appeared in the test runs. The agent never decodes.

### 4. Spool file format TRS2

Batch files written from step 7b on use magic `TRS2`, and their HMAC-SHA-384
covers the file name, the magic and the batch hash. The batch hash already
commits to the header length, header and payload. `TRS1` files, whose HMAC
covers the whole body, are still read, so a 7a spool survives the upgrade
(`TestSpool_ReadsStep7aFiles`). The `payload_sha256` re-check on read is kept.

## Consequences

- Collectors must implement `enc` and the 8 MiB limit (telemetry contract
  section 2). The reference verifier and e3collector do.
- **Measured compression is 4.5× on the varied corpus**
  (`BenchmarkStageCompress` and `BenchmarkCompressOptions`, M2, to be
  confirmed on the runner and on real E3 events). That is about 243 B per
  event on disk, so 2 GiB holds about 0.5 h at 5k events/s, not 8 h.
  - Other levels and batch sizes reach 4.5–4.9×.
  - The ADR amending 8.13 records the measured figure. Whether the spool cap
    or the target changes is the architect's decision (step-07b report,
    section 9).
