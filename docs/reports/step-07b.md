# Step 7b report: telemetry performance (Part P), compression (Part Z), D0 and D1

Session 1 (Parts P and Z) is the first half of this file. Session 2 (the architect's
decisions, items 1–5) follows it, before the progress log.

# Session 1

Prompt: `docs/prompts/step-07b.md`. Review: `docs/reviews/step-07a-review.md`.
Base: `eaa6c0b` (step 7a accepted). Date: 2026-11-27.

## 1. Summary

**Green boundary:** ci, integration and e3 are green on `39e8580` (run 46056428748), the
last commit with code or CI changes. S1–S13, T-S1–T-S5, P4-RSS and NO_SIGSYS all pass.
The `bench` job is red **by design**: it is the P3 gate, failing at 15149 ns per event
against 6000. This report's own commit is docs only; its progress line goes in at the
start of the next session.

**This session stopped at P3, as the prompt instructs: "If 6 µs can't be reached, stop and
bring the profile."**

- **The P3 gate is in CI, enforced and failing.** The worst of 3 runs is **15.4 µs per
  event (7.7 % of one core at 5k/s)** on the runner, against ≤ 6 µs (run 46040250809,
  job `bench`). The threshold was not relaxed.
- **CPU fell from 35.0 µs to 14.9 µs per event on the same machine** (section 11).
- **What blocks 6 µs is the design, not tuning.** Decoding and re-marshaling every event
  costs about 6 µs on its own. Section 9 and ADR 0041 section 4 give the options, with a
  measured prototype of the main alternative.
- **Compression (Part Z) is done, but it doesn't close the spool gap.**
  - 7a's spool figure was 8× too optimistic.
  - At the measured ratios (4.5× on a varied corpus, 21.5× on E3's repetitive real
    events), 2 GiB holds about 0.5–5 h at 5k events/s, not 8 h (section 12).
- **The whole relayd costs at least 43.8 µs per event** in E3 at 5.7k events/s, which
  is its full 25 % CPU quota. That's about 3× the gated pipeline, and the limit that
  matters in production (section 14).

That is the second decision for the architect.

| Item | Status | Commits |
| --- | --- | --- |
| First actions: prompt and review committed, progress line for `eaa6c0b`, `make ci` | done | `620d872` |
| P1 Linux benchmark job, pprof artifacts, pre-built input, stage breakdown, baseline first | done; baseline 55.0 µs per event on AMD EPYC 7763 (run 46035767467), 35.0 µs on Xeon 6975P-C (run 46040250809) | `7a35c03`, `0d59ac6` |
| P2 field-specific redaction (no reflection) | done; redact 12.1 → 1.9 µs per event | `4b22e1a`, `03eeed4` |
| P2 buffer reuse; no per-event allocation in classify and batching | done; classify was already 0 allocs | `25ac330` |
| P2 one HMAC and one fsync per batch | HMAC: the file MAC is now over the 32-byte batch hash. fsync: **not changed** (deviation 2) | `25ac330` |
| P3 CPU gate in CI | **enforced, failing at 15 µs: stopped here** | `31d1d79` |
| Z1 zstd dependency ADR, vendored, govulncheck, SBOM | done (ADR 0040) | `0b99e92`, `64cb1b3` |
| Z2 `enc: "zstd"`, hashes over the compressed bytes, v1 batches valid, verifier accepts both | done (header v2) | `0b99e92` |
| Z3 8 MiB decoded maximum in the contract; enforced in chainverify and e3collector; fuzzed | done | `0b99e92`, `64cb1b3` |
| Z4 ratio and spool hours | done: 4.51× on the corpus (0.49 h per 2 GiB); 21.51× on real E3 events (≈ 5.0 h) | `0b99e92`, `1754ff5` |
| P4 ADR amending 8.13; relayd RSS in E3 | ADR 0041 Proposed (CPU row open). E3 P4-RSS PASS: 62.5 MiB max VmRSS at 5,676 events/s; relayd CPU ≥ 43.8 µs per event (section 14) | `1754ff5`, `839b211`, `9a750f8`, `39e8580` |
| V1–V3, S1–S6 | **not started** (session 2, after the decisions in section 9) | — |

## 2. Files added or changed (since `eaa6c0b`; vendor/ and generated `redact_gen.go` excluded)

```
.github/workflows/ci.yml                 new job bench (benchmark, profiles, gate, history)
.github/workflows/nightly-fuzz.yml       FuzzRedactEquivalence, FuzzArgvPrefilter, FuzzPayloadDecode
.gitignore, Makefile                     bench-out/; make bench-gate; fuzz-short adds the three targets
cmd/e3collector/main.go                  decodes compressed payloads (8 MiB limit); prints enc/sent/decoded
docs/decisions/0040-zstd-dependency-and-compressed-batches.md   new
docs/decisions/0041-resource-targets-measured.md                new (Proposed; CPU row open)
docs/prompts/step-07b.md, docs/reviews/step-07a-review.md       committed verbatim
docs/telemetry-contract.md               header v2 (telemetry_policy_epoch, enc); hash as sent; 8 MiB decode limit
go.mod, go.sum, vendor/                  github.com/klauspost/compress v1.20.5
internal/limits/limits.go                MaxTelemetryDecodedPayloadBytes (8 MiB)
internal/telemetry/batch/header.go       header v2; v1 still parsed
internal/telemetry/batch/encoding.go     new: PayloadEncoder, PayloadDecoder (bomb limits)
internal/telemetry/batch/batchtest       versioned chains; EventsZstd
internal/telemetry/chainverify           decodes after the hash checks; bad_payload on a bomb
internal/telemetry/internal/redactgen/   new: generator of redact_gen.go from the v1.8.0 descriptors
internal/telemetry/redact.go             typed redaction; literal prefilter; unknown fields dropped
internal/telemetry/pipeline.go           reused payload/scratch buffers; unknown-field counter
internal/telemetry/spool.go, fs.go       TRS2 files (HMAC over the batch hash), multi-part writes,
                                         AppendEventsPayload, compression
internal/telemetry/*_test.go             corpus, benchmarks, oracle/differential tests, format tests
scripts/bench-gate.sh                    new
scripts/e3-run.sh                        P4-RSS
```

## 3. Command output

Local `make ci` (macOS) at the start of the step, before any change (`make -k ci`):

```
make: *** [lint] Error 1
internal/tetra coverage 86.4% is below the required 90%
make: *** [coverage90] Error 1
```

Everything else passed. Both failures are local only, as in 7a:
- `lint` reports five symbols unused in `internal/tetra/config.go`, which the
  Linux-only files use. `GOOS=linux golangci-lint run ./...` gives `0 issues.`
- `coverage90` for `internal/tetra` fails because its Linux-only files don't build
  on macOS.

GitHub ci was green on `eaa6c0b` (run 46013547920: ci ✓, integration ✓, e3 ✓).

At the end of the session (local):

```
$ GOOS=linux golangci-lint run ./...
0 issues.
$ go test -count=1 -race -cover ./internal/telemetry/...
ok   internal/telemetry               coverage: 92.7% of statements
ok   internal/telemetry/batch         coverage: 97.2% of statements
ok   internal/telemetry/chainverify   coverage: 96.0% of statements
$ make coverage90   (internal/telemetry/..., the gate's own measurement)
total:                                  (statements)    92.0%
$ govulncheck ./...
No vulnerabilities found.
$ make sbom && jq '.packages[]|select(.name|test("klauspost"))|[.name,.versionInfo]' dist/sbom.spdx.json
["github.com/klauspost/compress","v1.20.5"]
$ go test -run=NONE -fuzz=FuzzRedactEquivalence -fuzztime=30s ./internal/telemetry    PASS
$ go test -run=NONE -fuzz=FuzzArgvPrefilter -fuzztime=30s ./internal/telemetry        PASS (796059 execs)
$ go test -run=NONE -fuzz=FuzzPayloadDecode -fuzztime=30s ./internal/telemetry/batch  PASS
```

The P3 gate on the runner (run 46040250809, job `bench`, `bench-out/gate.txt`):

```
cpu: Intel(R) Xeon(R) 6975P-C
BenchmarkPipeline5k-4  200000  20084 ns/op  7.693 %core@5k/s  15387 cpu-ns/event  70.99 go-sys-MiB  70.69 maxrss-MiB
BenchmarkPipeline5k-4  200000  20090 ns/op  7.573 %core@5k/s  15145 cpu-ns/event  70.99 go-sys-MiB  70.95 maxrss-MiB
BenchmarkPipeline5k-4  200000  20076 ns/op  7.525 %core@5k/s  15050 cpu-ns/event  70.99 go-sys-MiB  72.02 maxrss-MiB
GATE: worst of 3 runs = 15387 cpu-ns/event (7.6935 % of one core at 5k events/s); limit 6000
GATE FAIL: pipeline CPU 15387 ns/event > 6000
```

## 4. Mapping: item → functions → tests

| Item | Functions | Tests |
| --- | --- | --- |
| P1 | `BenchmarkPipeline5k`, `bytesSource`, `benchCorpus`/`corpusEvent`, `BenchmarkStage{Decode,Classify,Redact,Marshal,Spool,Compress}`, `scripts/bench-gate.sh` | ci job `bench` (profiles uploaded as `pipeline-profiles-<run>`) |
| P2 redaction | `Redactor.Redact`, `redaction.*` (generated), `redactgen.Generate`, `requiredLiterals`, `lowerASCII`, `Redactor.argv/path`, `redaction.dropUnknown` | `TestRedact_MatchesReflectionWalk` (4000 fully populated events vs the 7a walk), `TestRedactGenUpToDate`, `TestRedact_UnknownFieldsDroppedAndCounted`, `TestRedact_PrefilterFoldCases`, `FuzzRedactEquivalence`, `FuzzArgvPrefilter` |
| P2 buffers | `Pipeline.build` (`pending.payload`, `scratch`), `Spool.AppendEventsPayload`, `countRecords` | `TestSpool_PayloadNotRetainedAndCountChecked`, pipeline tests |
| P2 HMAC | `Spool.sealParts`, `Spool.unseal` (TRS1 and TRS2), `writeAtomic(parts...)` | `TestSpool_ReadsStep7aFiles`, `FuzzSpoolFile` (both formats), crash matrix |
| P3 | `scripts/bench-gate.sh` gate | ci job `bench` |
| Z2 | `batch.Header{V, TelemetryPolicyEpoch, Enc}`, `Version()`, `Encoding()`, `PayloadEncoder`, spool compression | `TestHeader_V1StillAccepted`, `TestParseHeader_RejectsNonCanonical` (enc/tpe cases), `TestSpool_CompressesEventsPayloads`, `TestVerify_CompressedAndV1Batches` |
| Z3 | `batch.PayloadDecoder`, `chainverify.Verifier.decode`, e3collector `printEvents` | `TestPayloadDecoder_Limit` (six bomb shapes), `FuzzPayloadDecode` |
| Z4 | `BenchmarkStageCompress`, `BenchmarkCompressOptions` | E3 P4-RSS (real events) |
| P4 | `scenario_p4_rss` | E3 P4-RSS |

## 5. Invariants and threats addressed

- **Redaction is no weaker than 7a's, and covers the whole API by construction.** The
  field-by-field code is generated from the vendored descriptors for all 53+ messages
  reachable from `GetEventsResponse`. A change to the API that isn't regenerated fails
  `TestRedactGenUpToDate`. The 7a reflection walk is the oracle for a differential test
  and a fuzz target.
- **Unknown fields are dropped (new).**
  - `proto.Unmarshal` keeps unknown fields and `Marshal` writes them back, and the 7a
    walk never visited them. A newer Tetragon's field, an environment under a new field
    number for example, would have been forwarded unredacted.
  - Every message now has its unknown fields removed, counted in
    `events_with_unknown_fields`.
- **The prefilter can't skip a match.** A pattern is skipped only when the input is
  pure ASCII and lacks a literal every match contains.
  - Under `(?i)`, `k` and `s` also match U+212A and U+017F, so non-ASCII input always
    runs the regexp: `TestRedact_PrefilterFoldCases`.
  - `FuzzArgvPrefilter` compares the prefiltered and unfiltered redactors on arbitrary
    patterns and inputs.
- **Decompression bombs.** The collector-side decoder can't produce more than 8 MiB,
  whether frames declare a size or not, and however many frames there are. Hashes are
  checked before decoding.
- **Spool upgrade.** A 7a spool's TRS1 files with v1 headers are read and resent
  byte-identical, and they chain with v2 batches.

## 6. Deviations from this prompt or the architecture

1. **Stopped at P3** (prompt P3). P4's ADR is Proposed with the CPU row open, not
   "amending to the gated values", because no value passes the gate.
2. **"Exactly one fsync per batch" is not done.**
   - A batch is today a file fsync, a directory fsync after the rename, and the same
     two for the HMAC'd head. That is 4 syncs per batch, about 1000 events, so their
     CPU per event is negligible: spool without compression is 1.5 % of samples.
   - Getting to one sync means merging the head into the batch file. A local root
     could then delete the newest unsent files and the chain would carry on without a
     gap, so I didn't do it without a decision.
   - The HMAC part is done. Each batch file has one HMAC-SHA-384, over the file name,
     the magic and the batch hash, instead of over the whole file. The head keeps its
     own small HMAC.
3. **Header v2, not an optional `enc` key.** `v` is now 2, with
   `telemetry_policy_epoch` and `enc` always present, so the format changes once (S4
   only sets the epoch). "`enc` absent means `none`" is kept for v1 headers.
4. **Control batches are never compressed,** and an events payload that zstd doesn't
   shrink is sent as `enc: none`.
5. **Unknown fields are now dropped** (section 5). This is not in the prompt; it closes a
   gap in the redactor that P2 rewrote.
6. **The bench job builds earlier commits** (`BENCH_HISTORY`), because runners differ
   between runs (section 11).
7. **`sync.Pool` is not used.** The builder keeps two per-class payload buffers and one
   marshal scratch buffer for its lifetime. One goroutine owns them, so a pool would
   add nothing.
8. **E3 changes beyond the prompt's scenarios.**
   - T-S4's cap went from 512 KiB to 64 KiB: with compression its 43 s of events take
     90,776 bytes, so 512 KiB never overflowed (run 46039848254).
   - The e3 job got `timeout-minutes: 60`, after a P4-RSS bug held a runner for 57 min.
   - The e3 job now dumps `tetragon.service`'s journal.
9. **Commit size.** `0b99e92` (compression, header v2, decoder and their tests) is about
   670 changed lines outside vendor/. Header v2, the codec and the spool's use of it
   don't build apart.

## 7. Dependencies added

`github.com/klauspost/compress` v1.20.5 (zstd only), ADR 0040:
- vendored;
- `go.sum` `h1:rJj5VjH4xQxbnLphg6eqUcDxRFCw1jpMdDY9qXlrwSs=`;
- govulncheck: no vulnerabilities;
- in the SBOM;
- no cgo, but Go assembly on amd64 and arm64, plus one `unsafe` file under build tags;
- BSD-3-Clause.

## 8. Known limitations

- The gate fails (section 1). Until the CPU row is decided and met, the `bench` job is
  red. ci, integration and e3 are separate jobs and are unaffected.
- Spool capacity is about 0.5 h at 5k events/s (section 12).
- The benchmark doesn't include gRPC transport or TLS. E3 P4-RSS measures relayd's
  whole CPU under real load (section 14).
- zstd's decoder calls `println` without a debug guard when a limit is hit
  (`framedec.go:369,374`). No such output appeared in the tests. Only collectors
  decode.

## 9. Open questions for the architect

1. **CPU (P3, the stop).** At 15 µs per event, decode plus re-marshal is about 6 µs, and
   compression is 2.85 µs. The whole relayd in E3 costs at least 43.8 µs per event at
   5.7k events/s (section 14), so most of the real cost is outside the gated pipeline:
   gRPC receive, TLS, GC. Which one?
   - **(a) Wire-level redaction.** Keep Tetragon's bytes and rewrite only the redacted
     fields; this amends ADR 0039. The prototype gives an estimated ~10 µs with zstd.
   - **(b) (a) plus a cheaper codec or no compression.** Trades spool hours for CPU.
   - **(c) Accept about 8 % of one core** and set 8.13 to the measured value.

   I recommend (a): it removes most of the remaining cost and drops unknown fields by
   design. The 6 µs gate still needs a compression decision on top. Whichever you
   choose, the next step should profile relayd itself in E3 (an e3-tag CPU profile),
   because the benchmark sees only about a third of the real cost.
2. **Spool capacity.** 2 GiB holds about 0.5 h at 5k events/s at the measured 4.5×.
   7a's 55 min was an arithmetic slip; the real uncompressed figure is about 7 min.
   Which do you want?
   - **(a) A bigger cap:** about 33 GiB for 8 h.
   - **(b) A shorter outage window as the target.**
   - **(c) A lower event-rate assumption:** 2 GiB is 8 h at about 300 events/s.
3. **R7A-5** (raised in the acknowledgement, needed before Part S):
   - reserve the `telemetry` scope name;
   - drop step 11 (it hashes YAML policies, and a telemetry policy has none);
   - `keep_env` is a relaxation, so it should get a built-in deny pattern or root
     signatures;
   - protect `process_tracepoint` and `process_uprobe` too;
   - define expiry and tampered-mode behaviour.
4. **fsync** (deviation 2): keep the separate head (4 syncs per batch), or merge it into
   the batch file and accept the weaker evidence of deleted unsent files?
5. **`CPUQuota=25%`** (section 14). At 5.6k events/s relayd uses its whole quota. Is
   25 % the intended ceiling, given the 8.13 decision? It also determines what T-S6
   (a slow client) looks like.

## 10. Self-review: the 5 places a reviewer is most likely to find a bug

1. **The generator's oneof wrapper discovery** (`redactgen.wrapper`). It sets the case
   on a fresh message and reads the interface's dynamic type. If protobuf-go changes
   how oneofs are stored, generation fails loudly rather than producing a wrong file;
   the differential test populates every oneof case.
2. **`requiredLiterals` on `Simplify()`d trees.** Only a top-level literal, or the
   literal children of a top-level concatenation (through capture groups), count.
   Repeats, alternations and classes aren't descended into, so `(abc)+` gives no
   literal and always runs: safe, merely slower. If a future change descended into
   `OpStar` or `OpQuest`, whose bodies a match need not contain, it would skip real
   matches. `FuzzArgvPrefilter` would catch that.
3. **Prefilter state after a replacement** (`Redactor.argv`). When a pattern changes
   the string, the lower-cased copy is recomputed before the next pattern's check. A
   bug there would skip a later pattern on text the earlier one created; the fuzz
   target covers that path.
4. **TRS2 MAC order** (`Spool.unseal`). The MAC is checked before `ParseHeader`, over
   `HashOf(header, payload)` computed from untrusted lengths. The header-length bound
   check comes first. `FuzzSpoolFile` exercises both formats.
5. **PayloadDecoder buffer aliasing.** `Decode` returns a slice into the decoder's
   8 MiB buffer, valid only until the next call. `chainverify` uses it once per
   batch; a caller that keeps it across calls would see it overwritten.

## 11. Profile breakdown, before and after (per stage, same machine)

Intel Xeon 6975P-C, ci job `bench`, run 46040250809 (`bench-out/history.txt`). CPU per
event; the pipeline figure is the mean of 2 runs.

| Commit | Change | Decode | Redact (allocs) | Marshal | Compress | Spool + read (per event) | Pipeline | % core at 5k/s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `7a35c03` | baseline: 7a pipeline, P1 benchmark | 4.03 µs | 12.11 µs (61) | 2.19 µs | — | 7.64 µs | **35.0 µs** | 17.5 % |
| `4b22e1a` | field-specific redaction | 3.87 | 1.93 (3) | 2.21 | — | 7.66 | **22.4 µs** | 11.2 % |
| `25ac330` | reused buffers; TRS2 HMAC over the hash | 3.83 | 1.90 (3) | 2.12 | — | 3.34 | **15.3 µs** | 7.6 % |
| `0b99e92` | zstd | 3.89 | 1.93 (3) | 2.20 | 2.85 | 3.94 (includes compress) | **14.9 µs** | 7.5 % |

The first baseline ran on an AMD EPYC 7763 (run 46035767467): **55.0 µs per event, 27.5 %
of a core**, with decode 6.1 µs and redact 17.4 µs. The ratios between stages are the
same as on the Xeon.

Share of all CPU samples in the final profile (run 46040250809, `stage-shares.txt`):

| decode | redact | marshal | compress | spool (without compress) | export | GC background |
| --- | --- | --- | --- | --- | --- | --- |
| 33.7 % | 17.2 % | 16.6 % | 17.2 % | 1.5 % | 1.8 % | 3.7 % |

**The wire-level prototype** is a test-only file, not committed. It rewrites
`GetEventsResponse` bytes with a per-message plan built once from the descriptors, and
its output equals the decode → redact → marshal path (`proto.Equal`) on 200 corpus
events. On M2 it costs **2.4 µs per event with 7 allocs**. Decode, redact and marshal
cost 6.7 µs there: 3.3 + 1.6 + 1.8.

## 12. Compression ratio and spool hours

| Source | Ratio | Uncompressed per event | On disk per event | Hours per 2 GiB at 5k/s |
| --- | --- | --- | --- | --- |
| Corpus, SpeedFastest, 1 MiB batches (`BenchmarkStageCompress`, runner) | 4.51× | 1091 B | 243 B | 0.49 h |
| Corpus, default level | 4.76× | | | 0.52 h |
| Corpus, better level | 4.85× | | | 0.53 h |
| Corpus, 4 MiB batches, fastest / default / better | 4.50× / 4.79× / 4.95× | | | 0.50 / 0.53 / 0.55 h |
| Real Tetragon v1.8.0 events, E3 P4-RSS (run 46051067160): 342,002 events, 172 zstd batches | **21.51×** | 502 B | ≈ 23.7 B (23.3 B payload, plus about 656 B of header and framing per batch of about 2,000 events) | **≈ 5.0 h** |

8 h at 5k events/s needs ≤ 15 B per event on disk.

- **E3's 21.5×** comes from a load of one repeated exec (`/usr/bin/true` from bash
  loops): the optimistic bound.
- **The corpus's 4.5×** has varied binaries, arguments and 1–3 ancestors: the
  pessimistic bound.

A production host falls between **0.5 h and 5 h** per 2 GiB at 5k events/s.

## 13. Tetragon's slow-client behaviour (T-S6)

Not run in this session (Part V, session 2).

## 14. E3 evidence

T-S6 and T-S7 are session 2. This session's E3 run adds **P4-RSS**, relayd under the real
unit at a sustained event rate:

Run 46051067160 (`e0485e2`). Under the unchanged production unit (`MemoryMax=256M`,
`CPUQuota=25%`), two exec loops ran for 60 s:

```
P4-RSS unit MemoryMax=268435456 MainPID=6459
  VmHWM/VmRSS before the load: 49344 kB / 49344 kB; after: 63712 kB / 47884 kB
REPORT chain 6cd83a2b... contiguous=173 max=173 received=173 declared_dropped=0 reset=head_missing
REPORT CLEAN: 173 batches, 1 chain(s), no gap, fork or bad batch
P4-RSS events=342002 wall=60.3s rate=5676/s relayd_cpu=14.97s (24.85% of one core) cpu_per_event=43772ns max_vmrss=62.5MiB
P4-RSS payload sent=7985008 decoded=171762698 ratio=21.51 zstd_batches=172 sent_B/event=23 decoded_B/event=502
E3 RESULT: P4-RSS PASS
```

systemd at the stop: `Consumed 15.221s CPU time, 47.5M memory peak`.

- **RSS:** 62.5 MiB max, against < 64 MiB. It passes, but with little headroom.
- **CPU:** the whole relayd costs **≥ 43.8 µs per event** at 5.7k events/s, which is
  its whole 25 % quota.
  - That's about 3× the in-process benchmark (15 µs). The rest is gRPC and HTTP/2
    receive from Tetragon, export with TLS, and GC.
  - It's a lower bound: events drained after the load are counted, but their CPU is
    not.
- **T-S4 and T-S5 failed in this run because of a harness bug of mine, not because
  of Tetragon.**
  - That P4-RSS ended with `start_collector ts`, leaving a collector on the shared
    address.
  - T-S4's relayd connected to it, and it acked and deleted every batch. The
    evidence: T-S4 found "0 batches" in the spool, but a fresh chain always spools
    its `chain_reset` at seq 1, so something must have acked it. T-S4's own collector
    then had nothing.
  - At first I suspected Tetragon had stopped delivering after the flood. I didn't
    build on that guess, and the next run disproves it.

Run 46056428748 (`39e8580`) fixes this: P4-RSS ends with the collector stopped, runs
after T-S5, and adds a post-flood probe. **All scenarios pass:**

```
E3 RESULT: S1..S13 PASS, T-S1..T-S5 PASS, P4-RSS PASS, NO_SIGSYS PASS
P4-RSS events=338002 wall=60.2s rate=5610/s relayd_cpu=14.89s (24.71% of one core) cpu_per_event=44053ns max_vmrss=61.7MiB
P4-RSS payload sent=7928173 decoded=170098817 ratio=21.45 zstd_batches=170 sent_B/event=23 decoded_B/event=503
P4-RSS after the flood: collector store lines 172 -> 181 over 10 s of events (same relayd)
P4-RSS after the flood: collector store lines 181 -> 190 over 10 s of events (restarted relayd)
```

Tetragon kept delivering after the flood, to the same relayd and to a restarted one.
Its journal, now dumped by the e3 job, has no drop, rate-limit or slow-client warning
during the 5.6k events/s load. That's a starting point for T-S6, not a conclusion:
relayd kept up, at its quota.


# Session 2: docs/reviews/step-07b-decisions.md, items 1–5

Base: `07e3784`. Decisions: `docs/reviews/step-07b-decisions.md` (committed verbatim in
`fd86543`). Date: 2026-11-27.

## S2.1 Summary

**Boundary:** items 1–5 are done, and the boundary is not fully green. ci,
integration and bench are green. e3 is green except **P4-RSS, whose new E3 CPU gate
fails**. That failure is a finding for the architect (S2.9), not a regression, and the
gate was not relaxed.

- **D0: the control plane keeps its timing under a flood. P5-CONTROL-UNDER-LOAD
  passes** (runs 46073322092, 46073560126, 46073777071). With a monitor bundle delivered
  during the flood, the worst heartbeat gap was 15.0 s, the bundle was APPLIED in its
  health window, there was no watchdog timeout, `rate_limited` dropped records are in
  the chain, and the canary's kprobe events arrived.
- **D0 found and fixed a real starvation path.** The heartbeat read
  `Spool.Stats()`, which takes the spool mutex, and that mutex is held across
  compression, four fsyncs and overflow handling (`d9e83a4`).
- **D1 (a): wire-level redaction.** Pipeline CPU went from **15.4 µs to 9.7 µs per
  event** on one machine (7.7 % → 4.9 % of one core at 5k/s). A differential fuzz
  target checks it against decode → Redact → marshal.
- **D1 field filters: verified on the real v1.8.0 and wired in. They save 0 bytes by
  default**, because Tetragon sends no environment without its flag.
- **D1 gates.**
  - The benchmark regression gate (≤ 1.25 × `f80fcf4`, same runner) is blocking and
    passes: 9,737 against a limit of 12,139 ns.
  - **The E3 gate (≤ 15 % of one core at ≥ 5k generated events/s) fails: 24.76 % at
    5,608/s.**
- **The E3 relayd profile explains the E3 failure.** About 46 % of relayd's CPU is the
  gRPC reader's `read` syscalls on the Tetragon socket, about a third is the Go
  scheduler, and the pipeline is about 5 %. Tetragon sends one message per event, and
  that receive cost is paid before admission control can drop anything.

| Item | Status | Commits |
| --- | --- | --- |
| 1 Decisions file committed; bench gate report-only in the same commit | decisions committed. **The report-only change was blocked by this session's permission classifier**, so the 6 µs gate stayed blocking until item 5 replaced it (deviation S2.6.1) | `fd86543` |
| 2 D0 admission control | done | `799589d`, `e9c15fb`, `d9e83a4` |
| 2 D0 P5-CONTROL-UNDER-LOAD | done, PASS | `79cfddb` |
| 3 D1 wire-level redaction with differential fuzzing | done | `eccab9a`, `f80fcf4` |
| 4 D1 field filters (verify, then measure separately) | verified (integration), wired in, measured: 0 B saved by default | `c36fdc8`, `db86b5b` |
| 5 D1 E3 relayd profile | done (artifact `e3-relayd-profile-<run>`) | `3cbc170` |
| 5 New gates | benchmark gate blocking, PASS. E3 gate in P4-RSS, **FAIL** (S2.9) | `eb863df`, `3cbc170`, `55ef95b` |
| 5 ADR 0041 finalized | rewritten with D0/D1/D2 figures. Status stays Proposed: the CPU row for the whole relayd is open | this commit |
| ADR 0039 amended (D0, D1, D4) | section 10 | this commit |

## S2.2 Files added or changed (since `07e3784`)

```
.github/workflows/ci.yml            bench: regression gate vs f80fcf4, history adds D0/D1; e3: profile artifact
.github/workflows/nightly-fuzz.yml  FuzzPeekAdmit, FuzzWireRedact
Makefile                            fuzz-short: the two targets; -fuzzminimizetime=5s
cmd/e3controller/                   --bundle-delay, --max-heartbeat-gap
cmd/e3collector/main.go             rate_limited_events per chain
cmd/relayd/e3profile{,_testca}.go   SIGUSR1 CPU profile, testca build only
cmd/relayd/telemetry.go             max_event_rate, field filters, GOMAXPROCS in telemetry_started
docs/decisions/0039-...md           section 10: D0, D1, D4
docs/decisions/0041-...md           sections 7-8, decision table
docs/telemetry-contract.md          the rate_limited dropped record
internal/config, internal/limits    collector.max_event_rate (default 2000, hard maximum 5000)
internal/telemetry/admit.go         new: event peek, token bucket, drop accounting
internal/telemetry/wire.go          new: the wire-level rewriter
internal/telemetry/pipeline.go      raw ingest, admission, rewrite, HeartbeatStats lock-free, ExcludedFields
internal/telemetry/spool.go         AppendRateLimited, HeartbeatView
internal/telemetry/batch/payload.go Dropped.Reason/Events
internal/telemetry/chainverify      reports rate_limited events
internal/tetra/client.go            StreamEvents: raw bytes (raw codec), excludeFields
internal/tetra/fieldfilter_integration_test.go   new
scripts/bench-gate.sh               regression gate
scripts/e3-run.sh                   P5-CONTROL-UNDER-LOAD, P4-RSS E3 gate and profile, P4-GOMAXPROCS1
```

## S2.3 Command output

Local, at the end (macOS):

```
$ GOOS=linux golangci-lint run ./...
0 issues.
$ go test -count=1 ./...        (every package ok)
$ go test -run=NONE -fuzz=FuzzPeekAdmit -fuzztime=30s ./internal/telemetry
fuzz: elapsed: 31s, execs: 1254864 ... PASS
$ go test -run=NONE -fuzz=FuzzWireRedact -fuzztime=40s -fuzzminimizetime=3s ./internal/telemetry
fuzz: elapsed: 39s, execs: 226149 (6118/sec), new interesting: 193 (total: 229)
PASS
```

The benchmark gate, run 46073777071, job `bench` (Intel Xeon 6975P-C):

```
REF  BenchmarkPipeline5k-4  200000  20078 ns/op  4.856 %core@5k/s  9711 cpu-ns/event
HEAD BenchmarkPipeline5k-4  200000  20084 ns/op  4.868 %core@5k/s  9737 cpu-ns/event
REF  BenchmarkPipeline5k-4  200000  20097 ns/op  4.896 %core@5k/s  9792 cpu-ns/event
HEAD BenchmarkPipeline5k-4  200000  20090 ns/op  4.825 %core@5k/s  9650 cpu-ns/event
REF  BenchmarkPipeline5k-4  200000  20088 ns/op  4.829 %core@5k/s  9657 cpu-ns/event
HEAD BenchmarkPipeline5k-4  200000  20084 ns/op  4.865 %core@5k/s  9729 cpu-ns/event
GATE: worst HEAD run = 9737 cpu-ns/event (4.87 % of one core at 5k events/s); median f80fcf4 = 9711; limit 12139 (x1.25)
```

Field filters on the real Tetragon v1.8.0 (integration run 46073322092):

```
FIELD-FILTER none: exclude=[] events=20 bytes/event=528 ... args="--marker-arg x" cwd="/tmp" env=0 parent=true
FIELD-FILTER environment: exclude=[process.environment_variables parent.environment_variables ancestors.environment_variables] events=20 bytes/event=528 ... cwd="/tmp" env=0
FIELD-FILTER cwd: exclude=[process.cwd] events=20 bytes/event=522 ... cwd="" env=0
FIELD-FILTER arguments+cwd: exclude=[process.arguments process.cwd] events=20 bytes/event=506 ... args="" cwd=""
--- PASS: TestIntegration_FieldFilters (8.05s)
```

## S2.4 Mapping: item → functions → tests

| Item | Functions | Tests |
| --- | --- | --- |
| D0 raw ingest | `tetra.Client.StreamEvents` (`rawResponseCodec`) | `TestClient_StreamEvents`, `TestRawResponseCodec_RejectsWrongTypes` |
| D0 admission | `peekAdmit`, `tokenBucket`, `rateDrops`, `Pipeline.ingest`/`build` (`declare`), `Spool.AppendRateLimited` | `TestPeekAdmit`, `TestTokenBucket`, `TestPipeline_AdmissionControl`, `TestPipeline_MaxEventRateBounds`, `TestRateDrops_PutBack`, `TestSpool_AppendRateLimited`, `FuzzPeekAdmit` |
| D0 record format | `batch.Dropped{Reason,Events}`, `ParseDropped`, chainverify | `TestDropped_RateLimited` |
| D0 config | `collector.max_event_rate` | config table tests |
| D0 heartbeat | `Spool.unlock`/`HeartbeatView`, `Pipeline.HeartbeatStats` | `TestHeartbeatStats_NeverWaitsForTheSpoolLock` |
| D0 E3 | `scenario_p5`, e3controller `hbWatch` | E3 P5-CONTROL-UNDER-LOAD |
| D1 rewriter | `wirePlanBuilder`, `wireRewriter.rewrite`, `wireState.*`, `fixLength`, `packedOK` | `FuzzWireRedact`, `TestWirePlan_CoversTheGeneratedRedactor`, `TestWire_MatchesRedactOnFilledEvents`, `TestWire_Rejections`, `TestWire_DepthBound`, `TestWire_LongNestedMessagesKeepTheirLengths`, `TestWire_MapEntriesAreLenientLikeUnmarshal`, `TestWire_PackedScalars`, `BenchmarkStageRewrite` |
| D1 field filters | `StreamEvents(excludeFields)`, `telemetry.ExcludedFields` | `TestClient_StreamEvents_ExcludeFields`, `TestIntegration_FieldFilters`, `TestPipeline_ConfigAndIngestReconnect` |
| D1 profile and gates | `startE3Profiler` (testca), `scripts/bench-gate.sh`, `scenario_p4_rss` | bench job, E3 P4-RSS |

## S2.5 Invariants and threats addressed

- **Event noise can't starve the control plane.** Non_security events are budgeted
  before decode. Security events always pass, and so does anything else only within
  the budget. The peek is conservative: a malformed response, or one with two
  distinct event fields, counts as non_security. `FuzzPeekAdmit` checks that nothing
  admitted as security decodes as anything else.
- **Loss stays declared.** Every admission drop is counted, in a `rate_limited`
  record in the chain. A record that can't be spooled is put back and declared in the
  next one.
- **The heartbeat takes no telemetry lock** (atomics published on every spool unlock).
- **The rewriter is a parser at parser standards.**
  - It rejects exactly what decode rejects, plus three stricter cases: a known field
    with the wrong wire type, depth over 32, and two oneof cases in one message.
  - The fuzz oracle's strictness comes from an independent, descriptor-driven scan.
  - The output is checked `proto.Equal` to decode → Redact → marshal. Unknown fields
    are dropped. The environment is validated, then removed.

## S2.6 Deviations

1. **Item 1: the bench gate was not made report-only in the decisions commit.** This
   session's permission classifier refused that change. The 6 µs gate therefore
   stayed blocking (bench red) until `eb863df` replaced it with D1's regression gate,
   which is blocking and green. The refused change was:
   `BENCH_GATE_ENFORCE: "0"` on the bench step.
2. **The rewriter rejects three inputs `proto.Unmarshal` accepts** (S2.5). D1 asks
   both for "wrong wire type for a known field … rejected" and for "exactly one
   rejecting is a failure". Go keeps a mistyped known field as an unknown field, so
   the fuzz oracle is decode **plus** `strictScan`, a descriptor-driven check of those
   three rules that is independent of the rewriter's plan. Inside map entries the
   rewriter is lenient exactly as Go's `consumeMap` is, because Go leaves no trace
   there to check against.
3. **The rewriter's plan is built at startup, not generated.** It comes from the same
   vendored descriptors redactgen uses, and `TestWirePlan_CoversTheGeneratedRedactor`
   ties the two message sets together. The plan has one extra message,
   `tetragon.EnvVar`, which it validates before dropping.
4. **P5's flood did not exceed 5k events/s.** Four shell loops generated 4.3k, 2.3k
   and 4.1k events/s on the three runs. Exec throughput on the 4-vCPU runner (with
   Tetragon's hooks) is the limit. P5 still passed at each rate, and prints a note
   when the rate is ≤ 5k/s.
5. **P4-RSS's E3 gate counts generated events** (loop iterations × 2). It fails the
   scenario if the runner generates < 5k/s, because the gate is then not evaluated.
   P4 now runs 3 loops.
6. **Commit sizes.** `e9c15fb` (raw ingest and admission, about 500 lines with tests)
   and `eccab9a` (the rewriter and its tests, about 780) are over the ~400 guideline.
   Each is one parser or mechanism with its tests.
7. **Outside the items:**
   - `-fuzzminimizetime=5s` in `fuzz-short`. Go's 60 s default minimization (its
     execs aren't counted) took most of each 60 s smoke run: `FuzzWireRedact` did
     24,586 execs in CI, and `FuzzRedactEquivalence` showed the same stall.
   - A timing-dependent assertion in `TestPipeline_HostileAckDeletesNothingAndResends`
     was fixed (`c817fb1`).
   - `P4-GOMAXPROCS1` (report-only) was added as data for S2.9.

## S2.7 Dependencies added

None.

## S2.8 Known limitations

- The E3 gate fails (S2.9).
- `peekAdmit` and the rewriter's plan know v1.8.0's event field numbers. A newer
  Tetragon's new event types count as non_security for admission (conservative) and as
  unclassified in the builder.
- The field filter's saving is 0 B until Tetragon's environment flag is on (V1).
- Admission drops are declared per `batch_max_age`. A crash loses the count of up to
  one window of drops, as with any events not yet spooled (ADR 0039, Consequences).

## S2.9 Open questions for the architect

1. **The E3 CPU gate can't be met by relayd's pipeline.**
   - At 5,608 generated events/s, relayd uses 24.76 % of a core (its quota) while
     admitting 1,992/s.
   - About 46 % of its CPU is `read` syscalls on the Tetragon socket, about 33 % is
     the Go scheduler, and about 5 % is the pipeline.
   - The receive happens before any admission decision.
   - Options (ADR 0041 section 8):
     - (a) shed at the source with `GetEventsRequest.deny_list` from signed policy;
     - (b) tune the per-message cost (GOMAXPROCS, read buffers);
     - (c) set the E3 gate on admitted events, or at the measured cap, relying on P5
       for the control plane.
   - I recommend (c) with P5 as the binding gate. P5 already proves what D0 asked
     for, and (a) doesn't bound an attacker's own exec noise.
   - The GOMAXPROCS figure: P4-GOMAXPROCS1, below.
2. **D2's arithmetic.** "At least 4 h at 1k/s even with the pessimistic ratio" doesn't
   hold. At 243 B per event, 2 GiB holds 2.45 h at 1k/s, and 4 h needs ≤ 149 B per
   event. ADR 0041 states the measured 2.5–25 h at 1k/s. Do you want a different
   default cap, or is the statement enough?
3. **P5's flood rate.** The runner can't exceed about 4.3k events/s with shell loops.
   Is that acceptable as "the maximum rate the runner can generate", or should P5 use a
   compiled exec generator?

## S2.10 Self-review: where a reviewer is most likely to find a bug

1. **`fixLength`'s in-place shift** when a nested message's length needs more than
   one byte. Outer starts are recorded before inner content, so nested shifts compose.
   `TestWire_LongNestedMessagesKeepTheirLengths` (70 KB strings) and the fuzz cover it.
2. **`opDrop` validation into `st.discard`.** The buffer is reused, and a nested drop
   would alias it. The output is discarded, but a bug there could panic rather than
   err. v1.8.0 has no nested `environment_variables`.
3. **`peekAdmit` vs the rewriter's oneof rule.** Both treat two distinct event fields
   as not security (peek) or as rejected (rewrite). A response with the same event
   field twice is security in both.
4. **`rateDrops.putBack`** after a failed spool write. The count is declared in the
   next window, with `first_ts` widened. `TestRateDrops_PutBack` caught a real
   min/max bug during development.
5. **The token bucket's clock.** It uses `Config.Clock` (`time.Now`, wall clock). A
   backward step refills nothing, and a forward jump refills at most one burst.

## S2.11 Profile breakdown, before and after (same machine)

Intel Xeon 6975P-C, run 46073777071 (`bench-out/history.txt`), mean of 2 runs:

| Commit | Change | Decode | Rewrite | Redact | Marshal | Compress | Spool (+ compress) | **Pipeline** | % core at 5k/s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `7a35c03` | 7a pipeline | 3.93 µs | — | 11.56 | 2.08 | — | 7.34 | **34.1 µs** | 17.0 % |
| `0b99e92` | session 1's last (zstd) | 3.86 | — | 1.88 | 2.05 | 2.86 | 3.92 | **14.6 µs** | 7.3 % |
| `d9e83a4` | D0 (decode moves into the pipeline) | 3.86 | — | 1.93 | 1.97 | 2.83 | 3.91 | **15.4 µs** | 7.7 % |
| `f80fcf4` | D1 wire-level redaction | (3.85) | **3.89** (9 allocs) | (2.04) | (2.01) | 2.86 | 3.92 | **9.7 µs** | 4.9 % |

On `f80fcf4`, the figures in parentheses are stages no longer in the pipeline path.
Shares of the pipeline profile on HEAD: rewrite 40 %, spool 34 % (compress 28 %),
redact (inside rewrite) 13 %, export 6 %, GC 2 %.

relayd itself in E3 (run 46073560126, 50 s profile under P4-RSS load, 10.32 s of
samples): `syscall` 45.6 % flat, `futex` 16.6 %, scheduler about 33 % cumulative, the
telemetry pipeline 5.5 %, `grpc.recv` 5.3 %. ADR 0041 section 8 has the table.

## S2.12 Compression ratio and spool hours

These are unchanged from session 1 (section 12). With admission, P4-RSS's received
events compress 15.7–16.7× (fewer repeats per batch at 2k/s). ADR 0041's spool row
restates capacity per D2 as hours per GiB at a rate and ratio (S2.9 question 2).

## S2.13 Tetragon's slow-client behaviour

Not in items 1–5 (V3/T-S6 is the next session).

## S2.14 E3 evidence

**P5-CONTROL-UNDER-LOAD**, run 46073322092 (`c36fdc8`):

```
e3controller: [2026-11-27T22:38:10Z] sent bundle 1 (/tmp/e3-bundles/p5-monitor.json, ...)
e3controller: heartbeat gaps OK: 6 heartbeats, worst gap 15.003s <= 20s
canary under the monitor bundle, during the flood: rc=0
REPORT   event *tetragon.GetEventsResponse_ProcessKprobe binary="/usr/local/bin/e3-canary-sh" ...
P5 generated=645176 (4309/s) received=300002 (2003/s) wall=149.7s relayd_cpu=24.62s (16.44% of one core)
E3 RESULT: P5-CONTROL-UNDER-LOAD PASS
```

Runs 46073560126 and 46073777071 also passed (worst gap 15.003 s each, at 2,265/s and
4,068/s generated).

**P4-RSS and the E3 gate**, run 46073777071 (`eb863df`):

```
P4-RSS generated=337926 (5608/s) events=120002 wall=60.3s rate=1992/s relayd_cpu=14.92s (24.76% of one core) cpu_per_event=124331ns cpu_per_generated=44152ns max_vmrss=63.2MiB
E3 CPU gate: relayd used 24.76% of one core at 5608 events/s (> 15%)
E3 RESULT: P4-RSS FAIL
```

Admission at work in P4-RSS (run 46073322092): `rate_limited_events=216931` over one
clean chain (`contiguous=92 max=92`, no gap).

**The last code commit**, run 46083840295 (`c817fb1`): ci ✓, bench ✓, integration ✓,
e3 ✗ on P4-RSS only:

```
E3 RESULT: S1..S13 PASS, T-S1..T-S5 PASS, P5-CONTROL-UNDER-LOAD PASS, NO_SIGSYS PASS
GOMAXPROCS 2
P4-RSS E3 CPU gate not evaluated: the runner generated 4689 events/s (< 5000)
P4-RSS generated=283542 (4689/s) events=120005 wall=60.5s rate=1985/s relayd_cpu=14.52s (24.01% of one core) cpu_per_event=120995ns cpu_per_generated=51209ns max_vmrss=63.2MiB
E3 RESULT: P4-RSS FAIL
GOMAXPROCS 1
P4-GOMAXPROCS1 generated=166424 (2805/s) received=120001 (2023/s) relayd_cpu=9.22s (15.54% of one core) cpu_per_generated=55401ns
e3controller: heartbeat gaps OK: 6 heartbeats, worst gap 15.006s <= 20s
P5 generated=491200 (3292/s) received=148245 (994/s) wall=149.2s relayd_cpu=3.64s (2.44% of one core)
GATE: worst HEAD run = 15193 cpu-ns/event (7.60 % of one core at 5k events/s); median f80fcf4 = 15248; limit 19060 (x1.25)
GATE PASS
```

- **GOMAXPROCS=1 doesn't help.** It used 55.4 µs of relayd CPU per generated event,
  against 51.2 µs at the default (2 under the 25 % quota). The scheduler share isn't
  an easy lever (S2.9 question 1, option b).
- **The bench gate is stable across machines.** This run's runner was slower (15.2 µs
  per event for both HEAD and `f80fcf4`), and the same-machine ratio still held.
- **P5 in this run received only 994 events/s** (under the 2000/s budget) at 3,292/s
  generated, and relayd used 2.44 % of a core. That is consistent with relayd's CPU
  following the messages Tetragon delivers. I didn't establish why Tetragon delivered
  fewer here; it is a question for T-S6, not an assumption.

# Session 3: docs/reviews/step-07b-decisions-2.md, items 1–5 (V3 as observation)

Base: `da61669`. Decisions: `docs/reviews/step-07b-decisions-2.md` (committed verbatim in
`846d5cb`). Date: 2026-11-28.

## S3.1 Summary

**Boundary:** items 1–4 are done, plus V1, V2 and T-S6 as an observation. On the final
commit (run 46131312207) ci, bench and integration are green, and every e3 scenario
passes, T-S1 with V2 included, **except P5-CONTROL-UNDER-LOAD's new enforce case. It
failed the same way in three runs, and it found a real enforcement-safety problem
(S3.9 Q1).** The gate was not relaxed.

- **e3 went green first, as asked** (run 46113949265 on `2d634ab`). P4-RSS's CPU line is
  now report-only, and RSS fails at ≥ 96 MiB and warns at ≥ 64 MiB (E1.2, E2).
- **P5 now proves the saturated case** (E1.1). The compiled generator
  (`cmd/e3execflood`) makes **10,363 events/s** on the runner, against about 3–6k/s from
  the shell loops. relayd sat at its quota: 23.22 % of one core and `nr_throttled`
  +1,271. Heartbeats held: every gap was 15 s through both applies.
- **Finding: under that flood, an enforce bundle that should roll back was APPLIED.**
  - The admin-path shell **was** killed (exit 137).
  - relayd's health window never received the kill event, so the window passed and
    epoch 8 was committed (`ApplyResult status=APPLIED epoch=8`).
  - In the same window the canary's kprobe event never reached telemetry.
  - No kprobe event of any kind reached relayd during P5, including the canary's,
    though its policy was loaded.
  - Tetragon ran at about 1.05 cores. Its drop counters stayed flat
    (`notify_overflowed` 104,262 → 104,262; ringbuf lost 0), while **its RSS grew from
    1.76 GB to 6.97 GB**. That is consistent with Tetragon's own processing falling
    behind the kernel and queueing, so the events arrive after the window. This is
    inferred, not proven.
  - The same failure happened in two runs (46121973985, 46126491257). This is the
    starvation path E1.1 was meant to test.
- **T-S6 (V3): Tetragon drops events for a slow client with no signal on the stream.**
  - relayd read at most 100 msgs/s while 2,000 events/s were generated for 60 s.
  - relayd received 12,017 of 120,004 events.
  - `tetragon_notify_overflowed_events_total` went from 145 to 167,801.
  - Tetragon sent no RateLimitInfo, the stream never ended, and Tetragon logged
    nothing about it. Its memory did not grow: it drops, it doesn't buffer.
- **V1:** v1.8.0's flag is `--enable-process-environment-variables`, read from
  `tetragon --help` in CI.
- **V2:** with the flag on, a separate GetEvents client with no field filter saw the
  canary's `SECRET_TOKEN`; that client is the positive control. No event relayd
  forwarded carried an environment (`env=0` throughout). The first run failed on a
  harness bug: my own `grep -F <token>` put the token in argv, and Tetragon reported
  that exec. Fixed in `940b9d5`; V2 then passed (run 46126491257: the token was absent
  from the decoded events, the collector store, the spool and the journal). T-S1 still
  failed in that run, because the positive-control probe hit a deadline race (fixed in
  the next commit).
- **E1.3 (chunked handoff): no measurable gain in E3.** In the local benchmark it costs
  10.0–10.4 µs per event, against 13.5–14.7 µs for one channel send per event. In E3,
  Tetragon becomes the bottleneck after the first flood of the job. In the one pair of
  rounds run under the same conditions, per-event cost **4,953 ns** per delivered
  message and chunked **4,812 ns** (about 3 %). relayd was never at its quota in that
  pair. Keep or drop is S3.9 Q4.
- **E1.5 (aggregation_options):** v1.8.0 does not aggregate exec or exit. In six
  alternating rounds (three aggregated, three control) all 20 execs and 20 exits
  arrived, with no `aggregation_info`. One earlier aggregated round got 19 execs and 20
  exits. The API says the aggregator drops events when its buffer is full. Not built on.

| Item | Status | Commits |
| --- | --- | --- |
| Decisions committed; progress line for `da61669` | done | `846d5cb`, `2d634ab` |
| 1 E1.2 P4-RSS CPU report-only; E2 RSS 96/64 MiB; e3 green | done, e3 ✓ (run 46113949265) | `2d634ab` |
| 2 E1.1 compiled generator; P5 quota assertion; enforce/rollback case | done. **P5 FAIL: rollback not seen under saturation** (S3.9 Q1) | `fbe4b11`, `940b9d5` |
| 3 E1.3 chunked handoff; gRPC read buffer / window, measured | built and measured: no meaningful E3 gain (S3.11); keep or drop is Q4 | `d426451`, `940b9d5` |
| 4 E1.5 aggregation_options (report only) | done: no aggregation of exec/exit | `283e142`, `9457c24` |
| 5 V1 environment flag from `--help` | done | `b5b1306`, `dd4f3a3` |
| 5 V2 secret-token proof | built; S3.14 | `b5b1306`, `940b9d5` |
| 5 V3 / T-S6 | **observation only** (loss without signal; detection needs a decision, S3.9 Q2) | `56501c2` |
| 6–7 Part S, D2/S6 contract, ADRs Accepted | not started (next session) | — |

## S3.2 Files added or changed (since `da61669`)

```
.github/workflows/ci.yml                 V1 step; Tetragon with the env flag and a localhost
                                         metrics server; builds cmd/e3execflood
cmd/e3execflood/main.go                  new (e3): N fork/execve loops, --rate, SIGTERM
cmd/e3tetra/main.go                      env-probe mode (V2 positive control)
cmd/relayd/e3tuning.go, e3tuning_testca.go  new: testca-only RELAYD_E3_* knobs (handoff chunk,
                                         gRPC read buffer/window, paced source); no-op in production
cmd/relayd/main.go, telemetry.go         wire the knobs
internal/telemetry/handoff.go            new: chunked ingest -> builder handoff
internal/telemetry/pipeline.go           uses it; Config.HandoffChunk
internal/tetra/config.go, dial_linux.go  ReadBufferSize, InitialWindowSize (0: grpc defaults)
internal/tetra/aggregation_integration_test.go  new (E1.5)
scripts/e3-run.sh                        P4-RSS report-only CPU, RSS 96/64, cpu_per_delivered;
                                         P4-TUNING (replaces P4-GOMAXPROCS1); T-S6; P5 at
                                         saturation with the enforce case; T-S1 V2
docs/decisions/0041-resource-targets-measured.md  section 9; decision table
```

## S3.3 Command output

Local, before each push:

```
$ go vet ./... && go test -count=1 ./internal/... ./cmd/...     all ok
$ go test -count=1 -race -cover ./internal/telemetry/...
ok   internal/telemetry          coverage: 92.0% of statements
$ GOOS=linux golangci-lint run ./internal/telemetry/... ./internal/tetra/... ./cmd/relayd/...   0 issues.
$ GOOS=linux golangci-lint run --build-tags testca ./cmd/relayd/...                           0 issues.
$ go test -run=NONE -bench=BenchmarkPipeline5k -benchtime=100000x -count=2 ./internal/telemetry   (Apple M-series, local)
  chunked (d426451):  10377, 9975 cpu-ns/event
  per-event (before): 13526, 14722 cpu-ns/event
```

V1 (run 46117755144, e3 step "V1"):

```
38:      --enable-process-environment-variables      Include environment variables in process_exec events. Disabled by default. Note that this option can significantly increase the size of the events and may impact performance, as well as capture sensitive information such as passwords in the events ...
61:      --filter-environment-variables strings      Filter for specific environment variables
```

E1.5 (run 46121973985, integration):

```
AGGREGATION round=0 aggregation_options=true  ... exec=20 exit=20 responses_with_aggregation_info=0 (of 41 responses)
AGGREGATION round=1 aggregation_options=false ... exec=20 exit=20 responses_with_aggregation_info=0 (of 40 responses)
AGGREGATION round=2 aggregation_options=true  ... exec=20 exit=20 responses_with_aggregation_info=0 (of 40 responses)
AGGREGATION round=3 aggregation_options=false ... exec=20 exit=20 responses_with_aggregation_info=0 (of 40 responses)
AGGREGATION round=4 aggregation_options=true  ... exec=20 exit=20 responses_with_aggregation_info=0 (of 40 responses)
AGGREGATION round=5 aggregation_options=false ... exec=20 exit=20 responses_with_aggregation_info=0 (of 40 responses)
(run 46119904742, one aggregated round: exec=19 exit=20)
```

P5 (run 46121973985):

```
e3execflood workers=4 secs=148.5 execs=769661 generated=1539322 rate=10363/s failed=0
P5 generated=1539322 (10363/s) received=298773 (2011/s) wall=148.5s relayd_cpu=34.49s (23.22% of one core) nr_throttled=+1271
P5 saturation: relayd was at its CPU quota during the flood
P5 tetragon.service CPU: 155.07s (104.4% of one core)
P5 admin-path shell exit status: 137 (137 = SIGKILL)
e3controller: [08:29:00Z] sent bundle 2 (/tmp/e3-bundles/p5-enforce.json ...)
e3controller: [08:30:01Z] conn #1 seq=13 ApplyResult status=APPLIED epoch=8 ...
e3controller: FAIL: bundle 2: ApplyResult status APPLIED, want ROLLED_BACK (detail "action-rewrite")
the canary's kprobe event was not delivered
no admin-path health-window failure in the journal
```

T-S6 (run 46121973985):

```
e3execflood workers=2 secs=60.0 execs=60002 generated=120004 rate=2000/s failed=0
T-S6 tetragon VmRSS: before=4354016 KiB, max during=4366736 KiB, at flood end=3566856 KiB, 60 s after=3567696 KiB
T-S6 generated=120004 received=12017 (relayd read at most 100/s for 120 s = 12000)
tetragon_notify_overflowed_events_total 145      (before)
tetragon_notify_overflowed_events_total 167801   (after)
tetragon_observer_ringbuf_events_lost_total 0, tetragon_export_ratelimit_events_dropped_total 0 (both, before and after)
T-S6 RateLimitInfo seen by relayd: 0
T-S6 relayd ingest stream ends: 0
T-S6 tetragon log lines about queues, drops or slow clients: (none)
```

## S3.4 Mapping: item → functions → tests

| Item | Functions | Tests |
| --- | --- | --- |
| E1.2, E2 | `scenario_p4_rss` | E3 P4-RSS |
| E1.1 | `cmd/e3execflood`, `flood`, `unit_cpu_stat`, `scenario_p5` | E3 P5-CONTROL-UNDER-LOAD |
| E1.3 | `handoff.put/take/ready`, `Pipeline.build`, `Config.HandoffChunk`, `tetra.Config.dialOptions`, `e3Tuning` | `TestHandoff_*` (4), `TestDialOptions_BufferSizesOptIn`, pipeline tests, E3 P4-TUNING |
| E1.5 | — | `TestIntegration_AggregationOptions` |
| V1 | ci step "V1" | e3 job |
| V2 | `e3tetra --mode=env-probe`, `scenario_ts1` | E3 T-S1 |
| V3 | `e3Source`/`pacedSource` (testca), `scenario_ts6`, `tetragon_metrics` | E3 T-S6 (INFO) |

## S3.5 Invariants and threats addressed

- **Admission still comes before any queuing.** `peekAdmit` and the token bucket run in
  ingest, and only admitted events enter the handoff queue. The 1024-event backpressure
  bound is unchanged: `put` blocks when the queue is full, so Tetragon is read no
  faster than the pipeline spools.
- **The handoff never holds Tetragon's bytes after a take** (`clear(evs)`). The added
  latency is at most 10 ms.
- **Production takes no tuning from its environment.** `e3Tuning` and `e3Source` are
  identities without `testca`; `verify-no-test-symbols` still passes.
- **The V2 secret is never in argv.** It sits in a 0600 pattern file, and the canary
  gets it through its environment only.

## S3.6 Deviations

1. **E1.2 is report-only, not a regression gate** (ADR 0041 section 9). At the quota,
   `cpu_per_generated` ≈ quota / generator rate: identical code measured 51.2 µs and
   35.5 µs. P4-RSS now also prints `cpu_per_delivered` (CPU per message Tetragon
   delivered, admitted + rate_limited), which is what E1.3 is measured by.
2. **P4-RSS keeps the shell loops**, so its numbers stay comparable across step 7b. Only
   P5 and T-S6 use the compiled generator.
3. **T-S6 throttles relayd's reader, not its builder** (testca `RELAYD_E3_SOURCE_RATE`).
   From Tetragon's side it is the same slow client: with a slow builder the handoff
   queue fills and the reader blocks. This keeps test hooks out of `internal/telemetry`.
4. **Tetragon now runs with `--metrics-server 127.0.0.1:2112`** in e3. That was needed to
   observe its drops (T-S6, P5). relayd's own unit still can't reach it.
5. **P4-GOMAXPROCS1 is retired.** Its result is in ADR 0041 section 8.
6. **V3 stops at observation.** The detection design is S3.9 Q2.

## S3.7 Dependencies added

None.

## S3.8 Known limitations

- Tetragon's RSS in e3 is 3.5–4.4 GB late in the job, with the environment flag on and
  after about 2M exec events. That is Tetragon, not relayd, but it shares the runner.
- **e3's Tetragon degrades after its first flood:** CPU about 1 core → 55–60 %,
  generated rate 6.2k → 3.9k/s, RSS up to 7 GB. That limits what E3 can measure about
  relayd late in the job.

## S3.9 Open questions for the architect

**Q1. Health-window signals are lost under a saturating exec flood (P5).**
- With Tetragon at about one core and relayd at its quota, the kill event that should
  have failed the enforce bundle's health window never reached relayd. Epoch 8 was
  committed as APPLIED.
- The health window's stream is separate from telemetry's: it asks only for
  kprobe/uprobe/LSM events of the bundle's policies. Tetragon still did not deliver the
  event in time.
- Tetragon's drop counters were flat during P5, and its RSS grew by 5.2 GB. So this is
  most likely delay inside Tetragon, not a counted drop. An absent event, delayed or
  dropped, reads as "healthy".
- Options:
  - (a) The health window fails safe when it can't trust its event stream. That needs a
    loss signal relayd can read; relayd can't reach Tetragon's metrics endpoint.
  - (b) A positive liveness probe during the window: a known trigger whose event must
    arrive, and the window fails if it doesn't.
  - (c) Accept the risk and document it: an attacker who can flood exec can also blind
    the health window.
- My recommendation is (b). It turns "no event" from "healthy" into "unknown", and it
  catches delay and drops alike.

**Q2. Detecting Tetragon's silent drops (V3).**
- The stream carries no sequence number, and RateLimitInfo only comes from Tetragon's
  export rate limiter, which is not used here.
- The one discontinuity in the stream is exec/exit pairing: every `ProcessExit` carries
  the `process.exec_id` of a `ProcessExec`. An exit whose exec_id relayd never saw
  (after the stream's first N seconds) is evidence of a dropped exec. That gives an
  estimate, not a count, and it needs a bounded exec_id set.
- Shall I build that (an `Alert` plus a `dropped` record with `reason=tetragon_overflow`
  and an estimated count), or leave it to Tetragon's metric?

**Q4. E1.3: keep the chunked handoff?** The decision said to keep it if E3 cost drops.
In E3 it did not drop measurably (4,953 → 4,812 ns per delivered message, one
comparable pair, relayd below its quota). It is about 25 % cheaper in the local
benchmark. Neither gRPC setting changed much: window 1 MiB measured 4,191 ns and read
buffer 256 KiB 4,951 ns, one round each. My reading: E3 can't show the effect because
Tetragon saturates first. I'd drop the gRPC settings and either revert the handoff or
keep it on the benchmark's evidence. Your call.

**Q3. Tetragon's environment flag.** V2 needs it, and the help text warns about size
and performance. Should production deployments run Tetragon with it at all? relayd
excludes and redacts the environment regardless. `--filter-environment-variables` could
let Part S's `keep_env` be enforced at the source.

## S3.10 Self-review: where a reviewer is most likely to find a bug

1. `handoff.take` can return early on a stale notify. That is harmless (it takes
   whatever is queued), but it does mean an extra wake-up.
2. `put` signals at `n+1 == 1` or at a multiple of `chunk`. A take that swaps the
   buffer mid-chunk resets the count, which is intended.
3. `pacedSource` uses `time.After` per message: fine at 100/s, testca only.
4. P5's saturation check reads the cgroup's `cpu.stat` from the start of the flood to
   the end of the controller run, so it can include the post-flood seconds.
5. `flood_events` parses `generated=` from both generator formats; an empty file counts
   as 0.

## S3.11 Profile breakdown, before and after (E1.3)

Local benchmark (unpaced source, so it understates the wake-up savings): 10.0–10.4 µs
per event chunked, against 13.5–14.7 µs per event per-event.

E3 `P4-TUNING`, run 46121973985 (confounded: run after P4-RSS, Tetragon was the
bottleneck from the second round on):

| Setting | Delivered | relayd CPU | cpu_per_delivered |
| --- | --- | --- | --- |
| per-event (round 1) | 3,396/s | 15.31 % | 45.1 µs |
| chunked | 1,377/s | 0.74 % | 5.4 µs |
| chunked + read buffer 256 KiB | 2,533/s | 1.19 % | 4.7 µs |
| chunked + window 1 MiB | 2,524/s | 1.07 % | 4.3 µs |

Run 46126491257 (P4-TUNING first, alternating, Tetragon's CPU per round):

| Round | Setting | Tetragon CPU | Delivered | relayd CPU | cpu_per_delivered |
| --- | --- | --- | --- | --- | --- |
| 1 | per-event | 103.8 % | 6,102/s | 21.42 % (nr_throttled +53) | 35.1 µs |
| 2 | chunked | 54.2 % | 2,112/s | 1.16 % | 5.5 µs |
| 3 | per-event | 60.4 % | 3,617/s | 1.79 % | 4.95 µs |
| 4 | chunked | 60.6 % | 3,600/s | 1.73 % | 4.81 µs |
| 5 | chunked + window 1 MiB | 57.3 % | 3,463/s | 1.45 % | 4.19 µs |
| 6 | chunked + read buffer 256 KiB | 56.7 % | 3,340/s | 1.65 % | 4.95 µs |

Rounds 3 and 4 are the comparable pair. From round 2 on, Tetragon delivers less than
relayd can take, and relayd's cost per message falls about sevenfold (probably because
reads coalesce when it isn't busy; not measured). Round 1 is the only one at
saturation.

## S3.12 Compression ratio and spool hours

Unchanged (ADR 0041 section 6; E3 kept as stated).

## S3.13 Tetragon's slow-client behaviour (T-S6)

See S3.1 and S3.3. **Tetragon v1.8.0 does not buffer for a slow GetEvents client: it
drops.** Its RSS did not grow during the flood. The drops show up only in
`tetragon_notify_overflowed_events_total`; the stream carried no RateLimitInfo, no
error and no end. relayd therefore can't tell today. Detection: S3.9 Q2.

## S3.14 E3 evidence

Run 46126491257 (`940b9d5`): ci ✓, bench ✓, integration ✓, e3 ✗.

- **PASS:** S1–S13, T-S2–T-S5, P4-RSS (62.4 MiB) and NO_SIGSYS.
- **INFO:** P4-TUNING (S3.11) and T-S6. T-S6 received 11,767 of 120,004. Tetragon's
  VmRSS was 5.62 GB before, 5.98 GB at most, and 1.76 GB after.
- **T-S1 FAIL.** V2's absence checks passed:
  `V2: SECRET_TOKEN (fresh, 37 chars) absent from the decoded events, the collector
  store, the spool and relayd's journal`. The positive-control probe ended with
  `tetra: call timed out: GetEvents` (a deadline race; it now cancels instead). In run
  46121973985 the probe saw it: `ENVPROBE binary=/usr/bin/cat exec_events=1 with_env=1
  with_SECRET_TOKEN=1`.
- **P5 FAIL** (Q1):

```
e3execflood workers=4 secs=148.5 execs=743649 generated=1487298 rate=10016/s failed=0
P5 generated=1487298 (10020/s) received=298082 (2008/s) wall=148.4s relayd_cpu=34.21s (23.05% of one core) nr_throttled=+1256
P5 saturation: relayd was at its CPU quota during the flood
P5 tetragon before: VmRSS=1760252 KiB tetragon_notify_overflowed_events_total 104262 tetragon_observer_ringbuf_events_lost_total 0
P5 tetragon after:  VmRSS=6974640 KiB tetragon_notify_overflowed_events_total 104262 tetragon_observer_ringbuf_events_lost_total 0
P5 tetragon.service CPU: 157.83s (106.3% of one core)
P5 admin-path shell exit status: 137 (137 = SIGKILL)
e3controller: bundle 1 OK: APPLIED (5 heartbeats while waiting)
e3controller: FAIL: bundle 2: ApplyResult status APPLIED, want ROLLED_BACK (detail "action-rewrite")
telemetry during P5: 133,039 ProcessExec, 165,043 ProcessExit, 0 ProcessKprobe
```

## Progress log

One dated line per push: commit, what changed, the CI result observed.

- 2026-11-27 `7a35c03` (with `620d872` prompt/review and the `eaa6c0b` progress line): run 46035767467: ci ✓, bench ✓ (gate reported, not yet enforced: **baseline 55.0 µs per event, 27.5 % of a core**, AMD EPYC 7763), integration ✓, e3 ✓ (S1–S13, T-S1–T-S5).
- 2026-11-27 `4b22e1a` (field-specific redaction): run 46037195547: bench ✓ (22.6 µs, Xeon 6975P-C); ci ✗. coverage90 measured `./internal/telemetry/...` at 84.1 %: the generator packages counted at 0 %. integration and e3 skipped.
- 2026-11-27 `25ac330` (buffers; TRS2 HMAC): run 46037747184: bench ✓ (22.0 µs on EPYC); ci ✗ (the same coverage gate).
- 2026-11-27 `0b99e92`, `64cb1b3` (zstd, header v2, ADR 0040): run 46039377991: bench ✓ (15.0 µs, Xeon); ci ✗ (the same coverage gate).
- 2026-11-27 `03eeed4` (redactgen check in its own package): run 46039793433: ci ✓ (coverage 92.0 %), bench ✓, integration ✓, e3 ✗. **T-S4 FAIL**: compressed batches never filled the 512 KiB cap, so no dropped record.
- 2026-11-27 `0d59ac6` (bench history): run 46039848254: ci ✓, bench ✓ (same-machine history, section 11), integration ✓, e3 ✗ (T-S4, as above; everything else PASS, NO_SIGSYS PASS).
- 2026-11-27 `31d1d79`, `1754ff5` (gate enforced; P4-RSS): run 46040250809: ci ✓, **bench ✗: gate 15387 ns per event > 6000**, integration ✓, e3 canceled after 57 min. P4-RSS's bare `wait` waited for the collector. S1–S12 and T-S1–T-S3 PASS before it.
- 2026-11-27 `839b211`, `d15e7e3` (P4 wait fix, e3 timeout; pprof label): run 46050757591 canceled (superseded).
- 2026-11-27 `9a750f8` (P4 starts the unit on a fresh chain): run 46050913507 canceled (superseded).
- 2026-11-27 `e0485e2` (T-S4 cap 64 KiB): run 46051067160: ci ✓, bench ✗ (gate), integration ✓, e3 ✗. **S1–S13, T-S1–T-S3 and P4-RSS PASS** (5,676 events/s, 62.5 MiB, ≥ 43.8 µs per event, 21.5× compression). T-S4 and T-S5 FAIL: P4-RSS left a collector running that acked T-S4's batches (my harness bug; section 14).
- 2026-11-27 `39e8580` (P4-RSS after T-S5, post-flood probe, Tetragon log): run 46056428748: ci ✓, bench ✗ (the gate: worst of 3 is 15149 ns per event > 6000 ns, on the Xeon 6975P-C; red as intended until the CPU decision), integration ✓, **e3 ✓: S1–S13, T-S1–T-S5, P4-RSS and NO_SIGSYS all PASS.** P4-RSS: 5,610 events/s, 61.7 MiB, ≥ 44.1 µs per event, 21.45×; Tetragon still delivering after the flood.
- 2026-11-27 `07e3784` (session-1 report, ADR 0041 Proposed): run 46061521266: ci ✓, bench ✗ (the gate, 21373 ns per event > 6000, as intended until the decision), integration ✓, e3 ✓.
- 2026-11-27 `fd86543` (decisions file; progress line for `07e3784`): run 46070173156: ci ✓, bench ✗ (the 6 µs gate, still blocking: deviation S2.6.1), integration ✓, e3 ✓.
- 2026-11-27 `799589d`, `e9c15fb`, `d9e83a4`, `79cfddb` (D0, P5): run 46071629220: ci ✓, bench ✗ (6 µs gate; 15.6 µs), integration ✓, e3 ✓ (P5 PASS).
- 2026-11-27 `eccab9a`, `f80fcf4`, `c36fdc8` (D1 rewriter; field-filter verification): run 46073322092: ci ✓, bench ✗ (6 µs gate), integration ✓ (`TestIntegration_FieldFilters` PASS), **e3 ✓: S1–S13, T-S1–T-S5, P4-RSS, P5 PASS** (P4-RSS had no gate yet).
- 2026-11-27 `3cbc170` (E3 profile, E3 gate): run 46073560126: ci ✓, bench ✗ (6 µs gate), integration ✓, e3 ✗: **P4-RSS FAIL** (4,247 generated events/s, gate not evaluated; relayd at 24.74 %). Everything else PASS.
- 2026-11-27 `eb863df` (bench regression gate): run 46073777071: ci ✓, **bench ✓** (9,737 ≤ 12,139 ns), integration ✓, e3 ✗: **P4-RSS FAIL, E3 gate 24.76 % at 5,608 events/s**. Everything else PASS.
- 2026-11-27 `55ef95b`, `db86b5b` (3 P4 loops; field filters wired): run 46078322926: ci ✗ (gofmt, `pipeline_test.go`), integration and e3 skipped.
- 2026-11-27 `3fc8e80`, `4d7b9a7` (P4-GOMAXPROCS1; fuzz minimize time): runs 46078620253, 46078755365: ci ✗ (the same gofmt).
- 2026-11-27 `f77f7c2` (gofmt): run 46078900606: ci ✗ (`TestPipeline_HostileAckDeletesNothingAndResends`, a timing-dependent count), bench ✓.
- 2026-11-28 `c817fb1` (that test): run 46083840295: ci ✓, bench ✓ (15,193 ≤ 19,060 ns, slower runner), integration ✓, e3 ✗: **P4-RSS FAIL** (4,689 generated events/s, gate not evaluated; 24.0 %). Everything else PASS, P5 PASS. P4-GOMAXPROCS1: 15.5 % at 2,805/s (55.4 µs per generated event, against 51.2 µs).
- 2026-11-28 `da61669` (session-2 report; ADR 0039 section 10; ADR 0041): run 46088223116: ci ✓, bench ✓, integration ✓, e3 ✗: **P4-RSS FAIL on the 15 % gate** (24.11 % at 6,800 generated events/s; 63.5 MiB). Everything else PASS, P5 PASS (3,768 generated/s, relayd 1.56 %: not at its quota). P4-GOMAXPROCS1: 12.9 % at 3,274/s.
- 2026-11-28 `846d5cb`, `2d634ab` (decisions-2 committed; P4-RSS CPU report-only, RSS 96/64 MiB): run 46113949265: ci ✓, bench ✓, integration ✓, **e3 ✓: S1–S13, T-S1–T-S5, P4-RSS, P5 and NO_SIGSYS PASS.** P4-RSS: 23.85 % of one core at 5,004 generated events/s (report only), cpu_per_generated 47.7 µs, peak 62.1 MiB. P5 (old form): relayd 1.14 % at 2,501 generated/s, not at its quota.
- 2026-11-28 `fbe4b11`, `d426451`, `283e142`, `b5b1306`, `56501c2` (E1.1, E1.3, E1.5, V1/V2, T-S6): run 46117755144: ci ✓, bench ✓, integration ✓ (E1.5 20/20), e3 ✗ at the V1 step: v1.8.0 has two flags naming "environment" (`--enable-process-environment-variables`, `--filter-environment-variables`).
- 2026-11-28 `dd4f3a3` (V1 picks the boolean --enable-* flag; progress line for `2d634ab`): run 46119904742: ci ✓, bench ✓, integration ✗ (E1.5: one aggregated round got 19 exec / 20 exit), e3 skipped.
- 2026-11-28 `9457c24` (E1.5 alternates aggregated and control rounds): run 46121973985: ci ✓, bench ✓, integration ✓ (6 rounds, all 20/20), e3 ✗: **T-S1 FAIL** (harness: the token in my own grep's argv), **P5 FAIL** (at saturation, 10,363 generated/s, relayd 23.22 %, nr_throttled +1,271: the enforce bundle was APPLIED, not ROLLED_BACK; the kill event never reached the health window). Everything else PASS; T-S6 INFO (12,017 of 120,004 received at 100 msgs/s; `tetragon_notify_overflowed_events_total` 145 → 167,801; no RateLimitInfo).
- 2026-11-28 `940b9d5` (T-S1 token in a pattern file; P5 Tetragon counters; P4-TUNING first): run 46126491257: ci ✓, bench ✓, integration ✓, e3 ✗: **T-S1 FAIL** (V2's absence checks pass; the positive-control probe hit a deadline race), **P5 FAIL** (same as before: APPLIED, not ROLLED_BACK; Tetragon's drop counters flat, RSS 1.76 → 6.97 GB; 0 kprobe events delivered during the flood). Everything else PASS. P4-TUNING: per-event 4,953 vs chunked 4,812 ns per delivered message in the comparable pair.
- 2026-11-28 `b4955a0`, `8c8ac74` (env-probe cancel; report; ADR 0041 E1.1/E1.3): run 46131312207: ci ✓, bench ✓, integration ✓, e3 ✗ **only on P5** (third time: APPLIED, not ROLLED_BACK, at 9,746 generated/s, relayd 23.02 %, nr_throttled +1,251; Tetragon 1.05 cores, drop counters flat, RSS 3.20 → 7.02 GB). **T-S1 PASS with V2**: positive control `with_SECRET_TOKEN=1`; the token was absent from the decoded events, collector store, spool and journal. S1–S13, T-S2–T-S5, P4-RSS (61.9 MiB), NO_SIGSYS PASS; P4-TUNING and T-S6 INFO. **Session 3 stops here, for the architect's decision on S3.9 Q1, Q2 and Q4.**
