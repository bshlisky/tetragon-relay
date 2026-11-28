# ADR 0041: Architecture 8.13's resource targets, measured on Linux

## Status

Proposed (docs/prompts/step-07b.md P4 and Z4; docs/reviews/step-07b-decisions.md D0,
D1, D2; docs/reviews/step-07b-decisions-2.md E1–E3). Amends architecture doc 8.13. The
first decisions replaced the 6 µs gate with two gates (section 7). The second decisions
retired the 15 % E3 gate: P5-CONTROL-UNDER-LOAD at saturation is the binding gate, and
relayd's E3 CPU is report-only (section 9).

## Context

Architecture 8.13 targets < 1 % of one core at 5k events/s, < 64 MiB RSS, and
2 GiB of spool for about 8 h at 5k events/s compressed. 7a measured about 8 % of a core,
on an M2, with the harness included (step-07a report, section 13). Step 7b measures on the
CI runner and profiles the pipeline alone, then optimizes. R7A-1 set the gate at
≤ 6 µs of pipeline CPU per event (3 % of a core at 5k/s).

## Measurements

### 1. Method

- `BenchmarkPipeline5k` (`internal/telemetry/bench_test.go`) reads pre-marshaled
  events, so decoding is the pipeline's own first stage.
  - The corpus is 8192 distinct events from a deterministic generator: 55 % exec,
    40 % exit, 5 % kprobe. Each has 1–3 ancestors, varying pids, exec IDs and
    arguments, and some secrets and `~/.ssh` paths.
  - Each event runs through classify, redact, marshal, batch, chain, compress, the
    HMAC'd and fsynced spool, the export read and an in-process collector that acks.
- CPU is the process's `getrusage` user and system time over the measured window,
  GC included. The harness only waits in that window, so this is an upper bound.
- `scripts/bench-gate.sh` (ci job `bench`) runs per-stage benchmarks and CPU and
  allocation profiles, and gates the worst of 3 runs.
- **GitHub's `ubuntu-24.04` runners differ.**
  - Run 46035767467 got an AMD EPYC 7763: decode 6.1 µs per event.
  - Later runs got an Intel Xeon 6975P-C: decode 3.9 µs.

  So `BENCH_HISTORY` rebuilds each commit's benchmark and runs them all on the
  same machine.

### 2. CPU per event: before and after each change, on one machine

Intel Xeon 6975P-C, run 46040250809. Pipeline CPU is the mean of 2 runs of
200,000 events.

| Commit | Change | Decode | Redact | Marshal | Compress | Spool (+read) | **Pipeline** | % core at 5k/s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `7a35c03` | 7a pipeline (baseline) | 4.03 µs | 12.11 µs | 2.19 µs | — | 7.64 µs | **35.0 µs** | 17.5 % |
| `4b22e1a` | field-specific redaction | 3.87 | 1.93 | 2.21 | — | 7.66 | **22.4 µs** | 11.2 % |
| `25ac330` | reused buffers; HMAC over the batch hash | 3.83 | 1.90 | 2.12 | — | 3.34 | **15.3 µs** | 7.6 % |
| `0b99e92` | zstd (SpeedFastest) | 3.89 | 1.93 | 2.20 | 2.85 | 3.94 (includes compress) | **14.9 µs** | 7.5 % |

On the gate run: **15050–15387 ns per event, 7.5–7.7 % of one core.** The gate fails.

### 3. Where the remaining 15 µs goes

Share of all CPU samples, run 46040250809:

| Stage | Share |
| --- | --- |
| decode | 33.7 % |
| redact | 17.2 % |
| compress | 17.2 % |
| marshal | 16.6 % |
| spool, without compress | 1.5 % |
| export | 1.8 % |
| GC background workers | 3.7 % |

Decode (`proto.Unmarshal`, 86 allocations per event) and re-marshal together are
about 6 µs per event on this machine. That alone is the whole gate, so no tuning
inside the current design reaches 6 µs.

### 4. Options for the CPU row (architect's decision)

1. **Redact on the wire.**
   - Receive `GetEvents` frames as bytes (a raw codec on that one RPC, in
     `internal/tetra`) and rewrite only the fields redaction touches. Use a
     per-message plan built once from the v1.8.0 descriptors, drop unknown fields,
     and copy everything else.
   - This removes decode and re-marshal. A test-only prototype, checked equal to
     decode → redact → marshal with `proto.Equal` on 200 corpus events, costs
     2.4 µs per event on M2, against 6.7 µs for decode → redact → marshal there.
   - Estimate on the runner: about 15 − 8.0 + 2.8 ≈ 10 µs with zstd (decode, redact and marshal are 8.0 µs; the prototype scaled by the runner/M2 decode ratio, 1.18, is 2.8 µs), and still
     over 6 µs because of compression (2.85 µs).
   - Amends ADR 0039 (records are Tetragon's bytes with redacted fields rewritten,
     not a deterministic re-marshal). It adds a hand-written wire parser, which is
     attack surface: fuzzed against the decoder as an oracle.
2. **Option 1 plus a cheaper codec or no compression on the hot path.**
   - The stdlib has no LZ4 or S2.
   - `klauspost/compress/s2` is in the same, already-vendored module. Its ratio is
     unmeasured here.
   - Trades spool hours for CPU.
3. **Keep the design and set the target to the measured value:** about 8 % of one
   core at 5k events/s (16 µs per event, with headroom on the slower runner type).

### 5. relayd under the real unit (E3 P4-RSS, runs 46051067160 and 46056428748)

The production unit was used unchanged: `MemoryMax=256M`, `CPUQuota=25%`. Two exec
loops ran for 60 s.

| Measure | Value |
| --- | --- |
| Measure | Run 46051067160 | Run 46056428748 |
| --- | --- | --- |
| Events received | 342,002 in 60.3 s, **5,676 events/s** | 338,002 in 60.2 s, **5,610 events/s** |
| relayd CPU (`utime+stime` from `/proc`) | 14.97 s, **24.85 % of one core** | 14.89 s, **24.71 % of one core** |
| CPU per event | **≥ 43.8 µs** | **≥ 44.1 µs** |
| Max VmRSS (sampled each second) | **62.5 MiB** (VmHWM 63,712 kB) | **61.7 MiB** |

Both runs put relayd at the unit's 25 % quota. systemd's figure for the first run was
"Consumed 15.221s CPU time, 47.5M memory peak".

The CPU per event is a lower bound: events that drained after the load stopped are
counted, but their CPU is not.

- **The whole agent costs about 3× the benchmark.** The pipeline benchmark measures
  15 µs per event in-process. The rest is outside it: gRPC and HTTP/2 receive on the
  Tetragon socket, export over TLS, the control session, and GC under the quota.
  - At 5k events/s the agent is at its 25 % CPU quota, so it can't keep up with much
    more.
  - Any CPU option in section 4 must be measured this way too, not only by the
    benchmark.
- **RSS is just under the target** (62.5 MiB against < 64 MiB) at 5.7k events/s.
- **Tetragon kept delivering after the flood.** 10 s later, events arrived both at the
  same relayd and at a restarted one. Tetragon logged no drop or rate warnings
  during it (run 46056428748).

### 6. Spool capacity

`BenchmarkStageCompress` on the corpus measures:

| Figure | Value |
| --- | --- |
| Compression ratio | 4.51× |
| Uncompressed, per event | 1091 B |
| On disk, per event (header, framing and HMAC included) | 243 B |
| 2 GiB holds, at 5k events/s | **0.49 h** |

`BenchmarkCompressOptions`, other levels and batch sizes:

| Batch size | Level | Ratio | Hours per 2 GiB |
| --- | --- | --- | --- |
| 1 MiB | fastest | 4.51× | 0.49 h |
| 1 MiB | default | 4.76× | 0.52 h |
| 1 MiB | better | 4.85× | 0.53 h |
| 4 MiB | fastest | 4.50× | 0.50 h |
| 4 MiB | default | 4.79× | 0.53 h |
| 4 MiB | better | 4.95× | 0.55 h |

On real Tetragon v1.8.0 events (E3 P4-RSS, run 46051067160):

| Figure | Value |
| --- | --- |
| Compression ratio | **21.5×** (21.45× in run 46056428748) |
| Decoded, per event | 502 B |
| Sent, per event | 23.3 B |
| On disk, per event (with batch overhead, about 2,000 events per batch) | ≈ 23.7 B |
| 2 GiB holds, at 5k events/s | **≈ 5.0 h** |

That workload is one repeated exec, so it is the optimistic bound. The corpus is the
pessimistic one. A real host falls between 0.5 h and 5 h.

- **The 8.13 figure is out by an order of magnitude.** "2 GiB ≈ 8 h at 5k
  events/s compressed" needs ≤ 15 B per event on disk. The 7a report's
  "~55 min uncompressed" was an arithmetic slip:
  - it computed 1 KiB × 5000/s × 8 h as 18 GB; the right figure is 147 GB;
  - so 2 GiB holds about 7 min uncompressed, not 55.
- **What 8 h actually needs** at the measured 243 B per event and 5k events/s:
  about 33 GiB of spool.
- Alternatively, 2 GiB holds 8 h at about 300 events/s.

The architect decides between a larger cap, a shorter outage window, or a
lower rate target.

### 7. Step 7b session 2: D0 and D1, on one machine

Intel Xeon 6975P-C, ci job `bench`, run 46073777071 (`BENCH_HISTORY`, mean of 2 runs of
200,000 events):

| Commit | Change | Pipeline CPU per event | % core at 5k/s |
| --- | --- | --- | --- |
| `0b99e92` | zstd (session 1's last) | 14.64 µs | 7.3 % |
| `d9e83a4` | D0: raw bytes from `GetEvents`, admission control (decode moves into the pipeline) | 15.36 µs | 7.7 % |
| `f80fcf4` | D1: wire-level redaction | **9.73 µs** | **4.9 %** |

Stages on that run: rewrite 3.9 µs (9 allocations), against decode 3.8 + redact 1.8 +
marshal 2.0 µs for the path it replaces; compress 2.84 µs; spool 3.93 µs per event
(compression included). Share of the pipeline profile: rewrite 40 %, spool 34 % (of
which compress 28 %), export 6 %, GC 2 %.

**The two gates (D1):**

- **Benchmark (regression) gate**, blocking, in ci job `bench`: the worst of 3 runs of
  HEAD uses at most 1.25 × the median of 3 runs of `f80fcf4`, built and run alternately
  on the same runner. On run 46073777071: worst HEAD 9,737 ns, reference median 9,711 ns,
  limit 12,139 ns. **PASS.**
- **E3 gate**, in `P4-RSS`: at ≥ 5k generated events/s, the whole relayd uses ≤ 15 % of
  one core, which leaves 10 points of the 25 % quota for the control plane. Admission
  control may reach this by dropping non_security events: that is the configured
  budget's job.
- The 6 µs gate is retired.

**5k events/s of non_security events is above the default admission budget**
(`collector.max_event_rate`, 2000/s, hard maximum 5000/s). At the default, a host
flooding exec events sends at most 2000 of them per second, and declares the rest in
`rate_limited` dropped records.

**Field filters (D1, measured separately).** Tetragon v1.8.0 accepts
`GetEventsRequest.field_filters` with action EXCLUDE and keeps streaming. Paths are
relative to the event message (integration run 46073322092, `TestIntegration_FieldFilters`).
Bytes per exec event as received:

| Filter | Bytes per event |
| --- | --- |
| none | 528 |
| `process/parent/ancestors.environment_variables` | 528 |
| `process.cwd` | 522 |
| `process.arguments`, `process.cwd` | 506 |

relayd now excludes the environment. That saves nothing by default, because Tetragon
sends no environment unless its flag is set (V1). Redaction still removes it.

### 8. relayd itself under load (E3, with D0 and D1)

`P4-RSS` with the default budget, the real unit (`CPUQuota=25%`, `MemoryMax=256M`):

| Run | Commit | Generated | Received (admitted) | relayd CPU | Max VmRSS |
| --- | --- | --- | --- | --- | --- |
| 46073322092 | `c36fdc8` (D0, before D1 in E3) | not counted (2 loops) | 2,025/s | **24.78 %** | 62.8 MiB |
| 46073560126 | `3cbc170` (D0 + D1) | 4,247/s (2 loops) | 1,988/s | **24.74 %** | 61.5 MiB |
| 46073777071 | `eb863df` (D0 + D1) | **5,608/s** (2 loops) | 1,992/s | **24.76 %** | 63.2 MiB |
| 46083840295 | `c817fb1` (D0 + D1, field filters) | 4,689/s (3 loops) | 1,985/s | **24.01 %** (GOMAXPROCS 2) | 63.2 MiB |
| 46083840295 | `c817fb1`, `GOMAXPROCS=1` (P4-GOMAXPROCS1, report-only) | 2,805/s | 2,023/s | 15.54 % | — |

**The E3 gate fails:** 24.76 % of one core at 5,608 generated events/s, against ≤ 15 %
(run 46073777071, `E3 CPU gate: relayd used 24.76% of one core at 5608 events/s (> 15%)`).
On `3cbc170` the runner generated under 5k events/s, so the gate was not evaluated, and
relayd still sat at its quota.

**relayd's own CPU profile** (`3cbc170`, 50 s during the load, artifact
`e3-relayd-profile-46073560126`): 10.32 s of samples in 50 s (20.6 % of a core).

| Where | Share |
| --- | --- |
| `syscall` (the gRPC reader's `read` on the Tetragon socket, `http2Client.reader` 42 % cumulative) | 45.6 % flat |
| `futex` (goroutine wake-ups) | 16.6 % flat |
| scheduler (`schedule`/`findRunnable`, incl. `netpoll`/`epoll_wait`) | ~33 % cumulative |
| the telemetry pipeline (`Pipeline.build`, the rewrite included) | 5.5 % cumulative |
| `grpc.recv` (message reassembly) | 5.3 % cumulative |

Tetragon sends one gRPC message per event. Each one costs relayd socket reads, HTTP/2
frame parsing and goroutine hand-offs (reader → stream → ingest), **before admission
control sees it**. Admission drops non_security events before decode, but the receive
cost is already paid. That is why relayd stays at its quota while admitting only 2k
events/s. The pipeline itself is now about 5 % of relayd's CPU.

D0's goal holds regardless: P5-CONTROL-UNDER-LOAD passed on both runs (no heartbeat gap
above 15.0 s, `APPLIED` during the flood, no watchdog timeout). The 15 % gate does not
hold at this event rate, and no change inside relayd's pipeline can make it hold. The
options, for the architect:

1. **Shed at the source.** Tetragon's `GetEventsRequest` has `deny_list` filters
   (binary, namespace, pod, ...). relayd cannot rate-limit there, but a signed policy
   (Part S) could deny known-noisy binaries. That doesn't bound an attacker's own exec
   noise.
2. **Cut the per-message cost**: GOMAXPROCS (the scheduler share; measured in
   `P4-GOMAXPROCS1`, report-only), gRPC read-buffer sizes, or a dedicated receive path.
   These are tuning, and they don't change the per-event receive. Measured:
   GOMAXPROCS=1 costs 55.4 µs per generated event, against 51.2 µs at the default of 2
   (run 46083840295), so it is not a lever.
3. **Accept the receive cost and set the E3 gate on admitted events**, or raise it to
   the measured whole-relayd value at 5k generated/s. The quota still caps relayd at
   25 %, and P5 shows the control plane keeps its timing at that cap.

### 9. Step 7b session 3: E1.2, E2, E3 (docs/reviews/step-07b-decisions-2.md)

**E1.2: relayd's E3 CPU is report-only, not a regression gate.** The decision asked for
`cpu_per_generated` ≤ 1.25 × the value on the commit that lands E1, measured on the same
run or by a ratio robust across runners, or report-only if that is too expensive. It is
report-only, for a reason stronger than cost: under the unit's `CPUQuota=25%` relayd
sits at its quota during P4-RSS's flood (24.0–24.8 % in every run in section 8), so
`cpu_per_generated` ≈ 0.25 core / generator rate. It measures the generator, not relayd:

| Run | Commit | Generated | relayd CPU | cpu_per_generated |
| --- | --- | --- | --- | --- |
| 46083840295 | `c817fb1` | 4,689/s | 24.01 % | 51.2 µs |
| 46088223116 | `da61669` (docs only after `c817fb1`) | 6,800/s | 24.11 % | 35.5 µs |

The same code moved 1.44×, past a 1.25× gate, in both directions depending on the
runner. A same-run history build would cancel the runner difference, but not the quota:
both builds would read about 25 %. A regression gate needs relayd below its quota,
which means a load below what P4-RSS is for. P4-RSS prints relayd's CPU %, the generated
rate and `cpu_per_generated` on every run (`P4-RSS CPU (report only): ...`). E1.3
(chunked handoff, gRPC buffers) is measured by the CPU profile's shares and by the
admitted rate at the quota, not by this ratio.

**E2: RSS.** The target is < 96 MiB at the admission budget. P4-RSS fails at ≥ 96 MiB,
warns at ≥ 64 MiB, and prints its peak on every run (`P4-RSS peak VmRSS=...`).
`MemoryMax=256M` stays the hard bound. `GOMEMLIMIT` is not set: it would trade memory for
GC CPU, the scarcer resource.

**E3: spool.** 2 GiB stays the default, stated as a measured range (2.5–25 h at 1k
events/s, section 6 and the table below). The per-host disk budget comes from the
customer; the contract's sizing formula covers the rest.

## Decision (proposed)

8.13's table becomes:

| Metric | Target |
| --- | --- |
| RSS steady state | < 96 MiB at the admission budget (E2); P4-RSS fails at ≥ 96 MiB and warns at ≥ 64 MiB. `MemoryMax=256M` untouched, `GOMEMLIMIT` unset. relayd measured 61.5–63.5 MiB max under load (E3 P4-RSS) |
| CPU, pipeline | Regression gate: ≤ 1.25 × `f80fcf4`'s CPU per event on the same runner (`bench`). Measured 9.7 µs per event, 4.9 % of one core at 5k/s, on an Intel Xeon 6975P-C |
| CPU, whole relayd | Capped by the unit's `CPUQuota=25%`. Reported, not gated, in P4-RSS (section 9): relayd reaches its quota at ≥ 4k generated events/s, admitting 2.0k/s. The 15 % gate is retired (E1) |
| Control plane under load | **Binding gate (E1.1):** E3 `P5-CONTROL-UNDER-LOAD`, with relayd shown to be at its quota during the flood: no heartbeat gap above 20 s, applies complete in their health window, an enforce bundle rolls back with heartbeats continuing, no watchdog timeout |
| Event budget | `collector.max_event_rate` non_security events/s, default 2000, hard maximum 5000. Security events are not rate-limited. 5k/s of non_security events is above the default budget |
| Apply latency, reconnect | unchanged |
| Spool capacity (D2, E3) | 2 GiB default, configurable. Stated as hours per GiB at a rate and ratio: on disk an event takes 23 B (E3's repetitive load, 21.5×) to 243 B (varied corpus, 4.5×), so 2 GiB holds **0.49–5.0 h at 5k events/s** and **2.5–25 h at 1k events/s** (2 GiB / (243 B × 1000/s) = 2.45 h). With the default budget, sustained non_security traffic is at most 2k/s (1.2–12.6 h per 2 GiB). Overflow drops non_security batches first. The per-host disk budget is the customer's; operators size the spool from the observed rate (contract formula) |

## Consequences

- The `bench` job blocks on a regression against D1's commit, measured on the same
  machine, not on an absolute number.
- P4-RSS fails only on RSS ≥ 96 MiB, too few events, or a relayd restart. Its CPU line
  is data for this ADR.
- P5 carries D0's guarantee; it fails as "not evaluated" if relayd never reached its
  quota during the flood (E1.1).
- `BENCH_HISTORY` keeps the same-machine comparison reproducible.
