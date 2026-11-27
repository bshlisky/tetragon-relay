# ADR 0041: Architecture 8.13's resource targets, measured on Linux

## Status

Proposed (docs/prompts/step-07b.md P4 and Z4). Amends architecture doc 8.13. **The CPU row
is undecided.** The 6 µs per event gate (P3) is enforced and fails at about 15 µs.
Section 4 lists the options, and the decision is the architect's.

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

## Decision (proposed)

8.13's table becomes:

| Metric | Target |
| --- | --- |
| RSS steady state | < 64 MiB, unchanged. relayd measured 62.5 MiB max at 5.7k events/s (E3 P4-RSS) |
| CPU steady state | **open**: pipeline gated at ≤ 6 µs per event (3 % of one core at 5k/s) by step 7b. Measured 15 µs in-process, and ≥ 43.8 µs for the whole relayd (at its 25 % CPU quota). Options in section 4 |
| Apply latency, reconnect | unchanged |
| Spool capacity | 2 GiB holds **≈ 0.5–5 h at 5k events/s** (measured, zstd fastest: 4.5× on a varied corpus, 21.5× on E3's repetitive events). 8 h needs up to ≈ 33 GiB, or ≤ 300 events/s |

## Consequences

- The `bench` job fails until the CPU row is decided and met. That failure is the
  P3 gate working.
- `BENCH_HISTORY` keeps the same-machine comparison reproducible.
