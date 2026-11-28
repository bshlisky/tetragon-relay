# Architect decisions: step 7b, after session 2 (origin/main @ da61669)

Reviewer: architect · Date: 2026-11-27

**Session 2 is accepted.** D0 did its job, and it found a real starvation path: the
heartbeat waited on the spool mutex, which is held across compression and four fsyncs
(`d9e83a4`). That bug would have produced false SILENT reports in production, so this
alone justified the work. P5 passes with a worst heartbeat gap of 15.003 s under the
flood. The wire rewriter brought pipeline CPU from 15.4 µs to 9.7 µs, with differential
fuzzing in place, and the E3 profile showed where the rest goes.

## E1 (answers S2.9 Q1): option (c), with P5 as the binding gate, plus two changes

The profile settles it. Only about 5 % of relayd's CPU is the pipeline, while about 46 %
is `read` on the Tetragon socket and about 33 % is the scheduler. That cost is paid per
message Tetragon delivers, before admission control can drop anything. A 15 % gate at
5k generated events/s is therefore a target relayd can't reach by itself. I set it
without that data.

What D0 actually needs is that the control plane keeps its timing while relayd is at
its quota. P5 measures exactly that.

1. **P5-CONTROL-UNDER-LOAD is the binding gate.** Strengthen it so it proves the
   saturated case:
   - **Use a compiled exec generator** (this answers Q3), e3 tag, `cmd/e3execflood`:
     N workers in a tight `fork`/`execve("/usr/bin/true")` loop, with N and the
     duration as flags. Target the most the runner can do. Record generated/s; there
     is no minimum, but print it.
   - P5 **asserts that relayd was at its quota during the flood** (cgroup
     `cpu.stat` `nr_throttled` > 0, or usage ≥ 23 % of one core). Otherwise the
     scenario hasn't tested the saturated case and fails as "not evaluated", as
     P4-RSS does today.
   - **Add an enforce case to P5:** during the flood, deliver S12's enforce bundle,
     which must roll back (`ROLLED_BACK`, heartbeats continuing). A rollback under
     load is the riskiest path to starve, so test it.
2. **The E3 CPU number becomes a regression gate, like the bench:**
   `cpu_per_generated` in P4-RSS must stay ≤ 1.25 × the value measured on the commit
   that lands E1, on the same run (a history build), or using a ratio that is robust
   across runners. If the same-machine method is too expensive in E3, make it
   report-only, and say so in ADR 0041. The 15 % gate is retired.
3. **Cut the per-event handoffs (option b, the cheap part).**
   - The scheduler's ~33 % is mostly one channel operation and one wake-up per event,
     from the reader to the queue to the builder.
   - Hand off in chunks instead: the reader collects up to 64 messages, or whatever
     it has after a short non-blocking drain, and sends the slice.
   - Admission (`peekAdmit`) stays in the reader, before any copy.
   - Measure it in E3 with the same profile. Keep it if `cpu_per_generated` drops; drop
     it if not.
   - Also try `grpc.WithReadBufferSize` / `WithInitialWindowSize` on the Tetragon
     connection, measured the same way. Don't guess at a value.
4. **Option (a), shedding at the source, is approved as an operator tool, not as the
   defense.** The signed telemetry policy (Part S) may set `GetEventsRequest.deny_list`
   entries for **non-security** noise, for example a known-chatty binary's
   `process_exec`. The protected types under D3 can't be denied, and a guardrail
   enforces it. As Claude Code says, this doesn't bound an attacker, which is why P5 is
   the gate.
5. **Check, don't assume: `GetEventsRequest.aggregation_options`.** It exists in the
   API. Read the vendored v1.8.0 API and the real binary's behavior to find out
   whether it reduces the message count for exec and exit events, and whether it
   loses or alters fields we need. Report it; don't build on it unless it's clearly
   safe.

## E2 RSS headroom [new]

P4-RSS peaked at 63.2 MiB against the < 64 MiB target, which leaves 1.2 % headroom; it
will flake. `MemoryMax=256M` is the hard bound and stays. In ADR 0041:

- set the RSS target to < 96 MiB at the admission budget;
- have P4-RSS fail above 96 MiB and only warn above 64 MiB;
- record the peak in every run's report line.

Don't set `GOMEMLIMIT` to force the old number: that trades memory for GC CPU, which
is the scarcer resource now.

## E3 (answers S2.9 Q2): the arithmetic

This one is my error: at 243 B per event, 2 GiB holds about 2.45 h at 1k/s, not "at
least 4 h". ADR 0041's statement of the measured range (2.5–25 h at 1k/s) is the right
form. Keep 2 GiB as the default. I'll get the per-host disk budget from the customer;
the sizing formula in the telemetry contract covers the rest.

## E4 Q3: answered in E1.1 (yes, a compiled generator)

## The e3 job must be green before anything else

Apply E1.2 to P4-RSS first: make its CPU check the regression or report-only form, so
"not evaluated" isn't a failure. Then rebuild green, and continue.

## Session 3 scope and order (replaces items 6–8 of the session 2 plan)

1. E1.2 and E2: P4-RSS changes; e3 green. Record the progress-log line for da61669.
2. E1.1: the compiled generator, P5 at saturation, P5's enforce/rollback case.
3. E1.3: chunked handoff and the gRPC buffer settings, measured.
4. E1.5: an aggregation_options check (report only).
5. V1, V2 (the environment flag, the secret-token proof), then V3 / T-S6 (using the
   compiled generator and the throttle hook).
6. Part S with D3 and E1.4 (`deny_list`), then T-S7.
7. D2's contract and heartbeat field, and S6's contract additions. ADR 0041 moves to
   Accepted.

Stop at a green boundary after item 4 if the session runs long. A fourth session
finishing items 5–7 is fine.

**Definition of done for 7b:** ci, integration, bench and e3 green, with these passing:

- S1–S13 and T-S1 to T-S7;
- P4-RSS (in its new form);
- P5-CONTROL-UNDER-LOAD at saturation, with its monitor and enforce cases.

ADRs 0039 and 0041 are Accepted.
