# Architect decisions: step 7b, after session 1 (origin/main @ 07e3784)

Reviewer: architect · Date: 2026-11-27

**Session 1 is accepted.** Stopping at P3, rather than relaxing the gate, was the right call.

- The profile work is good, and building earlier commits on the same runner
  (`BENCH_HISTORY`) makes the numbers comparable.
- Field-specific redaction cut that stage from 12 µs to 2 µs.
- Dropping unknown fields closes a real gap.
- The P4-RSS measurement under the real unit is the most useful number in the report.

Session 1 also exposed a more important problem than the CPU target. It is decided first
(D0). The answers to report section 9 follow.

## D0 [HIGH, new] Telemetry load must never starve the control plane

The data: at 5.6k events/s, relayd uses its whole `CPUQuota=25%` (P4-RSS: 24.7–24.9 %).
Telemetry and the control stream live in one process and share one quota, and Go does not
schedule by priority. A burst of events can therefore delay heartbeats, the apply worker's
health window, and the watchdog ping. The consequences:

- a delayed heartbeat means a false SILENT or LOST, which **quarantines a healthy host**;
- a delayed watchdog ping means a restart.

A noisy workload (or an attacker generating exec noise on purpose) must not be able to get
a host quarantined, or an apply rolled back.

**The requirement:** under any event rate Tetragon can deliver, the control plane meets
its timing:

- heartbeats every 15 s, with no gap above 20 s;
- applies complete within their health window;
- no watchdog timeout.

**The mechanism**, in this order:

1. **Admission control at ingest.**
   - A token bucket limits **non-security** events to `collector.max_event_rate`
     (default 2000/s, set by config only within a hard maximum in limits).
   - Events over the budget are dropped *before* decode, counted, and declared in the
     chain as `dropped` records (class `non_security`, reason `rate_limited`). They are
     never silent.
   - Security events are not rate-limited. Their volume is set by the signed policies,
     and a policy that floods is a policy problem the controller can see.
2. **The telemetry goroutines yield.**
   - The builder's per-batch work is bounded.
   - The exporter's send is never on a goroutine the control stream waits on (confirm
     this; it should already hold).
3. **Prove it in E3 with a new scenario, P5-CONTROL-UNDER-LOAD:**
   - run the P4 flood at the maximum rate the runner can generate (more than 5k/s);
   - **during** the flood, deliver S7's monitor bundle;
   - assert no heartbeat gap above 20 s at the controller, `APPLIED` within the health
     window, no `Watchdog timeout`, `rate_limited` dropped records in the chain, and
     security events (the S7 canary kprobe) still delivered.

   This scenario is the gate that matters. A per-event CPU number is a regression check.

## D1 CPU: option (a), wire-level redaction, plus Tetragon field filters

- **Approved: (a) wire-level redaction.** Amend ADR 0039. The rewriter parses
  Tetragon's bytes, so it is a parser and is held to parser standards:
  - **Differential fuzzing:** a fuzz target asserts that the rewriter's output equals
    decode → redact → marshal (`proto.Equal`) for every input both accept. When
    exactly one of the two rejects an input, that is a failure.
  - Malformed input (bad varint, length past the end, nesting deeper than a bound,
    wrong wire type for a known field) is rejected, counted, and never passed through.
  - Unknown fields are dropped, as now.
  - The descriptor-built plan is generated, or built once at startup and checked
    against the vendored v1.8.0 descriptors in CI. The existing redactgen check
    pattern is fine.
- **Also, as a separate change measured on its own:** check the vendored v1.8.0
  `GetEventsRequest` for field filters (`field_filters`, a FieldMask-based
  include/exclude). Use them to stop Tetragon from sending fields we drop anyway, such
  as the environment and anything not on the allow-list. Fewer bytes means less gRPC
  receive and decode cost. Verify from the vendored API and the real binary; don't
  guess. If filters exist, redaction stays in place as defense in depth.
- **Profile relayd itself in E3.** Add an e3-tag CPU profile of the running relayd
  during P4, uploaded as an artifact. The benchmark sees about a third of the real cost,
  so the remaining two-thirds (gRPC receive, TLS export, GC) need their own breakdown.
- **Replace the gates:**
  - **Benchmark gate:** the pipeline's CPU per event at most 25 % above the value
    measured after D1 lands, on the same-machine history. It is a regression gate,
    recorded in ADR 0041.
  - **E3 gate:** at 5k events/s, the whole relayd uses ≤ 15 % of one core. That leaves
    10 points of the 25 % quota for the control plane. Admission control (D0) is
    allowed to reach this by dropping non-security events; it is the configured
    budget's job.
  - The 6 µs gate is retired. Its job is taken over by the two gates above and the
    P5 scenario.
- **ADR 0041 amends architecture 8.13:** replace "< 1 % at 5k/s" with the two gates
  above, the measured per-event costs, and an explicit statement that 5k/s of
  *non-security* events is above the default admission budget.

**Until D1 lands:** the bench job must not leave main red. Make the 6 µs check
report-only, in the same commit that records this decision, and restore a blocking gate
with the D1 values.

## D2 Spool capacity: (b) and (c), and size it per site

- 2 GiB stays the default, configurable.
- ADR 0041 states capacity as measured hours per GiB at a stated event rate and ratio,
  not as one number. On disk per event is 23 B to 243 B, so 2 GiB holds 0.5–5 h at
  5k/s, and at least 4 h at 1k/s even with the pessimistic ratio.
- With D0's default budget, the sustained rate of non-security events is at most 2k/s,
  which roughly doubles these figures.
- Overflow drops non-security batches first (as built), so security events survive the
  longest outage.
- Operators size the spool per site from the event rate they observe, so the controller
  needs that rate. Add `telemetry_events_per_s` (a 60 s average) to `Heartbeat`, and
  write the spool-sizing formula into docs/telemetry-contract.md.
- **Customer question** (I'll ask): the disk budget for `/var/spool` on their hosts.

## D3 R7A-5 refinements (your section 9.3): all accepted, with these specifics

- **Reserve the `telemetry` scope.** A policy bundle that names it is rejected
  `REJECTED_TARGET`.
- **Drop step 11** for telemetry policies. Its replacement is a schema check that the
  document has no YAML policy content.
- **`keep_env` stays signed by targets**, with a mandatory built-in deny list. A name
  containing any of `TOKEN`, `SECRET`, `PASS`, `PWD`, `KEY`, `CRED`, `AUTH`, `COOKIE` or
  `SESSION` is rejected `REJECTED_GUARDRAIL`, compared case-insensitively. Signed
  policy can't change this list. Root signatures aren't needed: the deny list keeps
  the risk small, and targets is already threshold-signed.
- **Protected event types:** `process_kprobe`, `process_lsm`, `process_tracepoint` and
  `process_uprobe` can never be removed from the allow-list.
- **Expiry:**
  - telemetry policies carry `expires` like bundles (≤ 90 days);
  - an expired policy **keeps applying** (it can only add collection and redaction to
    the built-ins), and the agent raises a new `Alert` kind,
    `TELEMETRY_POLICY_EXPIRED`, rate-limited like the others;
  - a new policy must be newer by epoch and unexpired.
- **Tampered mode:** built-in defaults only, `telemetry_policy_epoch: 0`, and every
  `TelemetryPolicy` is rejected `REJECTED_TAMPERED`.

## D4 fsync: keep the separate head

Four syncs per batch cost about 1.5 % of samples, which is negligible. Being able to
detect a local root deleting the newest unsent batches is worth more. Accepted as built.
Record it in ADR 0039.

## D5 `CPUQuota=25%` stays

It is the ceiling that keeps relayd from hurting the workload it protects. D0 and D1 make
the telemetry pipeline live within it, with room left for the control plane. T-S6 (slow
client) runs under this quota as shipped.

## Session 2 scope and order (replaces the prompt's priority list for what remains)

1. Make the bench gate report-only (with this file's commit).
2. D0 admission control, plus the P5-CONTROL-UNDER-LOAD E3 scenario.
3. D1 wire-level redaction with differential fuzzing.
4. D1 field filters (verify, then measure separately).
5. D1 E3 relayd profile, then the new gates and ADR 0041 finalized.
6. V1 and V2 (environment flag and secret-token proof), then V3 / T-S6.
7. Part S with D3, then T-S7.
8. D2 contract and heartbeat field, S6 contract additions.

This is likely **two more sessions**. The first should stop at a green boundary after
item 5.

**Definition of done for 7b:**

- ci, integration and e3 green, with S1–S13, T-S1 to T-S7, P4-RSS and
  P5-CONTROL-UNDER-LOAD passing;
- the restored blocking gates passing;
- ADRs 0039 and 0041 updated.
