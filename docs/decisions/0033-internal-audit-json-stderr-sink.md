# ADR 0033: internal/audit.JSONAuditor is the local sink for architecture doc 8.3's `audit` module

## Status

Accepted.

## Context

Architecture doc 8.3's module table lists `audit`: "Local append-only log of
every security-relevant action... journald entries (Forward Secure Sealing
enabled) plus central copy via telemetry... Structured, no secrets." Through
the end of step 6a's first E3 attempt, every `Auditor` implementation in this
repository (`agent.FakeAuditor`, `apply.FakeAuditor`) was in-memory only, and
`cmd/relayd`'s production `main()` wired `agent.FakeAuditor` -- meaning a
real, running `relayd` process produced **no audit output anywhere**, not
even to its own stderr. This was a known, documented limitation ("no off-host
audit sink yet; architecture doc section 10 is step 7").

docs/prompts/step-06a-e3-prompt.md's S6 scenario ("the audit record names
the stale component") cannot be checked by an external CI harness against a
sink that only exists in memory inside the process under test. The
working agreement's C4 ("No other behavior may differ between \[the E3\]
build and production") rules out a test-only (`testca`-gated) logging
auditor as the fix: that would make audit output itself a behavior
difference between the E3 build and production, which is exactly the kind
of production/test divergence C4 forbids. A real sink, used by every build,
is therefore the only fix consistent with C4 -- not a new scope expansion
of step 6a bundle/reconcile work, just closing a gap the FakeAuditor choice
left in C1-C4's own production startup sequence.

## Decision

`internal/audit.JSONAuditor` (new package) is the local sink architecture
doc 8.3's `audit` module row describes, for every build including
production:

- One JSON line per `audit.Event` (`Step`, `Detail`, `Err` -- an already
  stringified error, `Domain`, `Policy`), written to `os.Stderr`. systemd's
  own default (no `StandardError=` override in
  `packaging/systemd/tetragon-relay.service`) already forwards a unit's
  stderr to the journal, so this requires no packaging change to satisfy
  "journald entries."
- Every field is bounded (`limits.MaxAuditFieldBytes`, truncated not
  dropped) and the whole line is bounded (`limits.MaxAuditLineBytes`,
  falling back to a minimal static line in the practically-unreachable case
  a bounded, all-string struct somehow fails to marshal).
- A `Write` failure is counted (`WriteFailures`), never retried and never
  propagated to the caller: `Record` must not block or panic just because
  a downstream journal forwarder is backed up.
- `Event` is deliberately restricted to plain string fields only (enforced
  by `TestEvent_FieldsAreAllPlainStrings`), so no future field addition can
  smuggle a raw payload (an envelope, policy YAML, or key material) into
  an audit record without a reviewer having to change this type and
  explain why.
- `cmd/relayd/main.go` wires `audit.NewJSONAuditor(os.Stderr, time.Now)`
  unconditionally (production included) via two small, package-local
  adapters (`agentAuditor` for `agent.Auditor`, the updated
  `engineAuditorAdapter` for `apply.Auditor` -- the same adapter-per-
  interface convention this file already used before this change).
  `agent.FakeAuditor`/`apply.FakeAuditor` remain, for unit tests only.

Explicitly **not** built here (step 7/8 scope, per architecture doc 8.3's
`audit` row and section 10): journald Forward Secure Sealing configuration,
a central copy via telemetry, log rotation/retention policy, or redaction
rules beyond the bounding above (every existing `Auditor` caller already
avoids passing key material or raw payloads into `Step`/`Detail`; this ADR
does not change what callers pass in, only how it is durably recorded).

## Consequences

- Production `relayd` now produces real, journal-visible audit output for
  the first time; this is a behavior change for production, not only for
  the E3 build -- deliberately, since C4 required the two to stay
  identical and the only way to do that is to give production the real
  sink rather than giving the test build a fake one.
- `internal/audit` is added to the Makefile's `>= 90%` coverage gate
  (`COVER90_PKGS`).
- E3's S6 scenario asserts on `journalctl -u <transient unit>` output
  containing the `watchdog_withheld` record naming the stale component,
  rather than needing any new debug-only instrumentation.
- A later step replacing this with a richer sink (Forward Secure Sealing,
  telemetry forwarding) only needs to satisfy the same `audit.Sink`
  interface; `cmd/relayd`'s two adapters and every existing `Auditor`
  caller are unaffected.
