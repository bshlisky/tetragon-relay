// Package audit implements architecture doc 8.3's `audit` module's local
// sink: a structured, bounded, append-only record of every
// security-relevant action, written as one line of JSON per record so
// systemd (Type=notify, no explicit StandardError=, so stderr already
// goes to the journal by systemd's own default) captures it in the
// journal without any extra plumbing. docs/decisions/0033 records this
// as the long-term local sink; journald's own Forward Secure Sealing and
// the central copy via telemetry (architecture doc 8.3's full `audit`
// row) are steps 7/8, not built here.
//
// This package has no dependency on internal/agent or internal/apply:
// both of those packages define their own small Auditor interface and
// AuditEvent shape (Step/Detail/Err[, Domain, Policy]); this package
// defines one shared Event shape instead, and callers (cmd/relayd)
// adapt each package's own AuditEvent to audit.Event with a small,
// package-local adapter -- the same pattern cmd/relayd's existing
// engineAuditorAdapter already uses to bridge agent.Auditor and
// apply.Auditor to each other.
package audit
