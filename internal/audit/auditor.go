package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// Event is one structured audit record. Every field is a plain string
// (never a []byte, interface{} or embedded struct) by construction: a
// caller cannot accidentally attach a raw payload (an envelope, policy
// YAML, or key material) to an Event without changing this type itself,
// which TestEvent_FieldsAreAllPlainStrings guards against regressing.
type Event struct {
	// Step identifies what was happening, e.g. "crypto_self_test",
	// "watchdog_withheld", "apply".
	Step string
	// Detail is a short, human-readable description.
	Detail string
	// Err is the associated error's Error() string, or empty. Callers
	// pass the already-stringified error (not an error value): Event
	// has no error-typed field at all, so there is no way for a caller
	// to hand this package something other than a string without
	// calling Error() themselves first, keeping every field here
	// provably just a string end to end.
	Err string
	// Domain and Policy are apply.AuditEvent's own two extra fields,
	// carried through unchanged by cmd/relayd's apply.Auditor adapter;
	// empty for every agent.AuditEvent-sourced record.
	Domain string
	Policy string
}

// Sink is the minimal interface this package's own tests and any future
// alternative implementation (e.g. a buffering sink for a later step)
// need to satisfy.
type Sink interface {
	Record(Event)
}

// JSONAuditor writes each Event as one line of JSON to Out, timestamped
// with Clock (never time.Now directly, matching this project's "no
// time.Now in internal/" rule): the agent-startup sequence's own clock,
// injected by the caller.
type JSONAuditor struct {
	out   io.Writer
	clock func() time.Time

	mu sync.Mutex
	// writeFailures counts Out.Write errors this Auditor has swallowed
	// (never retried, never blocks the caller): Record must not panic
	// or block indefinitely just because, say, a full-disk journal
	// forwarder is backed up.
	writeFailures uint64
}

// NewJSONAuditor constructs a JSONAuditor. Both out and clock are
// required (a nil out or clock would make every record silently
// vanish or carry a meaningless zero timestamp -- a secure-zero-value
// violation for a component whose entire purpose is the audit trail
// architecture doc 8.3/10 requires).
func NewJSONAuditor(out io.Writer, clock func() time.Time) (*JSONAuditor, error) {
	if out == nil {
		return nil, fmt.Errorf("audit: out must not be nil")
	}
	if clock == nil {
		return nil, fmt.Errorf("audit: clock must not be nil")
	}
	return &JSONAuditor{out: out, clock: clock}, nil
}

// WriteFailures returns the number of Out.Write errors this Auditor has
// swallowed since construction, for a caller's own health reporting
// (not consumed by anything in this step).
func (a *JSONAuditor) WriteFailures() uint64 { return atomic.LoadUint64(&a.writeFailures) }

// jsonLine is the exact, closed shape of one marshaled audit line: only
// these fields, ever, so a future field added to Event is a deliberate,
// reviewed change to this struct too, never an accidental new key in the
// journal.
type jsonLine struct {
	Time   string `json:"time"`
	Step   string `json:"step"`
	Detail string `json:"detail,omitempty"`
	Err    string `json:"err,omitempty"`
	Domain string `json:"domain,omitempty"`
	Policy string `json:"policy,omitempty"`
}

// Record implements Sink. It never blocks indefinitely (a single
// buffered Out.Write, no retry) and never panics on any input: an
// oversized field is truncated (MaxAuditFieldBytes), never silently
// dropped, and a Write failure is counted (WriteFailures), not
// propagated or retried.
func (a *JSONAuditor) Record(e Event) {
	line := jsonLine{
		Time:   a.clock().UTC().Format(time.RFC3339Nano),
		Step:   truncate(e.Step),
		Detail: truncate(e.Detail),
		Err:    truncate(e.Err),
		Domain: truncate(e.Domain),
		Policy: truncate(e.Policy),
	}
	b, err := json.Marshal(line)
	if err != nil {
		// json.Marshal on a struct of plain strings cannot fail in
		// practice (no cycles, no unsupported types); fail closed with
		// a minimal, static line rather than silently dropping the
		// record if some future Go version's behavior ever surprised
		// this assumption.
		b = []byte(`{"step":"audit_marshal_failed"}`)
	}
	if len(b) > limits.MaxAuditLineBytes {
		b = []byte(`{"step":"audit_line_too_large"}`)
	}
	b = append(b, '\n')

	a.mu.Lock()
	_, werr := a.out.Write(b)
	a.mu.Unlock()
	if werr != nil {
		atomic.AddUint64(&a.writeFailures, 1)
	}
}

// truncate bounds s to limits.MaxAuditFieldBytes, never panicking on
// non-UTF-8 or multi-byte-boundary input (a plain byte-length slice can
// split a multi-byte rune; that is an acceptable, rare cosmetic artifact
// for a size-bounding defensive cap, not a correctness issue --
// encoding/json re-escapes whatever bytes remain, valid UTF-8 or not).
func truncate(s string) string {
	if len(s) <= limits.MaxAuditFieldBytes {
		return s
	}
	return s[:limits.MaxAuditFieldBytes]
}
