package agent

// Auditor is Startup's structured audit record sink, mirroring
// internal/apply.Auditor's shape (step 3 prompt Part D7) for the
// agent-level events this package can emit before an apply.Engine even
// exists: store tamper, a trust-root rotation decision, and an
// ML-DSA-unavailable role rejection. A fake now; a real implementation
// (later step) also ships it off-host (architecture doc section 10).
type Auditor interface {
	Record(event AuditEvent)
}

// AuditEvent is one structured agent-startup audit record.
type AuditEvent struct {
	// Step identifies what was happening, e.g. "crypto_self_test",
	// "store_open", "trust_root", "mldsa_requirement".
	Step string
	// Detail is a short, human-readable description.
	Detail string
	// Err is the associated error, if any.
	Err error
}

// FakeAuditor records every event in memory for test assertions.
type FakeAuditor struct {
	Events []AuditEvent
}

// Record implements Auditor.
func (f *FakeAuditor) Record(e AuditEvent) {
	f.Events = append(f.Events, e)
}
