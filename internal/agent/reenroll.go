package agent

import "context"

// Reenroller is the operator re-enrollment action: architecture doc
// section 8.4's REVOKED -> UNENROLLED state transition, and
// step-04b.md Part C6's explicit, never-automatic recovery path out of a
// TAMPERED store. Interface only in this step (out of scope per the
// prompt); see ADR 0023 for the design this interface anticipates and why
// implementation is deferred to the step that has identity and a control
// stream to re-sync from (step 5/6).
type Reenroller interface {
	// Reenroll performs operator-initiated recovery: it is the ONLY
	// path that may discard a TAMPERED store or a revoked identity and
	// re-initialize from scratch (re-attestation, a fresh join token,
	// re-sync from the controller). Startup and every internal/store
	// method never call this themselves; it exists purely so a future
	// operator-facing command (e.g. `relayd reenroll`) has a defined
	// contract to implement against.
	Reenroll(ctx context.Context) error
}
