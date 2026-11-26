package agent

import (
	"fmt"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/store"
)

// RevocationRecorder persists the REVOKED marker (ADR 0035). Satisfied
// by *store.Store.
type RevocationRecorder interface {
	MarkRevoked(at time.Time, reason string) error
}

// RevocationSource reads the persisted REVOKED marker. Satisfied by
// *store.Store.
type RevocationSource interface {
	Revocation() (store.Revocation, bool, error)
}

// RestoreRevocation implements docs/reviews/step-06a-e3-decisions.md D2
// at startup: if the store holds a REVOKED marker, it moves sm straight
// to REVOKED (valid from any state), so RunSession parks without dialing
// while the startup LKG stays enforced. It reports whether it did. Only
// operator re-enrollment (Reenroller, ADR 0023) clears the marker; this
// function never does. A read error is returned, never treated as "not
// revoked".
func RestoreRevocation(sm *StateMachine, src RevocationSource, auditor Auditor) (bool, error) {
	r, ok, err := src.Revocation()
	if err != nil {
		return false, fmt.Errorf("agent: read persisted revocation: %w", err)
	}
	if !ok {
		return false, nil
	}
	if err := sm.Fire(EventTerminateRevoked); err != nil {
		return false, fmt.Errorf("agent: enter REVOKED from persisted marker: %w", err)
	}
	auditor.Record(AuditEvent{Step: "revocation_restored", Detail: fmt.Sprintf("persisted REVOKED since %s (%s); not connecting", r.At.UTC().Format(time.RFC3339), r.Reason)})
	return true, nil
}
