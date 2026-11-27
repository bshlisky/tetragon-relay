// Package apply implements step 3 prompt Part D: loading a verified policy
// bundle (internal/verify.Result ACCEPT) into a real Tetragon v1.8.0
// without ever leaving a gap in enforcement, and reverting automatically
// if the host becomes unhealthy afterward (architecture doc section 7.7).
//
// Every mutating call to Tetragon goes through internal/tetra.Client,
// restricted to its own fixed RPC allowlist (step 3 prompt Part B1); this
// package never talks to Tetragon any other way.
package apply

import "errors"

// Typed errors for every rejection/failure this package can produce,
// matching the sentinel-error convention used throughout this project
// (internal/policydoc, internal/guard, internal/tetra).
var (
	// ErrApplyInProgress means Apply was called while another Apply or
	// Rollback was already running (Part D7's single-flight rule).
	ErrApplyInProgress = errors.New("apply: another apply/rollback is already in progress")

	// ErrNotAccepted means the supplied verify.Result was not
	// verify.CodeAccept; Apply never attempts to load anything else.
	ErrNotAccepted = errors.New("apply: verify.Result is not CodeAccept")

	// ErrApplyFailed is APPLY_FAILED (Part D3): adding the bundle's
	// policies failed partway through; everything this attempt added has
	// already been deleted again, and the previously loaded (LKG) set
	// was never touched.
	ErrApplyFailed = errors.New("apply: APPLY_FAILED")

	// ErrRolledBack is not itself an error from Apply's perspective
	// (Part D5/D6's rollback succeeding is the correct, safe outcome),
	// but is returned to the caller so it can report ROLLED_BACK rather
	// than APPLIED.
	ErrRolledBack = errors.New("apply: ROLLED_BACK (health window failed; LKG re-asserted)")

	// ErrRollbackFailed is ROLLBACK_FAILED (Part D6): the health window
	// failed AND re-asserting the LKG set itself failed. The engine
	// leaves whatever is currently loaded in place (it never deletes the
	// last enforcing set "to clean up") and the caller must raise an
	// alert; this is the one outcome that requires a human.
	ErrRollbackFailed = errors.New("apply: ROLLBACK_FAILED")

	// ErrUnsupportedTetragonVersion means internal/tetra.Client.
	// RequireVersion rejected the connected Tetragon (Part B4); Apply
	// refuses to load anything.
	ErrUnsupportedTetragonVersion = errors.New("apply: unsupported Tetragon version")
	// ErrLKGTampered is returned by Reconcile (and reported by rollback
	// as ROLLBACK_FAILED) when the LKG store reports tampering: an
	// unreadable LKG would otherwise read as "empty", and re-asserting an
	// empty set would unload every relay-managed policy (step 4b C6:
	// never unload or change what Tetragon has loaded).
	ErrLKGTampered = errors.New("apply: LKG store is TAMPERED; not re-asserting")
)
