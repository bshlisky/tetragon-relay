package apply

import "context"

// DriftReport is Reconcile's typed result (step 3 prompt Part D9).
type DriftReport struct {
	// InSync is true if Tetragon's relay-managed policies exactly match
	// the LKG set (same loaded names, nothing extra, nothing missing).
	InSync bool
	// Missing is every LKG policy's loaded name that is not currently
	// loaded.
	Missing []string
	// Unexpected is every currently-loaded relay-managed policy whose
	// loaded name is not in the LKG set.
	Unexpected []string
	// Reasserted is true if Reconcile found drift and successfully
	// re-applied the LKG set (ReassertOnDrift was true and the
	// re-assert succeeded).
	Reasserted bool
	// ReassertError is set if ReassertOnDrift was true but the
	// re-assert itself failed (ROLLBACK_FAILED-shaped outcome; the
	// caller's state machine should alert the same way).
	ReassertError error
}

// Reconcile implements step 3 prompt Part D9: compares Tetragon's current
// relay-managed policy set against LKG for this engine's domain and
// returns a typed drift report. If reassertOnDrift is true and drift is
// found, Reconcile re-asserts the LKG set once (the same add-before-remove
// procedure rollback uses) and records the outcome in the report; it never
// retries more than once and never runs on a timer itself (the caller
// schedules calls to Reconcile, architecture doc section 7.7/step 3 Part
// D9).
//
// Single-flight: Reconcile takes the same lock Apply does, so a Reconcile
// call never races a concurrent Apply.
func (e *Engine) Reconcile(ctx context.Context, reassertOnDrift bool) (*DriftReport, error) {
	if !e.mu.TryLock() {
		return nil, ErrApplyInProgress
	}
	defer e.mu.Unlock()

	lkgSet, _ := e.lkg.Get(e.cfg.domain())
	desired := make(map[string]bool, len(lkgSet.Policies))
	for _, p := range lkgSet.Policies {
		loadedName, err := LoadedName(p.Name, p.Version, p.CanonicalJSON)
		if err != nil {
			return nil, err
		}
		desired[loadedName] = true
	}

	existing, err := e.existingManaged(ctx)
	if err != nil {
		return nil, err
	}
	existingLoadedNames := make(map[string]bool, len(existing))
	for _, loadedName := range existing {
		existingLoadedNames[loadedName] = true
	}

	report := &DriftReport{}
	for loadedName := range desired {
		if !existingLoadedNames[loadedName] {
			report.Missing = append(report.Missing, loadedName)
		}
	}
	for loadedName := range existingLoadedNames {
		if !desired[loadedName] {
			report.Unexpected = append(report.Unexpected, loadedName)
		}
	}
	report.InSync = len(report.Missing) == 0 && len(report.Unexpected) == 0

	if report.InSync || !reassertOnDrift {
		return report, nil
	}

	e.audit("reconcile_drift", "re-asserting LKG once", nil, "")
	// rollback() re-asserts the current LKG via the same add-before-
	// remove procedure regardless of *why* it is being called; reused
	// here verbatim rather than duplicated. Its own single-flight lock
	// is already held by this call (sync.Mutex is not reentrant, so
	// rollback must not itself try to re-lock); it does not, since
	// rollback is a plain method with no locking of its own.
	result, applyErr := e.rollback(ctx, "reconcile drift")
	if result != nil && result.Status == StatusRolledBack {
		report.Reasserted = true
		return report, nil
	}
	report.ReassertError = applyErr
	return report, nil
}
