package apply

import (
	"context"
	"fmt"
)

// rollback implements step 3 prompt Part D6: re-assert the LKG set for
// this engine's domain, using the same add-before-remove procedure. If no
// LKG has ever been recorded (the very first apply attempt failed its
// health window), the LKG set is treated as empty: rollback means deleting
// everything this Apply attempt just loaded and nothing else, which is
// exactly addBeforeRemove's behavior when the desired set is empty.
//
// If rollback itself fails, the engine stops, leaves whatever is currently
// loaded in place (it never deletes the last enforcing set "to clean
// up"), and returns ErrRollbackFailed for the caller's state machine to
// raise an alert.
func (e *Engine) rollback(ctx context.Context, reason string) (*Result, error) {
	e.audit("rollback_start", reason, nil, "")

	lkgSet, _ := e.lkg.Get(e.cfg.domain()) // ok=false treated as "empty LKG"
	if err := e.lkgTampered(); err != nil {
		e.audit("rollback_failed", err.Error(), err, "")
		return &Result{Status: StatusRollbackFailed, Detail: err.Error()}, ErrRollbackFailed
	}

	resolved := make([]resolvedPolicy, 0, len(lkgSet.Policies))
	for _, p := range lkgSet.Policies {
		loadedName, err := LoadedName(p.Name, p.Version, p.CanonicalJSON)
		if err != nil {
			e.audit("rollback_failed", err.Error(), err, "")
			return &Result{Status: StatusRollbackFailed, Detail: err.Error()}, ErrRollbackFailed
		}
		named, err := setMetadataName(p.CanonicalJSON, loadedName)
		if err != nil {
			e.audit("rollback_failed", err.Error(), err, "")
			return &Result{Status: StatusRollbackFailed, Detail: err.Error()}, ErrRollbackFailed
		}
		resolved = append(resolved, resolvedPolicy{baseName: p.Name, loadedName: loadedName, finalJSON: named})
	}

	existing, err := e.existingManaged(ctx)
	if err != nil {
		e.audit("rollback_failed", err.Error(), err, "")
		return &Result{Status: StatusRollbackFailed, Detail: err.Error()}, ErrRollbackFailed
	}

	var additions []resolvedPolicy
	desired := make(map[string]bool, len(resolved))
	for _, r := range resolved {
		desired[r.loadedName] = true
		if existing[r.baseName] != r.loadedName {
			additions = append(additions, r)
		}
	}
	var removals []string
	for _, loadedName := range existing {
		if !desired[loadedName] {
			removals = append(removals, loadedName)
		}
	}

	added, err := e.addAll(ctx, additions)
	if err != nil {
		// Rollback's own adds failing is ROLLBACK_FAILED: stop, leave
		// whatever is currently loaded (the half-failed rollback
		// attempt's adds, plus whatever survived from before) in place.
		e.audit("rollback_failed", err.Error(), err, "")
		return &Result{Status: StatusRollbackFailed, Detail: err.Error()}, ErrRollbackFailed
	}
	if err := e.confirmLoaded(ctx, added); err != nil {
		e.audit("rollback_failed", err.Error(), err, "")
		return &Result{Status: StatusRollbackFailed, Detail: err.Error()}, ErrRollbackFailed
	}

	e.deleteAll(ctx, removals) // best-effort; a stray loaded policy here is not an enforcement gap

	if err := e.persist(resolved); err != nil {
		e.audit("rollback_persist_failed", err.Error(), err, "")
	}

	digest, _ := e.currentDigest(ctx)
	detail := fmt.Sprintf("rolled back: %s", reason)
	e.audit("rolled_back", detail, nil, "")
	return &Result{Status: StatusRolledBack, ModeMechanism: modeMechanismActionRewrite, Digest: digest, Detail: detail}, ErrRolledBack
}
