package store

import (
	"encoding/json"
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/apply"
)

// AppliedCommit is everything a successful (APPLIED) bundle apply
// persists, in ONE index generation (docs/prompts/step-06b.md B1, step
// 4b D1): the domain's new LKG set, the bundle scope's new epoch, and,
// for a monitor-mode bundle only, the policy names guard.PolicyHistory
// must from now on report as seen in monitor mode.
type AppliedCommit struct {
	// Domain is the LKG domain (apply.Config.Domain).
	Domain string
	// Set is the LKG set apply.Engine built for the applied bundle.
	Set apply.LKGSet
	// Scope is the bundle's scope; Epoch its epoch, which must be
	// strictly greater than the scope's persisted epoch.
	Scope string
	Epoch uint64
	// MonitorNames is the bundle's policy names when its mode is
	// "monitor", and must be empty otherwise (guard G5: only a monitor
	// apply may record monitor history).
	MonitorNames []string
}

// CommitApplied persists c atomically: either every part of it is in the
// next generation, or (on any error before the index rename) none is.
// RecordEpoch, Put and RecordMonitorNames each commit their own
// generation, so calling them in sequence would leave a crash window in
// which, for example, the LKG names the new bundle while the epoch still
// admits a replay of it; this method closes that window (step-06b report,
// section 11). The same ErrCommittedCounterLag contract as every other
// write applies.
func (s *Store) CommitApplied(c AppliedCommit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	if c.Domain == "" || c.Scope == "" {
		return fmt.Errorf("store: CommitApplied: domain and scope must be set")
	}
	if c.Set.Mode != "monitor" && len(c.MonitorNames) > 0 {
		return fmt.Errorf("store: CommitApplied: monitor names given for a %q-mode set", c.Set.Mode)
	}
	if cur, ok := s.committed.Epochs[c.Scope]; ok && c.Epoch <= cur {
		return fmt.Errorf("store: epoch %d for scope %q is not greater than persisted %d", c.Epoch, c.Scope, cur)
	}
	raw, err := json.Marshal(toLKGBlob(c.Set))
	if err != nil {
		return fmt.Errorf("store: marshal LKG set: %w", err)
	}
	digest, err := s.writeBlobIfMissing(raw)
	if err != nil {
		return err
	}
	next := s.cloneCommitted()
	next.LKG[c.Domain] = lkgEntry{BlobDigest: digest, Mode: c.Set.Mode, RootVersion: c.Set.RootVersion}
	next.Epochs[c.Scope] = c.Epoch
	seen := make(map[string]struct{}, len(next.History[c.Scope]))
	for _, n := range next.History[c.Scope] {
		seen[n] = struct{}{}
	}
	for _, n := range c.MonitorNames {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		next.History[c.Scope] = append(next.History[c.Scope], n)
	}
	return s.commitLocked(next)
}
