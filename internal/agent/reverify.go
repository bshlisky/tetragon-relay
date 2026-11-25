package agent

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/trust"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// reverifyLKG implements ADR 0025 (step-04b-review.md R4B-2): at startup,
// every domain's persisted LKG is re-confirmed against the EXACT trust
// root version that verified it (store.RootAtVersion), independent of
// whatever the current root is. This is deliberately NOT a re-run of
// verify.Verify's full acceptance algorithm: epoch, target and expiry
// checks are excluded (this is re-confirming provenance of an
// ALREADY-accepted artifact, not making a new acceptance decision) —
// only the signature (against the recorded root version) and the cached
// Policies/Mode's consistency with a fresh re-parse of the same raw bytes
// are checked. Any mismatch is reported as (a wrapped) store.ErrTampered,
// matching every other startup tamper path's contract: the caller must
// not retry Startup expecting self-heal, and must not unload or change
// anything Tetragon currently has loaded.
//
// A historical root whose OWN 365-day validity has since elapsed is NOT
// tamper (architecture doc 7.6 already treats an expired root as "stop
// accepting new bundles, keep enforcing LKG" at the ordinary
// verification layer, not evidence of forgery): that domain's
// re-verification is skipped and audited instead.
func reverifyLKG(st *store.Store, now time.Time, auditor Auditor) error {
	domains, err := st.Domains()
	if err != nil {
		return fmt.Errorf("agent: list LKG domains: %w", err)
	}
	for _, domain := range domains {
		if err := reverifyDomainLKG(st, domain, now, auditor); err != nil {
			return err
		}
	}
	return nil
}

func reverifyDomainLKG(st *store.Store, domain string, now time.Time, auditor Auditor) error {
	set, ok := st.Get(domain)
	if !ok {
		// Get itself marks the store tampered on any blob-level failure
		// (internal/store's own contract); a plain ok=false with no
		// Tampered() error means the entry simply raced a concurrent
		// removal, which cannot happen during single-threaded Startup.
		if terr := st.Tampered(); terr != nil {
			return terr
		}
		return nil
	}
	if len(set.RawEnvelope) == 0 {
		// An LKGSet persisted before ADR 0025 (or by a test/fixture that
		// never set RawEnvelope) has nothing to re-verify against.
		// Treated as "nothing to check," not tamper: this package did
		// not create such a record, and refusing to boot because of
		// data this step did not require before would be exactly the
		// kind of silent-widening-into-a-new-requirement this project's
		// working agreement warns against for anything OTHER than a
		// genuine security check. A future, fuller migration step may
		// choose to require it; this step does not.
		auditor.Record(AuditEvent{Step: "lkg_reverify", Detail: fmt.Sprintf("domain %q: no raw envelope recorded (pre-R4B-2 record); skipped", domain)})
		return nil
	}

	rootRaw, ok, err := st.RootAtVersion(set.RootVersion)
	if err != nil {
		return err
	}
	if !ok {
		auditor.Record(AuditEvent{Step: "lkg_reverify", Detail: fmt.Sprintf("domain %q: recorded root version %d is no longer retained", domain, set.RootVersion)})
		return fmt.Errorf("%w: domain %q: no retained root at version %d", store.ErrTampered, domain, set.RootVersion)
	}
	root, err := trust.LoadInitialRoot(rootRaw)
	if err != nil {
		return fmt.Errorf("%w: domain %q: recorded root version %d failed to parse: %w", store.ErrTampered, domain, set.RootVersion, err)
	}

	verifier, err := root.TargetsVerifier(now)
	if err != nil {
		if errors.Is(err, trust.ErrRootMetadataExpired) {
			auditor.Record(AuditEvent{Step: "lkg_reverify", Detail: fmt.Sprintf("domain %q: root version %d has expired; re-verification skipped (LKG keeps enforcing)", domain, set.RootVersion)})
			return nil
		}
		return fmt.Errorf("agent: domain %q: build verifier for root version %d: %w", domain, set.RootVersion, err)
	}

	env, err := dsse.ParseEnvelope(set.RawEnvelope, limits.MaxEnvelopeBytes, limits.MaxJSONDepth)
	if err != nil {
		return fmt.Errorf("%w: domain %q: recorded envelope failed to parse: %w", store.ErrTampered, domain, err)
	}
	if err := verifier.Verify(env); err != nil {
		return fmt.Errorf("%w: domain %q: recorded envelope does not verify under root version %d: %w", store.ErrTampered, domain, set.RootVersion, err)
	}

	bundle, err := verify.ParseBundleUnverified(set.RawEnvelope)
	if err != nil {
		return fmt.Errorf("%w: domain %q: recorded envelope payload failed to re-parse: %w", store.ErrTampered, domain, err)
	}
	resolved, err := apply.ResolveLKGSet(bundle, apply.RealPolicyParser{})
	if err != nil {
		return fmt.Errorf("%w: domain %q: recorded envelope's policies failed to re-resolve: %w", store.ErrTampered, domain, err)
	}
	if !lkgSetsEqual(set, resolved) {
		return fmt.Errorf("%w: domain %q: cached LKG content does not match a fresh re-parse of its own recorded envelope", store.ErrTampered, domain)
	}
	return nil
}

// lkgSetsEqual compares the fields reverifyDomainLKG actually derives
// fresh (Mode, Policies) -- NOT RawEnvelope/RootVersion, which resolved
// (built by apply.ResolveLKGSet) never populates at all.
func lkgSetsEqual(cached, resolved apply.LKGSet) bool {
	if cached.Mode != resolved.Mode {
		return false
	}
	if len(cached.Policies) != len(resolved.Policies) {
		return false
	}
	for i := range cached.Policies {
		a, b := cached.Policies[i], resolved.Policies[i]
		if a.Name != b.Name || a.Version != b.Version || !bytes.Equal(a.CanonicalJSON, b.CanonicalJSON) {
			return false
		}
	}
	return true
}
