package agent

import (
	"bytes"
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
// A historical root whose OWN 365-day validity has since elapsed does NOT
// skip the signature check (docs/reviews/step-04c-review.md R4C-2): expiry
// is a rule about accepting NEW bundles, and a signature's validity does
// not change with time, so reverifyDomainLKG uses (*trust.Root)'s
// ProvenanceVerifier, not TargetsVerifier, and only AUDITS the expiry as
// operational staleness rather than letting it change the outcome.
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
	if len(set.RawEnvelope) == 0 || set.RootVersion == 0 {
		// docs/reviews/step-04c-review.md R4C-1: there are no genuine
		// pre-R4B-2 records anywhere (internal/store's LKG schema was
		// introduced in step 4b and has never been deployed without
		// this re-verification step), and a missing raw envelope or
		// root version is exactly the attack ADR 0025 defends against
		// -- an attacker who can forge a valid store index HMAC
		// rewrites the LKG blob with altered policies and simply omits
		// raw_envelope/root_version, which would otherwise skip
		// re-verification entirely and trust the altered set. Fail
		// closed instead.
		auditor.Record(AuditEvent{Step: "lkg_reverify", Detail: fmt.Sprintf("domain %q: LKG has no raw envelope or root version recorded", domain)})
		return fmt.Errorf("%w: domain %q: LKG has no raw envelope or root version recorded", store.ErrTampered, domain)
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

	// R4C-2: expiry of the historical root's OWN metadata validity must
	// not skip the signature check -- it is audited as operational
	// staleness only, never as a reason to trust an unverified envelope.
	if !now.Before(root.Expires) {
		auditor.Record(AuditEvent{Step: "lkg_reverify", Detail: fmt.Sprintf("domain %q: root version %d has expired; re-verification continues anyway (LKG keeps enforcing)", domain, set.RootVersion)})
	}
	verifier := root.ProvenanceVerifier()

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
