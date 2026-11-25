package agent

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

// Config is Startup's input. No field reads time.Now or the environment
// itself (ADR 0008's clock-injection convention, extended to this
// package): Startup takes "now" as an explicit parameter.
type Config struct {
	// StoreDir is internal/store's directory (architecture doc section
	// 8.5: /var/lib/tetragon-relay/).
	StoreDir string
	// Sealer provides the store's HMAC key (a TPM-sealed key in step 5;
	// store.FakeKeySealer today).
	Sealer store.KeySealer
	// Counter mirrors the store's generation (a TPM NV counter in step
	// 5; store.FakeMonotonicCounter today).
	Counter store.MonotonicCounter
	// InitialRootBytes is the RPM-shipped trust root's raw signed bytes
	// (/etc/tetragon-relay/trust/root.json), read by the caller (not
	// this package: internal/agent has no filesystem access of its own
	// for config paths, matching the no-os.Getenv/no-hidden-I/O rule).
	// Required at first boot. At every later boot it is also considered
	// as one possible forward-chain candidate (folded into
	// AvailableRPMRoots by its own declared version), since
	// docs/decisions/0024-forward-root-chaining.md keeps root.json as
	// the lowest version an RPM ships.
	InitialRootBytes []byte
	// AvailableRPMRoots is every OTHER RPM-shipped root metadata
	// version's raw signed bytes the caller found under
	// /etc/tetragon-relay/trust/roots/ (step-04b-review.md R4B-1),
	// keyed by the version parsed from that file's OWN NAME
	// ("<version>.root.json") — not yet cross-checked against the
	// metadata's own declared version inside; establishTrustRoot does
	// that (a mismatch means the file is ignored and audited, never
	// trusted by file name alone). The caller does no interpretation
	// beyond listing the directory and reading each file's bytes: it is
	// this package's job to decide which are usable and in what order.
	// Optional; nil or empty means "chain by at most the single step
	// InitialRootBytes may offer," matching this package's behavior
	// before R4B-1. Bounded to limits.MaxRootChainFiles entries;
	// Startup returns a config error if there are more (see
	// docs/decisions/0024-forward-root-chaining.md: the caller, not
	// this package, is responsible for bounding how many files it ever
	// reads from disk in the first place — this is defense in depth).
	AvailableRPMRoots map[uint64][]byte
	// Auditor records startup-time security events. Required: a nil
	// Auditor is a configuration error (the same fail-closed convention
	// internal/verify and internal/guard already use for their required
	// collaborators), never silently skipped.
	Auditor Auditor
}

// StartupResult is Startup's successful outcome.
type StartupResult struct {
	// Store is the opened, validated persistent state store, handed to
	// the apply engine (verify.EpochSource, guard.PolicyHistory,
	// apply.LKGStore are all satisfied by *store.Store directly).
	Store *store.Store
	// Capabilities records what RunCryptoSelfTest found.
	Capabilities Capabilities
	// TrustRoot is the current trust root as of startup: either the
	// freshly-adopted initial root (first boot), the persisted root
	// (no forward move available or none configured), or the result of
	// chaining the persisted root forward by exactly one version via
	// the RPM-shipped root (Part C7).
	TrustRoot *trust.Root
	// FirstBoot mirrors (*store.Store).FirstBoot().
	FirstBoot bool
	// Degraded is true when Startup succeeded but found a condition
	// that should be surfaced to an operator immediately rather than
	// waiting for it to manifest as a bundle-verification failure
	// later (step-04b-review.md R4B-6): today, the only such condition
	// is the active trust root requiring mldsa-87 on a build where
	// ML-DSA is unavailable. A caller (step 6's relayd main) is
	// expected to enter the architecture doc 8.4 DEGRADED state when
	// this is true.
	Degraded bool
	// DegradedReason is a short, fixed, non-attacker-controlled string
	// explaining Degraded, e.g. "trust root requires ML-DSA,
	// unavailable in this build". Empty when Degraded is false.
	DegradedReason string
}

// Startup runs step-04b.md Part D2's sequence: crypto self-test, open the
// store, establish the trust root, and the resulting
// TAMPERED/first-boot decision. It does not touch Tetragon, the control
// stream or telemetry (step 6 scope) and does not start any background
// work; it only returns the validated state a later step's main() would
// hand to the apply engine.
//
// A returned error wrapping store.ErrTampered means the store itself
// detected tampering (internal/store.Open's own contract): callers must
// not retry Startup expecting it to self-heal (Part C6), and must not
// unload or change anything Tetragon currently has loaded. A returned
// error wrapping ErrECDSASelfTestFailed means this build must refuse to
// start outright. Every other error is an ordinary startup failure
// (unavailable sealer/counter, no trust root available) that a caller may
// retry.
func Startup(cfg Config, now time.Time) (*StartupResult, error) {
	if cfg.Auditor == nil {
		return nil, fmt.Errorf("agent: Config.Auditor must not be nil")
	}

	caps, err := RunCryptoSelfTest()
	if err != nil {
		cfg.Auditor.Record(AuditEvent{Step: "crypto_self_test", Detail: "ECDSA P-384 self-test failed; refusing to start", Err: err})
		return nil, err
	}
	if !caps.MLDSAAvailable {
		cfg.Auditor.Record(AuditEvent{Step: "crypto_self_test", Detail: "ML-DSA-87 unavailable in this build", Err: caps.MLDSAErr})
	}

	st, err := store.Open(cfg.StoreDir, cfg.Sealer, cfg.Counter)
	if err != nil {
		if errors.Is(err, store.ErrTampered) {
			cfg.Auditor.Record(AuditEvent{Step: "store_open", Detail: "store is TAMPERED", Err: err})
			return nil, err
		}
		cfg.Auditor.Record(AuditEvent{Step: "store_open", Detail: "failed to open the store", Err: err})
		return nil, fmt.Errorf("%w: %w", ErrStoreOpenFailed, err)
	}

	if len(cfg.AvailableRPMRoots) > limits.MaxRootChainFiles {
		_ = st.Close()
		return nil, fmt.Errorf("%w: %d RPM root files configured, max %d", ErrTooManyRootFiles, len(cfg.AvailableRPMRoots), limits.MaxRootChainFiles)
	}

	root, err := establishTrustRoot(st, cfg, caps, now, cfg.Auditor)
	if err != nil {
		_ = st.Close()
		return nil, err
	}

	// ADR 0025 (step-04b-review.md R4B-2): re-confirm every persisted
	// domain's LKG against the exact trust-root version that verified
	// it, independent of whichever root establishTrustRoot just
	// settled on. A failure here is exactly like store.Open's own
	// ErrTampered contract: the caller must not retry expecting
	// self-heal, and must not unload or change anything Tetragon
	// currently has loaded.
	if err := reverifyLKG(st, now, cfg.Auditor); err != nil {
		_ = st.Close()
		return nil, err
	}

	degraded, degradedReason := startupDegradedCondition(root, caps, cfg.Auditor)

	return &StartupResult{
		Store:          st,
		Capabilities:   caps,
		TrustRoot:      root,
		FirstBoot:      st.FirstBoot(),
		Degraded:       degraded,
		DegradedReason: degradedReason,
	}, nil
}

// establishTrustRoot implements Part C7, extended by step-04b-review.md
// R4B-1: at first boot, the RPM-shipped initial root is adopted
// unconditionally. At every later boot, the persisted root is
// authoritative; every other RPM-shipped root version (cfg.InitialRootBytes
// folded in by its own declared version, plus cfg.AvailableRPMRoots) is
// considered only as a possible forward move, walked one version at a time
// via (*trust.Root).Update starting from persisted+1 — never a downgrade,
// and the walk stops (keeping the last version it successfully reached)
// at the first missing version (a gap) or the first chain-verification
// failure, logging either via auditor. The persisted root is never left
// unset by a failed or partial walk.
func establishTrustRoot(st *store.Store, cfg Config, caps Capabilities, now time.Time, auditor Auditor) (*trust.Root, error) {
	if st.FirstBoot() {
		if len(cfg.InitialRootBytes) == 0 {
			return nil, fmt.Errorf("%w: first boot with no RPM-shipped initial root configured", ErrNoTrustRoot)
		}
		root, err := trust.LoadInitialRoot(cfg.InitialRootBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInitialRootInvalid, err)
		}
		if err := st.PersistTrustRoot(cfg.InitialRootBytes, root.Version); err != nil {
			return nil, fmt.Errorf("agent: persist initial trust root: %w", err)
		}
		auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("first boot: adopted initial root version %d", root.Version)})
		return root, nil
	}

	persistedRaw, _, ok, err := st.TrustRoot()
	if err != nil {
		return nil, fmt.Errorf("agent: load persisted trust root: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: store has no persisted trust root and this is not first boot", ErrNoTrustRoot)
	}
	persistedRoot, err := trust.LoadInitialRoot(persistedRaw)
	if err != nil {
		// The persisted root was accepted (HMAC-verified, blob-hash
		// verified) by internal/store but does not parse as valid
		// trust-root metadata: that should be impossible for a root
		// this package itself ever persisted, and is treated as
		// tampered evidence at the trust layer rather than silently
		// falling back to anything.
		auditor.Record(AuditEvent{Step: "trust_root", Detail: "persisted trust root failed to parse", Err: err})
		return nil, fmt.Errorf("%w: persisted root: %w", store.ErrTampered, err)
	}

	candidates := collectRootChainCandidates(cfg, auditor)

	current := persistedRoot
	currentRaw := persistedRaw
	steps := 0
	for {
		next, ok := candidates[current.Version+1]
		if !ok {
			break // no (usable) file at the next version: a gap, or simply nothing further to adopt.
		}
		if steps >= limits.MaxRootChainFiles {
			auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("forward root chain stopped at version %d: reached the %d-step bound", current.Version, limits.MaxRootChainFiles)})
			break
		}
		updated, uerr := current.Update(next, now)
		if uerr != nil {
			// Never accept, keep the last good version, log it. This
			// covers both an outright malicious/unchainable candidate
			// at the right version and name, and (defense in depth)
			// any other Update failure.
			auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("RPM-shipped root version %d did not chain from version %d; stopping, keeping version %d", current.Version+1, current.Version, current.Version), Err: uerr})
			break
		}
		if !caps.MLDSAAvailable && rootRequiresMLDSA(updated) {
			// step-04b-review.md R4B-6: adopting a root that requires
			// mldsa-87 on a build where ML-DSA is unavailable would
			// make every future bundle unverifiable on this host (no
			// signature could ever satisfy that role's
			// require_keytypes again). Refuse this step specifically,
			// keep the last good version, and stop the walk here —
			// never silently skip past it to a later candidate, which
			// could reintroduce the same unsatisfiable requirement or
			// worse.
			auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("refusing to adopt root version %d: requires mldsa-87 but ML-DSA is unavailable in this build; keeping version %d", updated.Version, current.Version)})
			break
		}
		current, currentRaw = updated, next
		steps++
	}

	if steps == 0 {
		return persistedRoot, nil
	}
	if err := st.PersistTrustRoot(currentRaw, current.Version); err != nil {
		return nil, fmt.Errorf("agent: persist updated trust root: %w", err)
	}
	auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("adopted RPM-shipped root: version %d -> %d (%d step(s))", persistedRoot.Version, current.Version, steps)})
	return current, nil
}

// collectRootChainCandidates builds the set of usable forward-chain
// candidates from cfg: cfg.InitialRootBytes (keyed by its own declared
// version) plus every entry in cfg.AvailableRPMRoots, EXCEPT any whose
// file-name version does not match the version its own metadata declares
// (step-04b-review.md R4B-1: "File-name versions must match the metadata
// version inside, else ignore that file and audit") or that fails to
// parse/self-verify at all. The persisted root's own forward-chain
// verification (old-threshold AND new-threshold, (*trust.Root).Update) is
// NOT done here — this only establishes which (version -> bytes) pairs
// are even worth attempting, so a candidate accepted here can still stop
// the walk later if it fails to chain from whatever the walk's current
// root turns out to be.
func collectRootChainCandidates(cfg Config, auditor Auditor) map[uint64][]byte {
	type namedFile struct {
		fileVersion uint64
		raw         []byte
		source      string
	}
	files := make([]namedFile, 0, len(cfg.AvailableRPMRoots)+1)
	if len(cfg.InitialRootBytes) > 0 {
		if parsed, err := trust.LoadInitialRoot(cfg.InitialRootBytes); err == nil {
			files = append(files, namedFile{fileVersion: parsed.Version, raw: cfg.InitialRootBytes, source: "root.json"})
		} else {
			auditor.Record(AuditEvent{Step: "trust_root_candidate", Detail: "root.json failed to parse/self-verify, ignored", Err: err})
		}
	}
	// Deterministic order (ascending file-name version) so audit
	// records for a fixed input are reproducible across runs, even
	// though map iteration order is not.
	versions := make([]uint64, 0, len(cfg.AvailableRPMRoots))
	for v := range cfg.AvailableRPMRoots {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, v := range versions {
		files = append(files, namedFile{fileVersion: v, raw: cfg.AvailableRPMRoots[v], source: fmt.Sprintf("roots/%d.root.json", v)})
	}

	out := make(map[uint64][]byte, len(files))
	for _, f := range files {
		parsed, err := trust.LoadInitialRoot(f.raw)
		if err != nil {
			auditor.Record(AuditEvent{Step: "trust_root_candidate", Detail: fmt.Sprintf("%s failed to parse/self-verify, ignored", f.source), Err: err})
			continue
		}
		if parsed.Version != f.fileVersion {
			auditor.Record(AuditEvent{Step: "trust_root_candidate", Detail: fmt.Sprintf("%s: file name declares version %d but metadata declares version %d; ignored", f.source, f.fileVersion, parsed.Version)})
			continue
		}
		if existing, dup := out[f.fileVersion]; dup && string(existing) != string(f.raw) {
			auditor.Record(AuditEvent{Step: "trust_root_candidate", Detail: fmt.Sprintf("%s: version %d already claimed by a different file's content; ignored", f.source, f.fileVersion)})
			continue
		}
		out[f.fileVersion] = f.raw
	}
	return out
}

// degradedReasonMLDSAUnavailable is StartupResult.DegradedReason's exact
// value for step-04b-review.md R4B-6's condition, so a caller can match on
// it (rather than parsing an arbitrary free-text string) if it ever needs
// to distinguish this reason from other future DEGRADED causes.
const degradedReasonMLDSAUnavailable = "trust root requires ML-DSA, unavailable in this build"

// rootRequiresMLDSA reports whether any of root's three roles
// (require_keytypes is mandatory on every role, R4A-1) lists mldsa-87,
// regardless of this build's own ML-DSA availability. Used both by
// establishTrustRoot's chain-walk (to refuse adopting such a root when
// unavailable, R4B-6) and by checkMLDSARequirement (to decide whether the
// ALREADY-established root needs a DEGRADED report).
func rootRequiresMLDSA(root *trust.Root) bool {
	if root == nil {
		return false
	}
	for _, role := range []trust.Role{root.RootRole(), root.TargetsRole(), root.LogRole()} {
		for _, kt := range role.RequireKeyTypes {
			if kt == trust.KeyTypeMLDSA87 {
				return true
			}
		}
	}
	return false
}

// startupDegradedCondition implements step-04b-review.md R4B-6's second
// bullet: if root (whatever Startup ultimately established -- first
// boot, an unchanged persisted root, or the end of a forward chain) still
// requires mldsa-87 on a build where ML-DSA is unavailable, Startup must
// still succeed (the persisted/established root keeps enforcing), but
// report a DEGRADED condition immediately rather than waiting for it to
// surface as a verification failure at the first bundle. This is
// deliberately a SEPARATE check from establishTrustRoot's own
// chain-walk refusal (which only prevents NEWLY adopting such a root);
// a root that already required it before this build ever ran reaches
// Startup having been established by some earlier boot (or by this
// build's own first-boot path, if the RPM-shipped initial root itself
// requires it) and still needs to be reported.
func startupDegradedCondition(root *trust.Root, caps Capabilities, auditor Auditor) (degraded bool, reason string) {
	if err := checkMLDSARequirement(root, caps, auditor); err != nil {
		return true, degradedReasonMLDSAUnavailable
	}
	return false, ""
}

// checkMLDSARequirement implements step-04a-review.md R4A-3's audit
// requirement: if the loaded root's targets role requires mldsa-87
// (trust.Role.RequireKeyTypes) and this build's crypto self-test found
// ML-DSA-87 unavailable, record a typed, named audit event. The root
// role and log role are also checked for the same reason, since
// require_keytypes is mandatory on every role (R4A-1) and any of them
// could in principle require mldsa-87. step-04b-review.md R4B-6: this is
// also what Startup uses to decide StartupResult.Degraded for an
// ALREADY-persisted root that requires mldsa-87 on an ML-DSA-unavailable
// build (the chain-walk's own refusal only prevents NEWLY adopting one;
// a root that already required it before this build ever ran still needs
// to surface immediately, not wait for the first bundle).
func checkMLDSARequirement(root *trust.Root, caps Capabilities, auditor Auditor) error {
	if caps.MLDSAAvailable || root == nil {
		return nil
	}
	roles := map[string]trust.Role{
		"root":    root.RootRole(),
		"targets": root.TargetsRole(),
		"log":     root.LogRole(),
	}
	var firstErr error
	for name, role := range roles {
		for _, kt := range role.RequireKeyTypes {
			if kt == trust.KeyTypeMLDSA87 {
				err := fmt.Errorf("%w: role %q requires mldsa-87", ErrMLDSAUnavailable, name)
				auditor.Record(AuditEvent{Step: "mldsa_requirement", Detail: fmt.Sprintf("role %q requires mldsa-87 but ML-DSA is unavailable in this build", name), Err: err})
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}
