package agent

import (
	"errors"
	"fmt"
	"time"

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
	// Required at first boot; optional at every later boot, where it is
	// only ever considered as a possible forward move (Part C7).
	InitialRootBytes []byte
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

	root, err := establishTrustRoot(st, cfg.InitialRootBytes, now, cfg.Auditor)
	if err != nil {
		_ = st.Close()
		return nil, err
	}

	if err := checkMLDSARequirement(root, caps, cfg.Auditor); err != nil {
		// Not fatal to Startup: a role requiring mldsa-87 that this
		// build cannot evaluate simply cannot be satisfied (fail
		// closed at verify time, same as trust.ErrMLDSAUnavailable's
		// own contract); the audit record above is the actionable
		// signal for an operator. No production role requires
		// mldsa-87 today (ADR 0022 Part B5), so this is not expected
		// to fire outside a future hybrid rotation.
		_ = err
	}

	return &StartupResult{
		Store:        st,
		Capabilities: caps,
		TrustRoot:    root,
		FirstBoot:    st.FirstBoot(),
	}, nil
}

// establishTrustRoot implements Part C7: at first boot, the RPM-shipped
// initial root is adopted unconditionally. At every later boot, the
// persisted root is authoritative; the RPM-shipped root is considered
// only as a possible forward move, exactly one version via
// (*trust.Root).Update — never a downgrade, never accepted silently on
// any chaining failure (logged via auditor and the persisted root is kept
// instead).
func establishTrustRoot(st *store.Store, initialRootBytes []byte, now time.Time, auditor Auditor) (*trust.Root, error) {
	if st.FirstBoot() {
		if len(initialRootBytes) == 0 {
			return nil, fmt.Errorf("%w: first boot with no RPM-shipped initial root configured", ErrNoTrustRoot)
		}
		root, err := trust.LoadInitialRoot(initialRootBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInitialRootInvalid, err)
		}
		if err := st.PersistTrustRoot(initialRootBytes, root.Version); err != nil {
			return nil, fmt.Errorf("agent: persist initial trust root: %w", err)
		}
		auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("first boot: adopted initial root version %d", root.Version)})
		return root, nil
	}

	persistedRaw, persistedVersion, ok, err := st.TrustRoot()
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
	_ = persistedVersion

	if len(initialRootBytes) == 0 {
		return persistedRoot, nil
	}

	candidate, err := trust.LoadInitialRoot(initialRootBytes)
	if err != nil {
		auditor.Record(AuditEvent{Step: "trust_root", Detail: "RPM-shipped root failed to parse; keeping persisted root", Err: err})
		return persistedRoot, nil
	}
	switch {
	case candidate.Version <= persistedRoot.Version:
		auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("RPM-shipped root version %d is not newer than persisted version %d; ignored", candidate.Version, persistedRoot.Version)})
		return persistedRoot, nil
	default:
		updated, err := persistedRoot.Update(initialRootBytes, now)
		if err != nil {
			// Covers both ErrVersionSkip (the RPM root is more than
			// one version ahead; an intermediate version is needed
			// first, architecture doc 7.6 — not available to this
			// package, which has no control-stream client) and any
			// chain-verification failure. Either way: never accept,
			// keep the persisted root, log it.
			auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("RPM-shipped root version %d did not chain from persisted version %d; keeping persisted root", candidate.Version, persistedRoot.Version), Err: err})
			return persistedRoot, nil
		}
		if err := st.PersistTrustRoot(initialRootBytes, updated.Version); err != nil {
			return nil, fmt.Errorf("agent: persist updated trust root: %w", err)
		}
		auditor.Record(AuditEvent{Step: "trust_root", Detail: fmt.Sprintf("adopted RPM-shipped root: version %d -> %d", persistedRoot.Version, updated.Version)})
		return updated, nil
	}
}

// checkMLDSARequirement implements step-04a-review.md R4A-3's audit
// requirement: if the loaded root's targets role requires mldsa-87
// (trust.Role.RequireKeyTypes) and this build's crypto self-test found
// ML-DSA-87 unavailable, record a typed, named audit event. The root
// role and log role are also checked for the same reason, since
// require_keytypes is mandatory on every role (R4A-1) and any of them
// could in principle require mldsa-87.
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
