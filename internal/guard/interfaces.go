// Package guard implements architecture doc section 7.5's agent-side
// guardrails as the step 2 prompt's Part C engine: rules G1-G9 run, in a
// fixed order, against a bundle's already-parsed, already-schema-valid
// policies (internal/policydoc.Doc) and the bundle's GuardContext, and are
// the last check before a policy may be loaded (INV-1).
package guard

// GuardContext carries the verified bundle fields guardrails need:
// internal/verify.Verify populates this from the already-schema-checked
// bundle payload (Scope and Mode are validated there — Mode is exactly
// "monitor" or "enforce" per step 1 review A3 — before guard ever runs).
//
//nolint:revive // GuardContext is the step 2 prompt's literal type name ("Check(ctx GuardContext, ...)"); kept verbatim rather than renamed to avoid diverging from the spec
type GuardContext struct {
	Scope string
	Mode  string
}

// HostCapabilities reports which enforcement-relevant kernel features are
// actually available on this host (architecture doc section 9.3). A real
// implementation (detecting CONFIG_BPF_KPROBE_OVERRIDE/ALLOW_ERROR_INJECTION
// and the active LSM list) is step 3 of this project; this step only
// defines the interface (G8) and tests against fakes.
type HostCapabilities interface {
	// KprobeOverride reports whether Override is usable on kprobes on
	// this host (CONFIG_BPF_KPROBE_OVERRIDE + ALLOW_ERROR_INJECTION on
	// the target function).
	KprobeOverride() bool
	// LSMBPF reports whether CONFIG_BPF_LSM is enabled and "bpf" is in
	// the active LSM list (architecture doc section 9.3).
	LSMBPF() bool
}

// PolicyHistory answers whether a policy name has previously appeared in a
// monitor-mode bundle for a scope (architecture doc section 7.5's
// "monitor-first" rule, G5). Persistence is step 4 of this project; this
// step provides only the interface and an in-memory fake for tests.
type PolicyHistory interface {
	// SeenInMonitor reports whether name was present in some earlier
	// monitor-mode bundle accepted for scope. An error is always treated
	// as "not seen" by G5 (fail closed): see Check's G5 implementation.
	SeenInMonitor(scope, name string) (bool, error)
}

// ProtectedSetSource lets a signed trust-root update extend (never shrink)
// the compiled-in protected binaries/paths (G9): guardrails can only be
// relaxed by signed trust-root metadata, never by a policy bundle. A
// bundle has no path to this interface at all; only the agent's own
// trust-root loading code (a later step) would construct a real
// implementation and pass it to Guardrails. This step provides the
// interface and a fake that returns nothing extra, per the prompt's
// "Define ProtectedSetSource{...} with a fake" instruction. See ADR 0014
// for the proposed root-metadata field placement, submitted for architect
// review as instructed (the prompt forbids changing the root-metadata
// format in this step).
type ProtectedSetSource interface {
	ExtraBinaries() []string
	ExtraPaths() []string
}
