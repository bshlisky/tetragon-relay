package verify

import (
	"github.com/bshlisky/tetragon-relay/internal/guard"
	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

// EpochSource provides the current epoch for a scope, as tracked by the
// agent's persistent state (internal/store, a later step). An error from
// Current must always result in rejection; it must never be treated as "no
// prior epoch, so accept."
type EpochSource interface {
	Current(scope string) (uint64, error)
}

// PolicyParser turns one policy's YAML text (whose sha256 Verify has
// already matched against the signed bundle's declared digest) into a
// typed, immutable *policydoc.Doc: step 2 prompt Part B (YAML hardening,
// CRD schema validation, a policy-level allowlist, canonical form, a typed
// model, an action-completeness cross-check, and bundle-name binding).
//
// Input.PolicyParser must never be nil in a real caller: Verify treats a
// nil PolicyParser as a configuration failure and rejects with
// CodeRejectedSchema (fail closed, the same policy step 1 review A2
// established for a nil Guardrails) rather than silently accepting a
// bundle whose policies were never schema-validated. Tests that want "any
// well-formed TracingPolicy is fine" must supply an explicit fake,
// declared only in _test.go files, never a nil value.
//
// The real implementation is internal/policydoc.Parse.
type PolicyParser interface {
	Parse(name, yamlDoc string) (*policydoc.Doc, error)
}

// Guardrails checks a parsed, otherwise-valid bundle's policies against
// the agent-compiled safety rules of architecture doc section 7.5 (e.g. no
// Sigkill/Override on sshd, systemd, Tetragon itself, etc.), via
// internal/guard's G1-G9 rules. It is called last, only after every other
// check has passed, and only with policies that have already been
// hash-, schema- and allowlist-validated by PolicyParser.
//
// Input.Guardrails must never be nil in a real caller: Verify treats a nil
// Guardrails as a configuration failure and rejects with
// CodeRejectedGuardrail (step 1 review A2) rather than silently accepting a
// bundle no guardrail ever evaluated. Tests that want "no guardrail
// restrictions" must supply an explicit allow-all fake, declared only in
// _test.go files, never a nil value.
//
// The real implementation is internal/guard.Guardrails (step 2 of this
// project).
type Guardrails interface {
	Check(ctx guard.GuardContext, docs []*policydoc.Doc) error
}
