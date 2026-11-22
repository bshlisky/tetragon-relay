package verify

import (
	"time"

	"github.com/bshlisky/tetragon-relay/internal/trust"
)

// Input holds every piece of state Verify needs. Nothing is read from any
// global, from the clock, or from the network; the caller is responsible
// for supplying all of it, which is what makes Verify pure and fuzzable.
type Input struct {
	// Envelope is the raw, signed DSSE envelope bytes as received from
	// the controller.
	Envelope []byte

	// Now is the time to check not_before/expires against. Callers must
	// not call time.Now() themselves and should instead thread a single
	// captured time through their call chain.
	Now time.Time

	// HostUUID is this host's own identifier, in canonical UUID form.
	HostUUID string

	// AllowedScopes is the set of scopes this host is configured to
	// accept bundles for (architecture doc section 8.6, host.allowed_scopes).
	AllowedScopes []string

	// TetragonVersion is the running Tetragon daemon's version, compared
	// against a bundle's tetragon_min_version.
	TetragonVersion string

	// Trust is the targets-role Verifier for the host's current trust
	// root, already time-checked by the caller via
	// (*trust.Root).TargetsVerifier(Now). It must not be nil.
	Trust trust.Verifier

	// Epochs supplies the current epoch for a scope.
	Epochs EpochSource

	// PolicyParser turns each policy's YAML into a typed, schema-valid
	// *policydoc.Doc (step 2 prompt Part B) before Guardrails ever sees
	// it. A nil PolicyParser is treated as a configuration failure and
	// causes Verify to reject with CodeRejectedSchema; it is never
	// treated as "schema validation not required."
	PolicyParser PolicyParser

	// Guardrails is called last, only on an otherwise-acceptable bundle.
	// A nil Guardrails is treated as a configuration failure and causes
	// Verify to reject with CodeRejectedGuardrail (step 1 review A2); it
	// is never treated as "no restrictions."
	Guardrails Guardrails
}
