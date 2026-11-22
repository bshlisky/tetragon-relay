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

	// Guardrails is called last, only on an otherwise-acceptable bundle.
	// It may be nil, in which case the guardrail step is skipped; the
	// real agent must never run with a nil Guardrails (that is enforced
	// by the caller in a later step, not by this package).
	Guardrails Guardrails
}
