package agent

import (
	"errors"
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/tpm"
	"github.com/google/go-tpm/tpm2/transport"
)

// ErrTPMRequired is returned by BuildTPMComponents when the components
// cannot be built from an already-open TPM connection (e.g. the counter
// index was never provisioned). This project never falls back to an
// in-memory KeySealer/MonotonicCounter in production (docs/prompts/
// step-05a.md C5): a host without a working, provisioned TPM must refuse
// to start, not silently run with fakes.
var ErrTPMRequired = errors.New("agent: a working, provisioned TPM is required in production")

// TPMComponents bundles the real, TPM-backed store.KeySealer and
// store.MonotonicCounter BuildTPMComponents constructs.
type TPMComponents struct {
	Sealer  store.KeySealer
	Counter store.MonotonicCounter
}

// BuildTPMComponents constructs the real KeySealer and MonotonicCounter
// internal/store needs from an already-open TPM connection t (production:
// tpm.OpenDevice("/dev/tpmrm0"), architecture doc section 8.6 -- never
// "/dev/tpm0"; this package takes the connection as a parameter rather
// than opening the device itself so the device-open step, platform- and
// hardware-dependent, stays entirely in the caller, which this step's
// relayd main -- step 6 -- is responsible for refusing to start without,
// same pattern as ADR 0023's Reenroller interface being built ahead of
// its first real caller): a sealed-HMAC-key blob at sealedKeyBlobPath
// (inside the store directory, architecture doc 8.5) and the rollback-
// protection NV counter at tpm.DefaultCounterHandle (already provisioned
// by the root-run relay-probe --provision-tpm, packaging/systemd/
// tetragon-relay.service's ExecStartPre=+; relayd itself never
// provisions it, only reads and increments).
//
// This is the ONLY place internal/agent's non-test code constructs a
// store.KeySealer or store.MonotonicCounter: there is no runtime flag to
// select store.FakeKeySealer/FakeMonotonicCounter instead (those remain
// reachable only from this package's own tests, which construct
// agent.Config{Sealer: ..., Counter: ...} directly). If the sealer cannot
// be built or the counter index was never provisioned, this returns a
// wrapped ErrTPMRequired; the caller must refuse to start rather than
// proceed with cfg.Sealer/cfg.Counter left nil.
func BuildTPMComponents(t transport.TPM, sealedKeyBlobPath string) (*TPMComponents, error) {
	sealer, err := tpm.NewKeySealer(t, sealedKeyBlobPath)
	if err != nil {
		return nil, fmt.Errorf("%w: key sealer: %w", ErrTPMRequired, err)
	}
	counter, err := tpm.OpenCounter(t, tpm.DefaultCounterHandle)
	if err != nil {
		return nil, fmt.Errorf("%w: monotonic counter: %w", ErrTPMRequired, err)
	}
	return &TPMComponents{Sealer: sealer, Counter: counter}, nil
}
