package tpm

import (
	"encoding/binary"
	"errors"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// faultTPM wraps a real transport.TPM (a live swtpm connection) and lets
// tests force a specific TPM 2.0 command to fail on a chosen occurrence,
// without needing to hand-construct well-formed TPM response bytes for
// every other command: everything not targeted passes straight through to
// the real TPM. This is Part C1's "unit tests use an interface" half of
// the testing strategy, layered on top of a genuine TPM connection rather
// than a fully synthetic mock, so the command bytes actually sent for the
// non-faulted path are still the real ones this package builds.
type faultTPM struct {
	inner transport.TPM
	// failCommand, if nonzero, is the TPM_CC this fake intercepts.
	failCommand uint32
	// failOnCall is which 1-indexed occurrence of failCommand to fail
	// (1 = the first time it is sent).
	failOnCall int
	// err is returned instead of actually sending the command, once
	// failOnCall is reached.
	err error

	seen int
}

var errFaultInjected = errors.New("tpm: fault injected by test")

func (f *faultTPM) Send(cmd []byte) ([]byte, error) {
	if len(cmd) >= 10 {
		cc := binary.BigEndian.Uint32(cmd[6:10])
		if cc == f.failCommand {
			f.seen++
			if f.seen == f.failOnCall {
				if f.err != nil {
					return nil, f.err
				}
				return nil, errFaultInjected
			}
		}
	}
	return f.inner.Send(cmd)
}

func cc(c tpm2.TPMCC) uint32 { return uint32(c) }
