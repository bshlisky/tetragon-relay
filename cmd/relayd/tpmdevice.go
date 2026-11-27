package main

import (
	"github.com/bshlisky/tetragon-relay/internal/tpm"
	"github.com/google/go-tpm/tpm2/transport"
)

// productionTPMDevice is the only TPM path relayd ever opens, in every
// build (docs/prompts/step-06a.md C3: "production builds accept only
// /dev/tpmrm0"). relayd defines no --tpm-device flag at all (R6A-3), so
// the standard flag package itself rejects one. R6A-5
// (docs/reviews/step-06a-final-review.md) removed the testtpm build's
// TCP swtpm transport: E3 uses a vtpm-proxy-backed swtpm at this same
// path in every scenario.
const productionTPMDevice = "/dev/tpmrm0"

// openTPMDevice opens productionTPMDevice through tpm.OpenDevice, the
// same opener relay-probe and cmd/testenroll use.
func openTPMDevice() (transport.TPMCloser, error) {
	return tpm.OpenDevice(productionTPMDevice)
}
