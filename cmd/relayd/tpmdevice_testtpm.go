//go:build testtpm

package main

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

// openTPMDevice, under the testtpm build tag only (docs/prompts/
// step-06a.md C3: "the test TPM transport remains available only under
// its build tag, for CI/E3"), additionally accepts "tcp:<host:port>" to
// reach a software TPM (swtpm) over TCP -- the same transport internal/
// controlclient's own integration_test.go (build tag testca) already
// uses to drive a real swtpm for enrollment testing. A bare "/dev/tpmrm0"
// still opens the real device, so this build tag never changes production
// behavior when the path is left at its default.
func openTPMDevice(path string) (transport.TPMCloser, error) {
	if addr, ok := strings.CutPrefix(path, "tcp:"); ok {
		tt, err := tcp.Open(tcp.Config{CommandAddress: addr})
		if err != nil {
			return nil, fmt.Errorf("relayd: open swtpm at %s: %w", addr, err)
		}
		return tt, nil
	}
	return linuxtpm.Open(path)
}
