//go:build !testtpm

package main

import (
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/tpm"
	"github.com/google/go-tpm/tpm2/transport"
)

// openTPMDevice implements C3: path must be exactly productionTPMDevice
// in a production build; any other value (e.g. an operator passing
// --tpm-device for a software TPM) is refused outright, never silently
// honored.
func openTPMDevice(path string) (transport.TPMCloser, error) {
	if path != productionTPMDevice {
		return nil, fmt.Errorf("relayd: --tpm-device must be %q in a production build, got %q", productionTPMDevice, path)
	}
	return tpm.OpenDevice(path)
}

// tpmDeviceFlag implements R6A-3: a production build (no test build
// tags) never even defines a --tpm-device flag, so passing one is
// rejected by the standard flag package itself ("flag provided but not
// defined") rather than accepted and then refused by openTPMDevice
// above. Only the testtpm build (tpmdevice_testtpm.go) defines the flag,
// for CI/E3's swtpm-backed runs.
func tpmDeviceFlag() *string {
	device := productionTPMDevice
	return &device
}
