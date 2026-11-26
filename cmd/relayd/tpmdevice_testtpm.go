//go:build testtpm

package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

// openTPMDevice, under the testtpm build tag only (docs/prompts/
// step-06a.md C3: "the test TPM transport remains available only under
// its build tag, for CI/E3"), additionally accepts
// "tcp:<command host:port>,<platform host:port>" to reach a software TPM
// (swtpm) over TCP -- the same transport internal/controlclient's own
// integration_test.go (build tag testca) already uses to drive a real
// swtpm for enrollment testing. go-tpm's tcp.Open dials BOTH the command
// and the platform (control) channel and fails if either is missing
// (vendor/github.com/google/go-tpm/tpm2/transport/tcp/tcp.go, Open), so
// both addresses are required; E3 run 45817131291 failed with "could not
// connect to platform service at \"\"" when only the command address
// was passed. A bare "/dev/tpmrm0" still opens the real device, so this
// build tag never changes production behavior when the path is left at
// its default.
func openTPMDevice(path string) (transport.TPMCloser, error) {
	if spec, ok := strings.CutPrefix(path, "tcp:"); ok {
		cfg, err := parseTCPTPMSpec(spec)
		if err != nil {
			return nil, err
		}
		tt, err := tcp.Open(cfg)
		if err != nil {
			return nil, fmt.Errorf("relayd: open swtpm at %s: %w", spec, err)
		}
		return tt, nil
	}
	return linuxtpm.Open(path)
}

// parseTCPTPMSpec parses "<command host:port>,<platform host:port>".
// Exactly two non-empty, comma-separated addresses; anything else is
// rejected rather than defaulted.
func parseTCPTPMSpec(spec string) (tcp.Config, error) {
	parts := strings.Split(spec, ",")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return tcp.Config{}, fmt.Errorf("relayd: --tpm-device tcp: wants \"tcp:<command host:port>,<platform host:port>\", got %q", "tcp:"+spec)
	}
	return tcp.Config{CommandAddress: parts[0], PlatformAddress: parts[1]}, nil
}

// tpmDeviceFlag defines --tpm-device, only under the testtpm build tag
// (R6A-3): a production build has no such flag at all (tpmdevice.go),
// so passing one to a production binary is rejected by the standard
// flag package as unknown, not silently accepted and then refused.
func tpmDeviceFlag() *string {
	return flag.String("tpm-device", productionTPMDevice, "TPM resource manager device (testtpm builds also accept tcp:<command host:port>,<platform host:port> for a software TPM)")
}
