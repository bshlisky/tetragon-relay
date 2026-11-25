package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// OpenDevice opens the TPM resource manager device at path. Production
// callers must always pass "/dev/tpmrm0" (architecture doc section 8.6):
// the kernel resource manager multiplexes sessions and transient object
// slots across every process using the TPM, which /dev/tpm0 (the raw
// device) does not do, and relayd running alongside any other TPM user on
// the host (e.g. a future SPIRE agent, step 5b) would otherwise corrupt
// each other's sessions. This package never opens any other path itself;
// the caller (cmd/relay-probe, internal/agent's wiring) is responsible for
// passing only "/dev/tpmrm0" in production, matching the systemd unit's
// own DeviceAllow=/dev/tpmrm0 rw (packaging/systemd/tetragon-relay.service).
//
// linuxtpm.Open builds and runs unmodified on any platform (it is a plain
// os.OpenFile against the given path with no Linux-specific syscalls), so
// this package has no platform-specific build files: it simply fails at
// runtime, not at build time, if the path does not exist or is not a
// device file.
func OpenDevice(path string) (transport.TPMCloser, error) {
	return linuxtpm.Open(path)
}
