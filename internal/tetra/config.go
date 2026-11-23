// Package tetra implements step 3 prompt Part B: a gRPC client to a real
// Tetragon v1.8.0, restricted to a fixed, typed allowlist of RPCs
// (AddTracingPolicy, DeleteTracingPolicy, ListTracingPolicies,
// EnableTracingPolicy, DisableTracingPolicy, GetHealth, GetVersion,
// GetEvents; TestAllowlist_NoOtherRPCsReferenced fails the build's test
// suite if any other FineGuidanceSensorsClient method is ever referenced
// from this package's own source). Every call is made over a unix socket
// whose peer this package verifies before every dial (architecture doc
// section 8.8, Part B2), with a bounded timeout (Part B3) and a version
// gate against the pinned v1.8.x family (Part B4).
package tetra

import (
	"log/slog"
	"os/user"
	"strconv"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// Config carries everything a Client needs to dial and verify Tetragon's
// socket. There is no default for SocketPath, TetragonBinaryPath, or
// RelayGroup: architecture doc section 8.6 treats these as
// deployment-specific and requires them to come from the agent's
// configuration file, never a compiled-in guess.
type Config struct {
	// SocketPath is the Tetragon gRPC unix socket (architecture doc
	// section 8.9, e.g. "/var/run/tetragon/tetragon.sock").
	SocketPath string
	// TetragonBinaryPath is the configured, trusted path to the Tetragon
	// daemon binary (e.g. "/usr/local/bin/tetragon"). Part B2's final
	// check resolves the connected peer's pid's /proc/<pid>/exe and
	// compares it against this path.
	TetragonBinaryPath string
	// RelayGroupName is the POSIX group the socket's group ownership
	// must match (Part B2). Resolved to a gid at verification time (not
	// cached at startup) so a group rename/gid change takes effect
	// without an agent restart.
	RelayGroupName string
	// SELinuxRequired, when false, allows Part B2's SELinux label check
	// to be skipped (logged once) on a host where SELinux is disabled.
	// When true (the default), a disabled SELinux is itself a
	// verification failure. Architecture doc section 9.2 expects
	// SELinux enforcing on RHEL 9, so the zero value is the safer
	// (fail-closed) choice; a config that wants to opt out must say so
	// explicitly.
	SELinuxRequired bool
	// Timeout bounds every RPC (Part B3). Zero means
	// limits.DefaultTetragonRPCTimeout.
	Timeout time.Duration
	// Logger receives the "SELinux disabled, continuing" notice Part B2
	// requires to be logged once. Defaults to slog.Default() if nil.
	Logger *slog.Logger
}

func (c Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return limits.DefaultTetragonRPCTimeout
	}
	return c.Timeout
}

// relayGID resolves Config.RelayGroupName to a numeric gid. Kept as a
// method (not inlined) so socket_verify.go's tests can stub group lookup
// via a config pointing at a fake /etc/group in the future without
// touching this package's public surface; today it uses the standard
// library's NSS-backed lookup directly, which is sufficient for the
// RHEL 9 target (architecture doc section 8.6).
func (c Config) relayGID() (uint32, error) {
	g, err := user.LookupGroup(c.RelayGroupName)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(gid), nil
}
