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
	"strings"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// defaultPeerSELinuxType and defaultUnitCgroupPath are Config's defaults
// for the post-connect peer checks added by the step 3a architect review's
// R3-1 amendment (docs/reviews/step-03a-review.md): the SELinux domain
// Tetragon is expected to run in, and the cgroup v2 unified-hierarchy path
// (relative to /sys/fs/cgroup) of the systemd unit Tetragon runs under.
const (
	defaultPeerSELinuxType = "tetragon_t"
	defaultUnitCgroupPath  = "system.slice/tetragon.service"
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
	// daemon binary (e.g. "/usr/local/bin/tetragon"). No longer used by
	// Part B2's post-connect peer check (step-03a-review.md R3-1: the
	// /proc/<pid>/exe check it drove required CAP_SYS_PTRACE, which
	// architecture doc section 8.7 forbids); kept on Config because
	// cmd/relay-probe and internal/hostprobe still use it to verify the
	// Tetragon binary's own hash/path at host-fact collection time.
	TetragonBinaryPath string
	// RelayGroupName is the POSIX group the socket's group ownership
	// must match (Part B2). Resolved to a gid at verification time (not
	// cached at startup) so a group rename/gid change takes effect
	// without an agent restart.
	RelayGroupName string
	// SELinuxRequired, when false, allows Part B2's SELinux label check
	// (and the R3-1 amendment's SO_PEERSEC peer check) to be skipped
	// (logged once) on a host where SELinux is disabled. When true (the
	// default), a disabled SELinux is itself a verification failure.
	// Architecture doc section 9.2 expects SELinux enforcing on RHEL 9,
	// so the zero value is the safer (fail-closed) choice; a config that
	// wants to opt out must say so explicitly.
	SELinuxRequired bool
	// PeerSELinuxType is the expected SELinux type component of the
	// connected peer's own SO_PEERSEC security context (step-03a-review.md
	// R3-1 amendment, replacing the reverted /proc/<pid>/exe check).
	// Defaults to "tetragon_t" if empty.
	PeerSELinuxType string
	// UnitCgroupPath is the expected cgroup v2 unified-hierarchy path,
	// relative to /sys/fs/cgroup, of the systemd unit Tetragon runs under
	// (R3-1 amendment). Defaults to "system.slice/tetragon.service" if
	// empty. A leading "/" is tolerated and stripped.
	UnitCgroupPath string
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

func (c Config) peerSELinuxType() string {
	if c.PeerSELinuxType == "" {
		return defaultPeerSELinuxType
	}
	return c.PeerSELinuxType
}

func (c Config) unitCgroupPath() string {
	if c.UnitCgroupPath == "" {
		return defaultUnitCgroupPath
	}
	return strings.TrimPrefix(c.UnitCgroupPath, "/")
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
