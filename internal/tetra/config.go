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

// HostSELinuxEnforcing and HostSELinuxPermissive are the
// Config.HostSELinuxMode values that make verifyPeerSELinux's
// AppArmor-style bare-label fallback a hard failure instead of "SELinux
// disabled" (step-03b-review.md R3B-1). These are string-for-string
// copies of internal/hostprobe.HostFacts.SELinuxMode's own values (not
// imported, to keep this package decoupled from internal/hostprobe); a
// test (TestHostSELinuxModeConstants, not in this file, step-04a) is
// expected to assert that equality holds.
const (
	HostSELinuxEnforcing  = "enforcing"
	HostSELinuxPermissive = "permissive"
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
	// AllowSELinuxDisabled, when true, lets Part B2's SELinux label check
	// (and the R3-1 amendment's SO_PEERSEC peer check) be skipped (logged
	// once) on a host where SELinux is disabled. The zero value (false)
	// is the fail-closed choice: SELinux is required, matching
	// architecture doc section 9.2's expectation of SELinux enforcing on
	// RHEL 9. A Go bool's zero value is false, so naming this field for
	// its "allow the weaker behavior" sense (rather than the inverted
	// "SELinuxRequired") means a caller that forgets to set it gets the
	// secure default, not a silent opt-out (step-03b-review.md R3B-1: the
	// previous name's zero value was the fail-open setting, the opposite
	// of what its own doc comment claimed).
	//
	// HostSELinuxMode, not this field, governs whether an unparseable
	// (non-SELinux, e.g. AppArmor) SO_PEERSEC peer label is ever treated
	// as "SELinux disabled" in the first place: when HostSELinuxMode is
	// "enforcing" or "permissive", that fallback never applies and the
	// peer check fails regardless of AllowSELinuxDisabled.
	AllowSELinuxDisabled bool
	// HostSELinuxMode is the host's SELinux mode as independently
	// determined by internal/hostprobe.HostFacts.SELinuxMode
	// ("enforcing", "permissive", or "disabled"), passed in by the
	// caller rather than read directly by this package (internal/tetra
	// stays decoupled from internal/hostprobe, the same way
	// internal/apply duplicates rather than imports internal/guard's
	// action list). Empty means "unknown" (facts not wired up by this
	// caller yet) and is treated the same as "disabled" for the one
	// place this field is consulted (verifyPeerSELinux's AppArmor-style
	// bare-label fallback, step-03b-review.md R3B-1): a host that does
	// not positively assert SELinux is enforcing/permissive gets the
	// pre-R3B-1 behavior, never a new failure mode sprung on an
	// un-migrated caller.
	HostSELinuxMode string
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

// hostSELinuxEnforcingOrPermissive reports whether HostSELinuxMode
// positively asserts SELinux is active on this host (as opposed to
// "disabled" or "" meaning unknown/not wired up).
func (c Config) hostSELinuxEnforcingOrPermissive() bool {
	return c.HostSELinuxMode == HostSELinuxEnforcing || c.HostSELinuxMode == HostSELinuxPermissive
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
