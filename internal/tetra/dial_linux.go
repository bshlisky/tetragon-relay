//go:build linux

package tetra

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// selinuxLabelType is the required SELinux type component of the socket's
// security.selinux context (architecture doc section 8.8, Part B2).
const selinuxLabelType = "tetragon_var_run_t"

var warnSELinuxDisabledOnce sync.Once

// Dial implements step 3 prompt Part B2: it verifies the configured
// socket's owner/group/mode/SELinux label via lstat (no symlink follow)
// before every connection attempt — including every gRPC-internal
// reconnect, since grpc invokes the dialer again on each one — and verifies
// the connected peer's credentials, SELinux domain and cgroup once the
// connection is actually established (step-03a-review.md R3-1 amendment).
func Dial(_ context.Context, cfg Config) (*Client, error) {
	gid, err := cfg.relayGID()
	if err != nil {
		return nil, fmt.Errorf("%w: resolve relay group %q: %w", ErrSocketVerification, cfg.RelayGroupName, err)
	}

	peer := &peerTracker{}
	dialer := func(dialCtx context.Context, _ string) (net.Conn, error) {
		if err := verifySocketFile(cfg, gid); err != nil {
			return nil, err
		}
		conn, err := connectAndVerifyPeer(dialCtx, cfg)
		if err != nil {
			return nil, err
		}
		recordPeer(peer, conn)
		return conn, nil
	}

	conn, err := grpc.NewClient("passthrough:///"+cfg.SocketPath, cfg.dialOptions(dialer)...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	c := NewUnverified(conn, cfg)
	c.peer = peer
	return c, nil
}

// recordPeer records conn's SO_PEERCRED pid in peer (Client.Peer). conn
// already passed connectAndVerifyPeer, which read the same credentials;
// a failure to read them again here leaves peer unchanged.
func recordPeer(peer *peerTracker, conn net.Conn) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	if _, pid, err := peerCredFunc(uc); err == nil {
		peer.record(pid)
	}
}

// connectAndVerifyPeer is the post-lstat half of Dial's dialer closure:
// the actual unix-socket connect, followed by Part B2's post-connect
// identity checks. Split out from Dial itself (rather than left as an
// inline closure) specifically so it can be unit-tested directly against
// a real socket this test process owns, bypassing only the owner-uid-0
// check verifySocketFile performs beforehand (which inherently requires
// root and is already exhaustively tested in isolation via
// evaluateSocketStat's synthetic-FileInfo cases) — Dial itself is
// unchanged and still calls verifySocketFile first, in production, every
// time.
func connectAndVerifyPeer(dialCtx context.Context, cfg Config) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "unix", cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %w", ErrUnavailable, cfg.SocketPath, err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: unexpected connection type %T", ErrSocketVerification, conn)
	}
	if err := verifyPeerCredAndTetragon(cfg, uc); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// verifySocketFile implements Part B2's pre-connect checks: lstat (never
// following a symlink — os.Lstat, not os.Stat), must be a socket, owner
// uid 0, group must equal gid, mode must not be more permissive than
// 0660, and (if SELinux is enabled, or !Config.AllowSELinuxDisabled) the
// security.selinux xattr's type component must be selinuxLabelType.
func verifySocketFile(cfg Config, gid uint32) error {
	fi, err := os.Lstat(cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("%w: lstat %s: %w", ErrSocketVerification, cfg.SocketPath, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: could not read owner/group of %s", ErrSocketVerification, cfg.SocketPath)
	}
	if err := evaluateSocketStat(cfg.SocketPath, cfg.RelayGroupName, fi, st, gid); err != nil {
		return err
	}
	return verifySELinuxLabel(cfg)
}

// evaluateSocketStat is the pure, side-effect-free half of Part B2's
// pre-connect checks (symlink/socket-type/owner/group/mode), split out
// from verifySocketFile so tests can exercise every branch with a
// synthetic os.FileInfo + syscall.Stat_t instead of needing root to
// actually own a file as uid 0 (step 3 prompt Part E2).
func evaluateSocketStat(path, groupName string, fi os.FileInfo, st *syscall.Stat_t, gid uint32) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrSocketVerification, path)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: %s is not a socket", ErrSocketVerification, path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%w: %s is owned by uid %d, want 0", ErrSocketVerification, path, st.Uid)
	}
	if st.Gid != gid {
		return fmt.Errorf("%w: %s is owned by gid %d, want %d (%s)", ErrSocketVerification, path, st.Gid, gid, groupName)
	}
	if perm := fi.Mode().Perm(); perm&^0o660 != 0 {
		return fmt.Errorf("%w: %s has mode %04o, want no more permissive than 0660", ErrSocketVerification, path, perm)
	}
	return nil
}

// getxattrFunc is a package variable so tests can stub the xattr read
// (step 3 prompt Part E2: "use a test hook for xattr reads") without
// needing a real SELinux-enabled filesystem.
var getxattrFunc = unix.Lgetxattr

func verifySELinuxLabel(cfg Config) error {
	buf := make([]byte, 256)
	n, err := getxattrFunc(cfg.SocketPath, "security.selinux", buf)
	if err != nil {
		if isSELinuxDisabledErr(err) {
			if !cfg.AllowSELinuxDisabled {
				return fmt.Errorf("%w: SELinux is disabled on this host but allow_selinux_disabled is false", ErrSocketVerification)
			}
			warnSELinuxDisabledOnce.Do(func() {
				cfg.logger().Warn("SELinux is disabled on this host; continuing because allow_selinux_disabled is true", "socket", cfg.SocketPath)
			})
			return nil
		}
		return fmt.Errorf("%w: read security.selinux xattr on %s: %w", ErrSocketVerification, cfg.SocketPath, err)
	}
	context := strings.TrimRight(string(buf[:n]), "\x00")
	parts := strings.SplitN(context, ":", 4)
	if len(parts) < 3 || parts[2] != selinuxLabelType {
		return fmt.Errorf("%w: %s has SELinux context %q, want type %q", ErrSocketVerification, cfg.SocketPath, context, selinuxLabelType)
	}
	return nil
}

// isSELinuxDisabledErr reports whether err indicates "this filesystem/host
// has no security.selinux xattr to read" (SELinux disabled or the
// filesystem doesn't support security xattrs), as opposed to some other
// I/O failure that should not be silently downgraded to a warning.
func isSELinuxDisabledErr(err error) bool {
	return errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)
}

// peerCredFunc and getsockoptPeerSecFunc are package variables so tests
// can stub SO_PEERCRED and SO_PEERSEC resolution.
var (
	peerCredFunc = func(uc *net.UnixConn) (uid uint32, pid int32, err error) {
		raw, err := uc.SyscallConn()
		if err != nil {
			return 0, 0, err
		}
		var cred *unix.Ucred
		var sysErr error
		err = raw.Control(func(fd uintptr) {
			cred, sysErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		})
		if err != nil {
			return 0, 0, err
		}
		if sysErr != nil {
			return 0, 0, sysErr
		}
		return cred.Uid, cred.Pid, nil
	}
	// getsockoptPeerSecFunc implements SO_PEERSEC (SO_PEERSEC(2const)):
	// "returns the security context of the peer socket connected to this
	// socket", which for a Unix domain stream socket is the SELinux
	// context of the process that created the peer end at connect time —
	// available directly from the kernel's socket security struct, with
	// no /proc access and no special capability.
	getsockoptPeerSecFunc = func(uc *net.UnixConn) (string, error) {
		raw, err := uc.SyscallConn()
		if err != nil {
			return "", err
		}
		var sec string
		var sysErr error
		err = raw.Control(func(fd uintptr) {
			sec, sysErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_PEERSEC)
		})
		if err != nil {
			return "", err
		}
		return sec, sysErr
	}
	// verifyPeerCgroupFunc lets tests stub the cgroup v2 membership check
	// (peercgroup_linux.go) without a real cgroupfs layout.
	verifyPeerCgroupFunc = verifyPeerCgroup
)

var warnPeerSELinuxDisabledOnce sync.Once

// isPeerSELinuxUnavailableErr reports whether err indicates "no LSM
// security module is providing a peer security context" (SELinux
// disabled), as opposed to some other getsockopt failure. SO_PEERSEC
// returns ENOPROTOOPT in this case, confirmed by both systemd
// (src/basic/socket-util.c's getpeersec(), which treats exactly
// ENOPROTOOPT this way) and the Linux AppArmor SO_PEERSEC implementation
// (Ubuntu launchpad bug 1235478's strace: "getsockopt(... SO_PEERSEC
// ...) = -1 ENOPROTOOPT"); EOPNOTSUPP is included defensively for the
// same "not supported" class, mirroring verifySELinuxLabel's xattr
// handling above.
func isPeerSELinuxUnavailableErr(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP)
}

// verifyPeerSELinux implements the R3-1 amendment's SO_PEERSEC check: the
// peer's own SELinux context type must equal cfg.peerSELinuxType()
// (default "tetragon_t"). active is true only when a real comparison was
// made (SELinux enabled); it is false when the check was skipped because
// SELinux is disabled and cfg.AllowSELinuxDisabled is true — the only
// case where err is also nil without active being true.
//
// step-03b-review.md R3B-1: when cfg.HostSELinuxMode positively asserts
// SELinux is enforcing or permissive (from internal/hostprobe's
// independently-collected host facts, not from anything this socket
// connection itself reports), neither SO_PEERSEC failure mode below is
// ever treated as "SELinux disabled" — a host that host-probe says is
// SELinux-enforcing but whose peer returns no usable SELinux context is
// a verification failure regardless of AllowSELinuxDisabled, since that
// combination means either the peer is lying about its context or this
// host's SELinux state is inconsistent between the two independent
// sources, neither of which this check may paper over.
func verifyPeerSELinux(cfg Config, uc *net.UnixConn) (active bool, err error) {
	sec, gerr := getsockoptPeerSecFunc(uc)
	disabled := func() (bool, error) {
		if cfg.hostSELinuxEnforcingOrPermissive() {
			return false, fmt.Errorf("%w: host facts report SELinux %s but socket peer has no usable SELinux SO_PEERSEC context", ErrSocketVerification, cfg.HostSELinuxMode)
		}
		if !cfg.AllowSELinuxDisabled {
			return false, fmt.Errorf("%w: SELinux is disabled on this host but allow_selinux_disabled is false", ErrSocketVerification)
		}
		warnPeerSELinuxDisabledOnce.Do(func() {
			cfg.logger().Warn("SELinux is disabled on this host; continuing because allow_selinux_disabled is true", "check", "peer_so_peersec")
		})
		return false, nil
	}
	if gerr != nil {
		if isPeerSELinuxUnavailableErr(gerr) {
			return disabled()
		}
		return false, fmt.Errorf("%w: SO_PEERSEC: %w", ErrSocketVerification, gerr)
	}
	parts := strings.SplitN(sec, ":", 4)
	if len(parts) < 3 {
		// SO_PEERSEC is not SELinux-specific: AppArmor implements it too
		// (Ubuntu launchpad bug 1235478), returning its own bare label
		// (e.g. "unconfined", with no colons) instead of SELinux's
		// "user:role:type:level" format. On a host where AppArmor, not
		// SELinux, is the active LSM providing SO_PEERSEC (observed on
		// GitHub-hosted ubuntu-24.04 runners), getsockopt succeeds but
		// returns a label this check cannot interpret as an SELinux
		// type — handled the same as SELinux being unavailable, not as
		// a type mismatch, UNLESS host facts say SELinux is actually
		// enforcing/permissive (disabled() handles that above).
		return disabled()
	}
	if parts[2] != cfg.peerSELinuxType() {
		return false, fmt.Errorf("%w: socket peer has SELinux context %q, want type %q", ErrSocketVerification, sec, cfg.peerSELinuxType())
	}
	return true, nil
}

// verifyPeerCredAndTetragon implements the R3-1 amendment's post-connect
// checks, replacing the reverted /proc/<pid>/exe check: SO_PEERCRED uid
// must be 0, and the peer must be verified as Tetragon by at least one of
// two checks that need no capability — SO_PEERSEC (peer SELinux domain)
// and cgroup v2 membership (peercgroup_linux.go) — run together when
// both are available, with the cgroup check's absence (cgroup v1/hybrid)
// tolerated only when the SELinux check actively passed.
func verifyPeerCredAndTetragon(cfg Config, uc *net.UnixConn) error {
	uid, pid, err := peerCredFunc(uc)
	if err != nil {
		return fmt.Errorf("%w: SO_PEERCRED: %w", ErrSocketVerification, err)
	}
	if uid != 0 {
		return fmt.Errorf("%w: socket peer uid is %d, want 0", ErrSocketVerification, uid)
	}

	selinuxActive, err := verifyPeerSELinux(cfg, uc)
	if err != nil {
		return err
	}

	cgroupResult, err := verifyPeerCgroupFunc(cfg, pid)
	if err != nil {
		return err
	}
	if cgroupResult.Available {
		if !cgroupResult.Passed {
			return fmt.Errorf("%w: socket peer pid %d is not in cgroup %q", ErrSocketVerification, pid, cfg.unitCgroupPath())
		}
		return nil
	}
	// cgroup v2 unavailable (v1/hybrid layout): accepted only if the
	// SELinux check actively ran and passed (step-03a-review.md R3-1
	// amendment: "fails closed (typed error) unless the SO_PEERSEC check
	// is active and passed").
	if !selinuxActive {
		return fmt.Errorf("%w: cgroup v2 is unavailable on this host and the SO_PEERSEC check did not actively pass; cannot verify socket peer %d", ErrSocketVerification, pid)
	}
	return nil
}

// dialOptions are Dial's grpc options: the verifying dialer, no transport
// security (a local unix socket whose peer Dial verifies), the response
// size limit, and the optional buffer sizes.
func (c Config) dialOptions(dialer func(context.Context, string) (net.Conn, error)) []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(limits.MaxGetEventsResponseBytes)),
	}
	if c.ReadBufferSize > 0 {
		opts = append(opts, grpc.WithReadBufferSize(c.ReadBufferSize))
	}
	if c.InitialWindowSize > 0 {
		opts = append(opts, grpc.WithInitialWindowSize(c.InitialWindowSize), grpc.WithInitialConnWindowSize(c.InitialWindowSize))
	}
	return opts
}
