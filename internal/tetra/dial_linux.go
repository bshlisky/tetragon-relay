//go:build linux

package tetra

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
// the connected peer's credentials and resolved binary path once the
// connection is actually established.
func Dial(_ context.Context, cfg Config) (*Client, error) {
	gid, err := cfg.relayGID()
	if err != nil {
		return nil, fmt.Errorf("%w: resolve relay group %q: %w", ErrSocketVerification, cfg.RelayGroupName, err)
	}

	dialer := func(dialCtx context.Context, _ string) (net.Conn, error) {
		if err := verifySocketFile(cfg, gid); err != nil {
			return nil, err
		}
		return connectAndVerifyPeer(dialCtx, cfg.SocketPath, cfg.TetragonBinaryPath)
	}

	conn, err := grpc.NewClient("passthrough:///"+cfg.SocketPath,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(limits.MaxGetEventsResponseBytes)),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return NewUnverified(conn, cfg), nil
}

// connectAndVerifyPeer is the post-lstat half of Dial's dialer closure:
// the actual unix-socket connect, followed by Part B2's post-connect
// SO_PEERCRED/exe checks. Split out from Dial itself (rather than left as
// an inline closure) specifically so it can be unit-tested directly
// against a real socket this test process owns, bypassing only the
// owner-uid-0 check verifySocketFile performs beforehand (which
// inherently requires root and is already exhaustively tested in
// isolation via evaluateSocketStat's synthetic-FileInfo cases) — Dial
// itself is unchanged and still calls verifySocketFile first, in
// production, every time.
func connectAndVerifyPeer(dialCtx context.Context, socketPath, tetragonBinaryPath string) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %w", ErrUnavailable, socketPath, err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: unexpected connection type %T", ErrSocketVerification, conn)
	}
	if err := verifyPeerCredAndExe(uc, tetragonBinaryPath); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// verifySocketFile implements Part B2's pre-connect checks: lstat (never
// following a symlink — os.Lstat, not os.Stat), must be a socket, owner
// uid 0, group must equal gid, mode must not be more permissive than
// 0660, and (if SELinux is enabled, or Config.SELinuxRequired) the
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
			if cfg.SELinuxRequired {
				return fmt.Errorf("%w: SELinux is disabled on this host but selinux_required is true", ErrSocketVerification)
			}
			warnSELinuxDisabledOnce.Do(func() {
				cfg.logger().Warn("SELinux is disabled on this host; continuing because selinux_required is false", "socket", cfg.SocketPath)
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

// peerCredFunc and peerExeFunc are package variables so tests can stub
// SO_PEERCRED and /proc/<pid>/exe resolution.
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
	peerExeFunc = func(pid int32) (string, error) {
		return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	}
)

// verifyPeerCredAndExe implements Part B2's post-connect checks: the
// socket peer's SO_PEERCRED uid must be 0, and the peer pid's resolved
// /proc/<pid>/exe must equal the configured Tetragon binary path exactly
// (no prefix/suffix matching, so a binary at a look-alike path never
// passes).
func verifyPeerCredAndExe(uc *net.UnixConn, wantExe string) error {
	uid, pid, err := peerCredFunc(uc)
	if err != nil {
		return fmt.Errorf("%w: SO_PEERCRED: %w", ErrSocketVerification, err)
	}
	if uid != 0 {
		return fmt.Errorf("%w: socket peer uid is %d, want 0", ErrSocketVerification, uid)
	}
	exe, err := peerExeFunc(pid)
	if err != nil {
		return fmt.Errorf("%w: resolve /proc/%d/exe: %w", ErrSocketVerification, pid, err)
	}
	wantAbs, err := filepath.Abs(wantExe)
	if err != nil {
		return fmt.Errorf("%w: configured Tetragon binary path %q: %w", ErrSocketVerification, wantExe, err)
	}
	if exe != wantAbs {
		return fmt.Errorf("%w: socket peer pid %d is %q, want %q", ErrSocketVerification, pid, exe, wantAbs)
	}
	return nil
}
