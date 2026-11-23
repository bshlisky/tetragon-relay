//go:build linux

package tetra

import (
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// fakeFileInfo is a minimal os.FileInfo for exercising evaluateSocketStat's
// branches without touching the real filesystem (step 3 prompt Part E2:
// wrong owner/mode/symlink/regular file). Only Mode() is ever read by
// evaluateSocketStat; the rest exist to satisfy the os.FileInfo interface.
type fakeFileInfo struct {
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return "s" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

// TestDial_BadRelayGroup covers Dial's own relayGID resolution failure, no
// root required.
func TestDial_BadRelayGroup(t *testing.T) {
	cfg := Config{SocketPath: "/nonexistent", RelayGroupName: "this-group-should-not-exist-tetragon-relay"}
	if _, err := Dial(context.Background(), cfg); err == nil {
		t.Fatal("Dial with an unresolvable relay group returned no error")
	}
}

// currentGroupName resolves the invoking user's primary group name, used
// by tests below that need a RelayGroupName guaranteed to resolve without
// root (CI runners are never root for the plain "ci" job).
func currentGroupName(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("LookupGroupId: %v", err)
	}
	return g.Name
}

// TestDial_NonexistentSocket exercises Dial's full construction path (gid
// resolution, dialer closure, grpc.NewClient) plus the dialer's
// verifySocketFile call on the first real RPC attempt, with no root
// required: grpc.NewClient itself never dials eagerly, so Dial succeeds,
// and the failure surfaces on the first RPC.
func TestDial_NonexistentSocket(t *testing.T) {
	cfg := Config{
		SocketPath:         filepath.Join(t.TempDir(), "does-not-exist"),
		TetragonBinaryPath: "/usr/sbin/tetragon",
		RelayGroupName:     currentGroupName(t),
		Timeout:            2 * time.Second,
	}
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.GetVersion(ctx); err == nil {
		t.Fatal("GetVersion over a nonexistent socket returned no error")
	}
}

// TestDial_RealSocketWrongOwner creates a real unix socket owned by this
// (non-root) test process and dials it for real through Dial, expecting
// the post-lstat owner check to reject it — covering verifySocketFile's
// real os.Lstat + syscall.Stat_t path (not just evaluateSocketStat's
// synthetic-FileInfo unit test above) without requiring root.
func TestDial_RealSocketWrongOwner(t *testing.T) {
	dir, err := os.MkdirTemp("", "tetradialowner")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "s")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	if err := os.Chmod(sock, 0o660); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		SocketPath:         sock,
		TetragonBinaryPath: "/usr/sbin/tetragon",
		RelayGroupName:     currentGroupName(t),
		Timeout:            2 * time.Second,
	}
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.GetVersion(ctx); err == nil {
		t.Fatal("GetVersion over a socket not owned by uid 0 returned no error")
	}
}

// TestVerifySocketFile_RealFilesystemObjects exercises verifySocketFile's
// real os.Lstat + syscall.Stat_t path (the wrapper around
// evaluateSocketStat, which is unit-tested above with a synthetic
// os.FileInfo) against real filesystem objects this non-root test process
// can create directly: a regular file, a symlink, and a real socket owned
// by the wrong (non-root) uid.
func TestVerifySocketFile_RealFilesystemObjects(t *testing.T) {
	dir, err := os.MkdirTemp("", "tetraverify")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	gid, err := Config{RelayGroupName: currentGroupName(t)}.relayGID()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("regular_file_not_socket", func(t *testing.T) {
		p := filepath.Join(dir, "regular")
		if err := os.WriteFile(p, []byte("x"), 0o660); err != nil {
			t.Fatal(err)
		}
		cfg := Config{SocketPath: p, RelayGroupName: currentGroupName(t)}
		if err := verifySocketFile(cfg, gid); err == nil {
			t.Fatal("verifySocketFile accepted a regular file")
		}
	})

	t.Run("symlink_to_socket", func(t *testing.T) {
		realSock := filepath.Join(dir, "real.sock")
		lis, err := net.Listen("unix", realSock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lis.Close() }()
		link := filepath.Join(dir, "link.sock")
		if err := os.Symlink(realSock, link); err != nil {
			t.Fatal(err)
		}
		cfg := Config{SocketPath: link, RelayGroupName: currentGroupName(t)}
		if err := verifySocketFile(cfg, gid); err == nil {
			t.Fatal("verifySocketFile accepted a symlink")
		}
	})

	t.Run("real_socket_wrong_owner", func(t *testing.T) {
		p := filepath.Join(dir, "owned.sock")
		lis, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lis.Close() }()
		if err := os.Chmod(p, 0o660); err != nil {
			t.Fatal(err)
		}
		cfg := Config{SocketPath: p, RelayGroupName: currentGroupName(t)}
		if err := verifySocketFile(cfg, gid); err == nil {
			t.Fatal("verifySocketFile accepted a socket not owned by uid 0")
		}
	})

	t.Run("nonexistent_path", func(t *testing.T) {
		cfg := Config{SocketPath: filepath.Join(dir, "nope"), RelayGroupName: currentGroupName(t)}
		if err := verifySocketFile(cfg, gid); err == nil {
			t.Fatal("verifySocketFile accepted a nonexistent path")
		}
	})
}

func TestEvaluateSocketStat(t *testing.T) {
	const wantGID = 123
	cases := []struct {
		name    string
		mode    os.FileMode
		uid     uint32
		gid     uint32
		wantErr bool
	}{
		{"valid_socket", os.ModeSocket | 0o660, 0, wantGID, false},
		{"symlink", os.ModeSymlink | os.ModeSocket | 0o660, 0, wantGID, true},
		{"regular_file_not_socket", 0o660, 0, wantGID, true},
		{"wrong_owner", os.ModeSocket | 0o660, 1000, wantGID, true},
		{"wrong_group", os.ModeSocket | 0o660, 0, 999, true},
		{"mode_too_permissive_world", os.ModeSocket | 0o662, 0, wantGID, true},
		{"mode_too_permissive_group_exec", os.ModeSocket | 0o670, 0, wantGID, true},
		{"mode_exactly_0640_ok", os.ModeSocket | 0o640, 0, wantGID, false},
		{"mode_exactly_0600_ok", os.ModeSocket | 0o600, 0, wantGID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fi := fakeFileInfo{mode: tc.mode}
			st := &syscall.Stat_t{Uid: tc.uid, Gid: tc.gid}
			err := evaluateSocketStat("/fake/path", "relaygroup", fi, st, wantGID)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestGetxattrFunc_Real exercises the real (non-stubbed) getxattrFunc
// (unix.Lgetxattr) against a real file. On a host with SELinux disabled
// (every GitHub-hosted ubuntu-24.04 runner), this returns ENODATA/
// ENOTSUP, exercising isSELinuxDisabledErr's real caller path end to end.
func TestGetxattrFunc_Real(t *testing.T) {
	dir, err := os.MkdirTemp("", "tetraxattr")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	_, err = getxattrFunc(p, "security.selinux", buf)
	if err == nil {
		t.Skip("security.selinux xattr present and readable on this host; nothing to assert")
	}
	if !isSELinuxDisabledErr(err) {
		t.Fatalf("getxattrFunc on a host with no SELinux xattr returned an unexpected error: %v", err)
	}
}

func TestVerifySELinuxLabel(t *testing.T) {
	restore := getxattrFunc
	defer func() { getxattrFunc = restore }()

	t.Run("correct_label", func(t *testing.T) {
		getxattrFunc = func(_, _ string, dest []byte) (int, error) {
			s := "system_u:object_r:tetragon_var_run_t:s0"
			n := copy(dest, s)
			return n, nil
		}
		if err := verifySELinuxLabel(Config{SocketPath: "/fake"}); err != nil {
			t.Fatalf("correct label rejected: %v", err)
		}
	})

	t.Run("wrong_label", func(t *testing.T) {
		getxattrFunc = func(_, _ string, dest []byte) (int, error) {
			s := "system_u:object_r:var_run_t:s0"
			n := copy(dest, s)
			return n, nil
		}
		if err := verifySELinuxLabel(Config{SocketPath: "/fake"}); err == nil {
			t.Fatal("wrong SELinux label accepted")
		}
	})

	t.Run("disabled_selinux_required_false", func(t *testing.T) {
		getxattrFunc = func(_, _ string, _ []byte) (int, error) {
			return 0, unix.ENODATA
		}
		if err := verifySELinuxLabel(Config{SocketPath: "/fake", SELinuxRequired: false}); err != nil {
			t.Fatalf("disabled SELinux with selinux_required=false rejected: %v", err)
		}
	})

	t.Run("disabled_selinux_required_true", func(t *testing.T) {
		getxattrFunc = func(_, _ string, _ []byte) (int, error) {
			return 0, unix.ENOTSUP
		}
		if err := verifySELinuxLabel(Config{SocketPath: "/fake", SELinuxRequired: true}); err == nil {
			t.Fatal("disabled SELinux with selinux_required=true accepted")
		}
	})

	t.Run("other_xattr_error_always_rejected", func(t *testing.T) {
		getxattrFunc = func(_, _ string, _ []byte) (int, error) {
			return 0, unix.EACCES
		}
		if err := verifySELinuxLabel(Config{SocketPath: "/fake", SELinuxRequired: false}); err == nil {
			t.Fatal("an unrelated xattr read error was treated as disabled SELinux")
		}
	})
}

// realUnixConnPair returns a connected *net.UnixConn client half, backed
// by a real unix socket in a temp dir, for tests that need a genuine
// *net.UnixConn value to pass through verifyPeerCredAndExe (whose own
// behavior under test is fully controlled via peerCredFunc/peerExeFunc
// stubs, not by anything this connection actually carries).
func realUnixConnPair(t *testing.T) *net.UnixConn {
	t.Helper()
	dir, err := os.MkdirTemp("", "tetrapeer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	lis, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		c, err := lis.Accept()
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestPeerCredFunc_Real exercises the real (non-stubbed) default
// peerCredFunc implementation (SO_PEERCRED via raw.Control +
// unix.GetsockoptUcred) against a real unix socket pair. SO_PEERCRED
// requires no special privilege to query on a connection this process
// itself owns, so this covers the real syscall path without root: the
// peer here is this same test process, so uid/pid must match
// os.Getuid()/os.Getpid() exactly.
func TestPeerCredFunc_Real(t *testing.T) {
	conn := realUnixConnPair(t)
	uid, pid, err := peerCredFunc(conn)
	if err != nil {
		t.Fatalf("peerCredFunc: %v", err)
	}
	if uid != uint32(os.Getuid()) {
		t.Errorf("uid = %d, want %d", uid, os.Getuid())
	}
	if pid != int32(os.Getpid()) {
		t.Errorf("pid = %d, want %d", pid, os.Getpid())
	}
}

// TestPeerExeFunc_Real exercises the real (non-stubbed) default
// peerExeFunc implementation (os.Readlink of /proc/<pid>/exe) against this
// test process's own pid, which it can always resolve regardless of
// privilege.
func TestPeerExeFunc_Real(t *testing.T) {
	exe, err := peerExeFunc(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("peerExeFunc: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe != self {
		t.Errorf("peerExeFunc(self) = %q, want %q", exe, self)
	}
}

// TestPeerCredFunc_ClosedConn covers peerCredFunc's error return when the
// underlying connection is already closed.
func TestPeerCredFunc_ClosedConn(t *testing.T) {
	conn := realUnixConnPair(t)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := peerCredFunc(conn); err == nil {
		t.Fatal("peerCredFunc on a closed connection returned no error")
	}
}

// TestConnectAndVerifyPeer covers Dial's post-lstat connect logic
// (connectAndVerifyPeer) directly against a real socket this non-root
// test process owns, with peerCredFunc/peerExeFunc stubbed to simulate a
// uid-0 peer — exercising the real net.Dialer.DialContext call, the
// *net.UnixConn type assertion, and the success return path, none of
// which any other test reaches (Dial's own dialer closure can never get
// past verifySocketFile's real owner-uid-0 check without root).
func TestConnectAndVerifyPeer(t *testing.T) {
	restoreCred, restoreExe := peerCredFunc, peerExeFunc
	defer func() { peerCredFunc, peerExeFunc = restoreCred, restoreExe }()

	dir, err := os.MkdirTemp("", "tetraconnect")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "s")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return // listener closed (test cleanup): exit cleanly
			}
			_ = c // keep the accepted side open for the connecting client's lifetime; GC/process exit reclaims it at test end
		}
	}()

	t.Run("success", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		peerExeFunc = func(int32) (string, error) { return "/usr/sbin/tetragon", nil }
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := connectAndVerifyPeer(ctx, sock, "/usr/sbin/tetragon")
		if err != nil {
			t.Fatalf("connectAndVerifyPeer: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("peer_verification_fails", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 1000, 42, nil }
		peerExeFunc = func(int32) (string, error) { return "/usr/sbin/tetragon", nil }
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := connectAndVerifyPeer(ctx, sock, "/usr/sbin/tetragon"); err == nil {
			t.Fatal("connectAndVerifyPeer accepted a non-root peer")
		}
	})

	t.Run("dial_fails_nonexistent_socket", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := connectAndVerifyPeer(ctx, filepath.Join(dir, "nope"), "/usr/sbin/tetragon"); err == nil {
			t.Fatal("connectAndVerifyPeer accepted a nonexistent socket")
		}
	})
}

func TestVerifyPeerCredAndExe(t *testing.T) {
	restoreCred, restoreExe := peerCredFunc, peerExeFunc
	defer func() { peerCredFunc, peerExeFunc = restoreCred, restoreExe }()

	conn := realUnixConnPair(t)

	t.Run("wrong_uid", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 1000, 42, nil }
		peerExeFunc = func(int32) (string, error) { return "/usr/sbin/tetragon", nil }
		if err := verifyPeerCredAndExe(conn, "/usr/sbin/tetragon"); err == nil {
			t.Fatal("non-root peer uid accepted")
		}
	})

	t.Run("wrong_exe", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		peerExeFunc = func(int32) (string, error) { return "/tmp/evil/tetragon", nil }
		if err := verifyPeerCredAndExe(conn, "/usr/sbin/tetragon"); err == nil {
			t.Fatal("mismatched peer exe path accepted")
		}
	})

	t.Run("correct", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		peerExeFunc = func(int32) (string, error) { return "/usr/sbin/tetragon", nil }
		if err := verifyPeerCredAndExe(conn, "/usr/sbin/tetragon"); err != nil {
			t.Fatalf("correct peer rejected: %v", err)
		}
	})

	t.Run("peercred_error", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 0, os.ErrPermission }
		if err := verifyPeerCredAndExe(conn, "/usr/sbin/tetragon"); err == nil {
			t.Fatal("SO_PEERCRED error was not propagated")
		}
	})
}

func TestDial_RealSocketEndToEnd(t *testing.T) {
	// Exercises Dial itself (not just its sub-checks) against a fake gRPC
	// server listening on a real unix socket this test owns and chmods,
	// confirming the whole pre-dial + post-connect pipeline wires
	// together. It stubs out getxattr/peercred/exe (this test process is
	// not root and cannot own the socket as uid 0, and evaluateSocketStat
	// itself is already covered in isolation above) but exercises a real
	// lstat and a real unix socket connection end to end.
	restoreXattr, restoreCred, restoreExe := getxattrFunc, peerCredFunc, peerExeFunc
	defer func() { getxattrFunc, peerCredFunc, peerExeFunc = restoreXattr, restoreCred, restoreExe }()
	getxattrFunc = func(string, string, []byte) (int, error) { return 0, unix.ENODATA }
	peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
	peerExeFunc = func(int32) (string, error) { return "/usr/sbin/tetragon", nil }

	dir, err := os.MkdirTemp("", "tetradial")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "s")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		_ = lis.Close()
		t.Fatal(err)
	}

	grpcSrv := grpc.NewServer()
	tetragonpb.RegisterFineGuidanceSensorsServer(grpcSrv, newFakeServer())
	go grpcSrv.Serve(lis) //nolint:errcheck // Stop() below always produces a "use of closed network connection" from Serve's goroutine
	defer grpcSrv.Stop()

	me, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	g, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Skipf("LookupGroupId: %v", err)
	}
	if err := os.Chown(sock, 0, -1); err != nil {
		t.Skipf("cannot chown socket to uid 0 (not running as root): %v", err)
	}

	cfg := Config{
		SocketPath:         sock,
		TetragonBinaryPath: "/usr/sbin/tetragon",
		RelayGroupName:     g.Name,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	if _, err := c.GetVersion(ctx); err != nil {
		t.Fatalf("GetVersion over Dial'd connection: %v", err)
	}
}
