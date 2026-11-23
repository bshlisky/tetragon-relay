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
