//go:build linux

package tetra

import (
	"context"
	"errors"
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
		SocketPath:     filepath.Join(t.TempDir(), "does-not-exist"),
		RelayGroupName: currentGroupName(t),
		Timeout:        2 * time.Second,
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
		SocketPath:     sock,
		RelayGroupName: currentGroupName(t),
		Timeout:        2 * time.Second,
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

// TestGetsockoptPeerSecFunc_Real exercises the real (non-stubbed) default
// getsockoptPeerSecFunc implementation (SO_PEERSEC via raw.Control +
// unix.GetsockoptString) against a real unix socket pair this test
// process owns on both ends. The outcome is host-dependent: a host with
// no LSM providing SO_PEERSEC returns ENOPROTOOPT
// (isPeerSELinuxUnavailableErr); GitHub-hosted ubuntu-24.04 runners
// default to AppArmor, which implements SO_PEERSEC too and succeeds with
// its own bare label (e.g. "unconfined") instead — verifyPeerSELinux
// handles that case separately (TestVerifyPeerSELinux's
// apparmor_bare_label_* subtests), so this only exercises the real
// syscall path itself, not any particular outcome.
func TestGetsockoptPeerSecFunc_Real(t *testing.T) {
	conn := realUnixConnPair(t)
	if _, err := getsockoptPeerSecFunc(conn); err != nil && !isPeerSELinuxUnavailableErr(err) {
		t.Fatalf("getsockoptPeerSecFunc returned an unexpected error: %v", err)
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

// stubPeerChecks overrides getsockoptPeerSecFunc and verifyPeerCgroupFunc
// for the duration of the calling test, returning a restore func.
func stubPeerChecks(t *testing.T, sec string, secErr error, cgroup cgroupCheckResult, cgroupErr error) {
	t.Helper()
	restoreSec, restoreCgroup := getsockoptPeerSecFunc, verifyPeerCgroupFunc
	t.Cleanup(func() { getsockoptPeerSecFunc, verifyPeerCgroupFunc = restoreSec, restoreCgroup })
	getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return sec, secErr }
	verifyPeerCgroupFunc = func(Config, int32) (cgroupCheckResult, error) { return cgroup, cgroupErr }
}

// TestConnectAndVerifyPeer covers Dial's post-lstat connect logic
// (connectAndVerifyPeer) directly against a real socket this non-root
// test process owns, with peerCredFunc/getsockoptPeerSecFunc/
// verifyPeerCgroupFunc stubbed to simulate a uid-0 peer that passes the
// cgroup check — exercising the real net.Dialer.DialContext call, the
// *net.UnixConn type assertion, and the success return path, none of
// which any other test reaches (Dial's own dialer closure can never get
// past verifySocketFile's real owner-uid-0 check without root).
func TestConnectAndVerifyPeer(t *testing.T) {
	restoreCred := peerCredFunc
	defer func() { peerCredFunc = restoreCred }()

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

	cfg := Config{SocketPath: sock}

	t.Run("success", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		stubPeerChecks(t, "", unix.ENOPROTOOPT, cgroupCheckResult{Available: true, Passed: true}, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := connectAndVerifyPeer(ctx, cfg)
		if err != nil {
			t.Fatalf("connectAndVerifyPeer: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("peer_verification_fails", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 1000, 42, nil }
		stubPeerChecks(t, "", unix.ENOPROTOOPT, cgroupCheckResult{Available: true, Passed: true}, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := connectAndVerifyPeer(ctx, cfg); err == nil {
			t.Fatal("connectAndVerifyPeer accepted a non-root peer")
		}
	})

	t.Run("dial_fails_nonexistent_socket", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := connectAndVerifyPeer(ctx, Config{SocketPath: filepath.Join(dir, "nope")}); err == nil {
			t.Fatal("connectAndVerifyPeer accepted a nonexistent socket")
		}
	})
}

func TestIsPeerSELinuxUnavailableErr(t *testing.T) {
	if !isPeerSELinuxUnavailableErr(unix.ENOPROTOOPT) {
		t.Error("ENOPROTOOPT not treated as SELinux-unavailable")
	}
	if !isPeerSELinuxUnavailableErr(unix.EOPNOTSUPP) {
		t.Error("EOPNOTSUPP not treated as SELinux-unavailable")
	}
	if isPeerSELinuxUnavailableErr(unix.EACCES) {
		t.Error("an unrelated errno was treated as SELinux-unavailable")
	}
}

func TestVerifyPeerSELinux(t *testing.T) {
	conn := realUnixConnPair(t)
	restore := getsockoptPeerSecFunc
	defer func() { getsockoptPeerSecFunc = restore }()

	t.Run("correct_type", func(t *testing.T) {
		getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return "system_u:system_r:tetragon_t:s0", nil }
		active, err := verifyPeerSELinux(Config{}, conn)
		if err != nil || !active {
			t.Fatalf("active=%v err=%v, want true/nil", active, err)
		}
	})

	t.Run("wrong_type", func(t *testing.T) {
		getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return "system_u:system_r:unconfined_t:s0", nil }
		if _, err := verifyPeerSELinux(Config{}, conn); err == nil {
			t.Fatal("wrong peer SELinux type accepted")
		}
	})

	t.Run("custom_configured_type", func(t *testing.T) {
		getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return "system_u:system_r:custom_t:s0", nil }
		active, err := verifyPeerSELinux(Config{PeerSELinuxType: "custom_t"}, conn)
		if err != nil || !active {
			t.Fatalf("active=%v err=%v, want true/nil", active, err)
		}
	})

	t.Run("disabled_selinux_required_false", func(t *testing.T) {
		getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return "", unix.ENOPROTOOPT }
		active, err := verifyPeerSELinux(Config{SELinuxRequired: false}, conn)
		if err != nil || active {
			t.Fatalf("active=%v err=%v, want false/nil", active, err)
		}
	})

	// AppArmor (the default LSM on GitHub-hosted ubuntu-24.04 runners)
	// implements SO_PEERSEC too, returning its own bare label (no
	// colons) instead of failing with ENOPROTOOPT — this must be treated
	// like disabled SELinux, not a type mismatch.
	t.Run("apparmor_bare_label_treated_as_disabled", func(t *testing.T) {
		getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return "unconfined", nil }
		active, err := verifyPeerSELinux(Config{SELinuxRequired: false}, conn)
		if err != nil || active {
			t.Fatalf("active=%v err=%v, want false/nil", active, err)
		}
	})

	t.Run("apparmor_bare_label_required_true_fails_closed", func(t *testing.T) {
		getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return "unconfined", nil }
		if _, err := verifyPeerSELinux(Config{SELinuxRequired: true}, conn); err == nil {
			t.Fatal("an unparseable (non-SELinux) label with selinux_required=true was accepted")
		}
	})

	t.Run("disabled_selinux_required_true", func(t *testing.T) {
		getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return "", unix.ENOPROTOOPT }
		if _, err := verifyPeerSELinux(Config{SELinuxRequired: true}, conn); err == nil {
			t.Fatal("disabled SELinux with selinux_required=true accepted")
		}
	})

	t.Run("other_getsockopt_error", func(t *testing.T) {
		getsockoptPeerSecFunc = func(*net.UnixConn) (string, error) { return "", unix.EACCES }
		if _, err := verifyPeerSELinux(Config{}, conn); err == nil {
			t.Fatal("an unrelated SO_PEERSEC error was treated as disabled SELinux")
		}
	})
}

func TestVerifyPeerCredAndTetragon(t *testing.T) {
	restoreCred := peerCredFunc
	defer func() { peerCredFunc = restoreCred }()
	conn := realUnixConnPair(t)

	t.Run("wrong_uid", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 1000, 42, nil }
		stubPeerChecks(t, "", unix.ENOPROTOOPT, cgroupCheckResult{Available: true, Passed: true}, nil)
		if err := verifyPeerCredAndTetragon(Config{}, conn); err == nil {
			t.Fatal("non-root peer uid accepted")
		}
	})

	t.Run("peercred_error", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 0, os.ErrPermission }
		if err := verifyPeerCredAndTetragon(Config{}, conn); err == nil {
			t.Fatal("SO_PEERCRED error was not propagated")
		}
	})

	t.Run("selinux_fails_short_circuits_cgroup", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		stubPeerChecks(t, "system_u:system_r:unconfined_t:s0", nil, cgroupCheckResult{Available: true, Passed: true}, nil)
		if err := verifyPeerCredAndTetragon(Config{}, conn); err == nil {
			t.Fatal("wrong peer SELinux type accepted")
		}
	})

	t.Run("cgroup_available_and_passes", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		stubPeerChecks(t, "", unix.ENOPROTOOPT, cgroupCheckResult{Available: true, Passed: true}, nil)
		if err := verifyPeerCredAndTetragon(Config{}, conn); err != nil {
			t.Fatalf("correct peer rejected: %v", err)
		}
	})

	t.Run("cgroup_available_and_fails", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		stubPeerChecks(t, "", unix.ENOPROTOOPT, cgroupCheckResult{Available: true, Passed: false}, nil)
		if err := verifyPeerCredAndTetragon(Config{}, conn); err == nil {
			t.Fatal("peer not in the expected cgroup was accepted")
		}
	})

	t.Run("cgroup_check_error", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		stubPeerChecks(t, "", unix.ENOPROTOOPT, cgroupCheckResult{}, errors.New("statfs failed"))
		if err := verifyPeerCredAndTetragon(Config{}, conn); err == nil {
			t.Fatal("a cgroup check error was not propagated")
		}
	})

	t.Run("cgroup_unavailable_selinux_active_passes", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		stubPeerChecks(t, "system_u:system_r:tetragon_t:s0", nil, cgroupCheckResult{Available: false}, nil)
		if err := verifyPeerCredAndTetragon(Config{}, conn); err != nil {
			t.Fatalf("cgroup-v1 host with a passing SELinux check rejected: %v", err)
		}
	})

	t.Run("cgroup_unavailable_selinux_inactive_fails_closed", func(t *testing.T) {
		peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
		stubPeerChecks(t, "", unix.ENOPROTOOPT, cgroupCheckResult{Available: false}, nil)
		if err := verifyPeerCredAndTetragon(Config{}, conn); err == nil {
			t.Fatal("a peer with neither cgroup nor SELinux verification available was accepted")
		}
	})
}

func TestDial_RealSocketEndToEnd(t *testing.T) {
	// Exercises Dial itself (not just its sub-checks) against a fake gRPC
	// server listening on a real unix socket this test owns and chmods,
	// confirming the whole pre-dial + post-connect pipeline wires
	// together. It stubs out getxattr/peercred/SO_PEERSEC/cgroup (this
	// test process is not root and cannot own the socket as uid 0, and
	// evaluateSocketStat itself is already covered in isolation above)
	// but exercises a real lstat and a real unix socket connection end to
	// end.
	restoreXattr, restoreCred := getxattrFunc, peerCredFunc
	defer func() { getxattrFunc, peerCredFunc = restoreXattr, restoreCred }()
	getxattrFunc = func(string, string, []byte) (int, error) { return 0, unix.ENODATA }
	peerCredFunc = func(*net.UnixConn) (uint32, int32, error) { return 0, 42, nil }
	stubPeerChecks(t, "", unix.ENOPROTOOPT, cgroupCheckResult{Available: true, Passed: true}, nil)

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
		SocketPath:     sock,
		RelayGroupName: g.Name,
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
