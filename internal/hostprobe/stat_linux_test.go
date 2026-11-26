//go:build linux

package hostprobe

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPlatformStatOpenFile_Linux exercises the real fstat/fstatfs path:
// /dev/shm is tmpfs on every systemd Linux host (and GitHub's runners);
// t.TempDir() on the runner is not. Ownership is the test user's, so only
// type, mode and filesystem are asserted here; the uid rule is covered by
// TestLoad_FailsClosed.
func TestPlatformStatOpenFile_Linux(t *testing.T) {
	check := func(t *testing.T, dir string, wantTmpfs bool) {
		t.Helper()
		p := filepath.Join(dir, "host-facts-stat-test.json")
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Skipf("cannot write in %s: %v", dir, err)
		}
		t.Cleanup(func() { _ = os.Remove(p) })
		if err := os.Chmod(p, 0o640); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p) //nolint:gosec // test-created path
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		info, err := platformStatOpenFile(f)
		if err != nil {
			t.Fatalf("platformStatOpenFile: %v", err)
		}
		if !info.regular || info.perm != HostFactsMode || info.uid != uint32(os.Getuid()) { //nolint:gosec // G115: uid fits
			t.Fatalf("info = %+v", info)
		}
		if info.onTmpfs != wantTmpfs {
			t.Fatalf("onTmpfs = %v for %s, want %v", info.onTmpfs, dir, wantTmpfs)
		}
	}
	t.Run("dev_shm_is_tmpfs", func(t *testing.T) {
		if _, err := os.Stat("/dev/shm"); err != nil {
			t.Skip("/dev/shm not present")
		}
		check(t, "/dev/shm", true)
	})
}

func TestPlatformStatOpenFile_ClosedDescriptor(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := platformStatOpenFile(f); !errors.Is(err, ErrHostFactsUnreadable) {
		t.Fatalf("platformStatOpenFile(closed) = %v, want ErrHostFactsUnreadable", err)
	}
}

func TestPlatformStatOpenFile_NotTmpfsOrNotRegular(t *testing.T) {
	// /proc is procfs and a directory: neither regular nor tmpfs.
	f, err := os.Open("/proc")
	if err != nil {
		t.Skipf("/proc: %v", err)
	}
	defer func() { _ = f.Close() }()
	info, err := platformStatOpenFile(f)
	if err != nil {
		t.Fatalf("platformStatOpenFile(/proc): %v", err)
	}
	if info.regular || info.onTmpfs {
		t.Fatalf("info = %+v, want regular=false onTmpfs=false", info)
	}
}

func TestSpecialBits(t *testing.T) {
	cases := []struct {
		mode uint32
		want os.FileMode
	}{
		{0, 0},
		{unix.S_ISUID, os.ModeSetuid},
		{unix.S_ISGID, os.ModeSetgid},
		{unix.S_ISVTX, os.ModeSticky},
		{unix.S_ISUID | unix.S_ISGID | unix.S_ISVTX, os.ModeSetuid | os.ModeSetgid | os.ModeSticky},
	}
	for _, tc := range cases {
		if got := specialBits(tc.mode); got != tc.want {
			t.Errorf("specialBits(%#o) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}
