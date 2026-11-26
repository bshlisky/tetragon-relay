//go:build linux

package hostprobe

import (
	"os"
	"path/filepath"
	"testing"
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
