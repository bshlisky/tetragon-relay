//go:build linux

package tetra

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsCgroupV2(t *testing.T) {
	restore := statfsFunc
	defer func() { statfsFunc = restore }()

	t.Run("v2", func(t *testing.T) {
		statfsFunc = func(_ string, st *unix.Statfs_t) error {
			st.Type = unix.CGROUP2_SUPER_MAGIC
			return nil
		}
		v2, err := isCgroupV2()
		if err != nil || !v2 {
			t.Fatalf("v2=%v err=%v, want true/nil", v2, err)
		}
	})

	t.Run("v1_or_hybrid", func(t *testing.T) {
		statfsFunc = func(_ string, st *unix.Statfs_t) error {
			st.Type = 0x9fa0 // PROC_SUPER_MAGIC-ish placeholder, just "not cgroup2"
			return nil
		}
		v2, err := isCgroupV2()
		if err != nil || v2 {
			t.Fatalf("v2=%v err=%v, want false/nil", v2, err)
		}
	})

	t.Run("statfs_error", func(t *testing.T) {
		injectErr := errors.New("injected statfs error")
		statfsFunc = func(string, *unix.Statfs_t) error { return injectErr }
		if _, err := isCgroupV2(); !errors.Is(err, injectErr) {
			t.Fatalf("isCgroupV2 error = %v, want wrapping the injected error", err)
		}
	})
}

// TestIsCgroupV2_Real exercises the real (non-stubbed) statfsFunc against
// this host's actual /sys/fs/cgroup, whatever it is: every GitHub-hosted
// ubuntu-24.04 runner (and every modern RHEL 9 host) mounts cgroup v2, so
// this is expected to report true, but the assertion only requires no
// error — the point is covering the real syscall path, not asserting a
// specific host layout.
func TestIsCgroupV2_Real(t *testing.T) {
	if _, err := isCgroupV2(); err != nil {
		t.Fatalf("isCgroupV2 on the real host: %v", err)
	}
}

func TestReadCgroupProcsFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid", func(t *testing.T) {
		p := filepath.Join(dir, "cgroup.procs")
		if err := os.WriteFile(p, []byte("1\n42\n\n100\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		pids, err := readCgroupProcsFile(p)
		if err != nil {
			t.Fatalf("readCgroupProcsFile: %v", err)
		}
		for _, want := range []int32{1, 42, 100} {
			if !pids[want] {
				t.Errorf("pid %d missing from %v", want, pids)
			}
		}
		if len(pids) != 3 {
			t.Errorf("len(pids) = %d, want 3", len(pids))
		}
	})

	t.Run("empty_file", func(t *testing.T) {
		p := filepath.Join(dir, "empty.procs")
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		pids, err := readCgroupProcsFile(p)
		if err != nil || len(pids) != 0 {
			t.Fatalf("pids=%v err=%v, want empty/nil", pids, err)
		}
	})

	t.Run("malformed_line", func(t *testing.T) {
		p := filepath.Join(dir, "bad.procs")
		if err := os.WriteFile(p, []byte("not-a-pid\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readCgroupProcsFile(p); err == nil {
			t.Fatal("readCgroupProcsFile accepted a malformed line")
		}
	})

	t.Run("nonexistent", func(t *testing.T) {
		if _, err := readCgroupProcsFile(filepath.Join(dir, "nope")); err == nil {
			t.Fatal("readCgroupProcsFile accepted a nonexistent path")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		realFile := filepath.Join(dir, "real.procs")
		if err := os.WriteFile(realFile, []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.procs")
		if err := os.Symlink(realFile, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readCgroupProcsFile(link); err == nil {
			t.Fatal("readCgroupProcsFile accepted a symlink")
		}
	})

	t.Run("bounded_read", func(t *testing.T) {
		p := filepath.Join(dir, "huge.procs")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		// Pad well past maxCgroupProcsBytes with valid "pid\n" lines,
		// then place a sentinel pid right after the padding: if the
		// read were unbounded, the sentinel would show up in the
		// result. A bounded read either errors (truncated mid-token)
		// or succeeds without ever seeing the sentinel; both are
		// correct, so this only asserts the sentinel never appears.
		line := []byte("7\n")
		for n := 0; n+len(line) < maxCgroupProcsBytes+4096; n += len(line) {
			if _, err := f.Write(line); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.WriteString("999999\n"); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		pids, err := readCgroupProcsFile(p)
		if err != nil {
			return
		}
		if pids[999999] {
			t.Fatal("readCgroupProcsFile read past maxCgroupProcsBytes")
		}
	})
}

func TestVerifyPeerCgroup(t *testing.T) {
	restoreStatfs, restoreRead := statfsFunc, readCgroupProcsFunc
	defer func() { statfsFunc, readCgroupProcsFunc = restoreStatfs, restoreRead }()

	t.Run("v2_pid_present", func(t *testing.T) {
		statfsFunc = func(_ string, st *unix.Statfs_t) error { st.Type = unix.CGROUP2_SUPER_MAGIC; return nil }
		readCgroupProcsFunc = func(string) (map[int32]bool, error) { return map[int32]bool{42: true}, nil }
		res, err := verifyPeerCgroup(Config{}, 42)
		if err != nil || !res.Available || !res.Passed {
			t.Fatalf("res=%+v err=%v, want Available=true Passed=true", res, err)
		}
	})

	t.Run("v2_pid_absent", func(t *testing.T) {
		statfsFunc = func(_ string, st *unix.Statfs_t) error { st.Type = unix.CGROUP2_SUPER_MAGIC; return nil }
		readCgroupProcsFunc = func(string) (map[int32]bool, error) { return map[int32]bool{99: true}, nil }
		res, err := verifyPeerCgroup(Config{}, 42)
		if err != nil || !res.Available || res.Passed {
			t.Fatalf("res=%+v err=%v, want Available=true Passed=false", res, err)
		}
	})

	t.Run("v1_unavailable", func(t *testing.T) {
		statfsFunc = func(_ string, st *unix.Statfs_t) error { st.Type = 0x9fa0; return nil }
		res, err := verifyPeerCgroup(Config{}, 42)
		if err != nil || res.Available {
			t.Fatalf("res=%+v err=%v, want Available=false, nil", res, err)
		}
	})

	t.Run("statfs_error", func(t *testing.T) {
		statfsFunc = func(string, *unix.Statfs_t) error { return errors.New("injected") }
		if _, err := verifyPeerCgroup(Config{}, 42); err == nil {
			t.Fatal("verifyPeerCgroup did not propagate a statfs error")
		}
	})

	t.Run("read_error", func(t *testing.T) {
		statfsFunc = func(_ string, st *unix.Statfs_t) error { st.Type = unix.CGROUP2_SUPER_MAGIC; return nil }
		readCgroupProcsFunc = func(string) (map[int32]bool, error) { return nil, errors.New("injected read error") }
		if _, err := verifyPeerCgroup(Config{}, 42); err == nil {
			t.Fatal("verifyPeerCgroup did not propagate a cgroup.procs read error")
		}
	})

	t.Run("custom_unit_cgroup_path", func(t *testing.T) {
		statfsFunc = func(_ string, st *unix.Statfs_t) error { st.Type = unix.CGROUP2_SUPER_MAGIC; return nil }
		var gotPath string
		readCgroupProcsFunc = func(p string) (map[int32]bool, error) {
			gotPath = p
			return map[int32]bool{42: true}, nil
		}
		if _, err := verifyPeerCgroup(Config{UnitCgroupPath: "/custom/path"}, 42); err != nil {
			t.Fatal(err)
		}
		want := cgroupRoot + "/custom/path/cgroup.procs"
		if gotPath != want {
			t.Errorf("readCgroupProcsFunc called with %q, want %q", gotPath, want)
		}
	})
}
