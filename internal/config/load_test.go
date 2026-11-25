package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// errGroupNotFoundForTest stands in for the error os/user.LookupGroup
// returns when the group does not exist, for TestCheckOpenedConfigFile_GroupLookupFailed.
var errGroupNotFoundForTest = errors.New("group: unknown group tetragon-relay (test fixture)")

// withGroupLookup overrides lookupGroupGID for the duration of a test, so
// tests do not depend on the real "tetragon-relay" system group existing
// on the machine running `go test` (see load.go's doc comment on
// lookupGroupGID).
func withGroupLookup(t *testing.T, gid uint32, err error) {
	t.Helper()
	orig := lookupGroupGID
	lookupGroupGID = func(name string) (uint32, error) {
		if name != relayGroupName {
			t.Fatalf("lookupGroupGID called with %q, want %q", name, relayGroupName)
		}
		return gid, err
	}
	t.Cleanup(func() { lookupGroupGID = orig })
}

// writeOwnedFile writes contents to a fresh file under dir (or a fresh
// t.TempDir() if dir is "") with the given mode, owned by the current
// process (the only uid/gid a non-root test process can actually create a
// file as).
func writeOwnedFile(t *testing.T, dir, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return path
}

// openConfigFileForTest calls openConfigFile and closes the returned file
// (if any) via t.Cleanup, since every test here only cares about the
// returned error.
func openConfigFileForTest(t *testing.T, path string) error {
	t.Helper()
	f, err := openConfigFile(path)
	if f != nil {
		t.Cleanup(func() { _ = f.Close() })
	}
	return err
}

func TestOpenConfigFile_NotFound(t *testing.T) {
	err := openConfigFileForTest(t, filepath.Join(t.TempDir(), "missing.yaml"))
	if !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("error = %v, want ErrConfigNotFound", err)
	}
}

func TestOpenConfigFile_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte("x: 1\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "relay.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// O_NOFOLLOW refuses to open a symlink at all: this exercises
	// step-06a-review B6, not a path-based Lstat.
	if err := openConfigFileForTest(t, link); !errors.Is(err, ErrConfigIsSymlink) {
		t.Fatalf("error = %v, want ErrConfigIsSymlink", err)
	}
}

func TestOpenConfigFile_NotRegularFile(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := openConfigFileForTest(t, sub); !errors.Is(err, ErrConfigNotRegularFile) {
		t.Fatalf("error = %v, want ErrConfigNotRegularFile", err)
	}
}

func TestOpenConfigFile_ModeTooPermissive(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: the owner check would mask the mode check this test isolates")
	}
	path := writeOwnedFile(t, "", "relay.yaml", []byte("x: 1\n"), 0o644) // "others read" bit exceeds 0640
	withGroupLookup(t, uint32(os.Getgid()), nil)
	if err := openConfigFileForTest(t, path); !errors.Is(err, ErrConfigModeTooPermissive) {
		t.Fatalf("error = %v, want ErrConfigModeTooPermissive", err)
	}
}

func TestOpenConfigFile_ExactlyMaxModeAccepted(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner-must-be-root check cannot be exercised as a non-root refusal when already root")
	}
	path := writeOwnedFile(t, "", "relay.yaml", []byte("x: 1\n"), 0o640)
	withGroupLookup(t, uint32(os.Getgid()), nil)
	// The process is not root, so this must fail on ownership, not mode:
	// proves 0640 itself is accepted by the mode check.
	if err := openConfigFileForTest(t, path); !errors.Is(err, ErrConfigNotOwnedByRoot) {
		t.Fatalf("error = %v, want ErrConfigNotOwnedByRoot (mode 0640 should pass the mode check)", err)
	}
}

func TestOpenConfigFile_MorePermissiveThanMaxRejectedEvenIfOwnerWouldPass(t *testing.T) {
	path := writeOwnedFile(t, "", "relay.yaml", []byte("x: 1\n"), 0o660)
	withGroupLookup(t, uint32(os.Getgid()), nil)
	if err := openConfigFileForTest(t, path); !errors.Is(err, ErrConfigModeTooPermissive) {
		t.Fatalf("error = %v, want ErrConfigModeTooPermissive", err)
	}
}

func TestOpenConfigFile_NotOwnedByRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test process is root; cannot exercise the non-root-owner refusal")
	}
	path := writeOwnedFile(t, "", "relay.yaml", []byte("x: 1\n"), 0o640)
	withGroupLookup(t, uint32(os.Getgid()), nil)
	if err := openConfigFileForTest(t, path); !errors.Is(err, ErrConfigNotOwnedByRoot) {
		t.Fatalf("error = %v, want ErrConfigNotOwnedByRoot", err)
	}
}

func TestOpenConfigFile_GroupLookupFailed(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("exercising the group-lookup-failure branch past the owner check requires running as root")
	}
	path := writeOwnedFile(t, "", "relay.yaml", []byte("x: 1\n"), 0o640)
	withGroupLookup(t, 0, errGroupNotFoundForTest)
	if err := openConfigFileForTest(t, path); !errors.Is(err, ErrConfigGroupLookupFailed) {
		t.Fatalf("error = %v, want ErrConfigGroupLookupFailed", err)
	}
}

func TestOpenConfigFile_WrongGroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("exercising the group-mismatch branch past the owner check requires running as root")
	}
	path := writeOwnedFile(t, "", "relay.yaml", []byte("x: 1\n"), 0o640)
	withGroupLookup(t, uint32(os.Getgid())+12345, nil) // deliberately wrong gid
	if err := openConfigFileForTest(t, path); !errors.Is(err, ErrConfigWrongGroup) {
		t.Fatalf("error = %v, want ErrConfigWrongGroup", err)
	}
}

// --- B7: parent directory checks ---

func TestCheckParentDir_NotFound(t *testing.T) {
	err := checkParentDir(filepath.Join(t.TempDir(), "doesnotexist", "relay.yaml"))
	if !errors.Is(err, ErrConfigParentDirNotFound) {
		t.Fatalf("error = %v, want ErrConfigParentDirNotFound", err)
	}
}

func TestCheckParentDir_Symlink(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	linkDir := filepath.Join(base, "etc-tetragon-relay")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	err := checkParentDir(filepath.Join(linkDir, "relay.yaml"))
	if !errors.Is(err, ErrConfigParentDirIsSymlink) {
		t.Fatalf("error = %v, want ErrConfigParentDirIsSymlink", err)
	}
}

func TestCheckParentDir_WritableByGroup(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := checkParentDir(filepath.Join(dir, "relay.yaml")); !errors.Is(err, ErrConfigParentDirWritable) {
		t.Fatalf("error = %v, want ErrConfigParentDirWritable", err)
	}
}

func TestCheckParentDir_WritableByOther(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o707); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := checkParentDir(filepath.Join(dir, "relay.yaml")); !errors.Is(err, ErrConfigParentDirWritable) {
		t.Fatalf("error = %v, want ErrConfigParentDirWritable", err)
	}
}

func TestCheckParentDir_NotOwnedByRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test process is root; cannot exercise the non-root-owner refusal")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := checkParentDir(filepath.Join(dir, "relay.yaml")); !errors.Is(err, ErrConfigParentDirNotOwnedByRoot) {
		t.Fatalf("error = %v, want ErrConfigParentDirNotOwnedByRoot", err)
	}
}

func TestCheckParentDir_SecureDirAccepted(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a non-root test process cannot create a root-owned directory to exercise the accept path")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := checkParentDir(filepath.Join(dir, "relay.yaml")); err != nil {
		t.Fatalf("checkParentDir on a root-owned, non-group/other-writable directory: %v", err)
	}
}

// --- reading ---

func TestReadOpenedConfigFile_TooLarge(t *testing.T) {
	big := make([]byte, 0)
	for len(big) <= 1<<20 {
		big = append(big, "x: 1\n"...)
	}
	path := writeOwnedFile(t, "", "relay.yaml", big, 0o640)
	f, err := os.Open(path) //nolint:gosec // G304: test-controlled temp path
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := readOpenedConfigFile(f, path); !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("error = %v, want ErrConfigTooLarge", err)
	}
}

func TestReadOpenedConfigFile_WithinLimitAccepted(t *testing.T) {
	path := writeOwnedFile(t, "", "relay.yaml", []byte(validYAML), 0o640)
	f, err := os.Open(path) //nolint:gosec // G304: test-controlled temp path
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := readOpenedConfigFile(f, path)
	if err != nil {
		t.Fatalf("readOpenedConfigFile: %v", err)
	}
	if string(raw) != validYAML {
		t.Fatalf("read bytes do not match what was written")
	}
}

func TestLoad_EndToEnd_NonRootProcessFailsOnOwnership(t *testing.T) {
	// Load() cannot be driven all the way to success in a non-root,
	// non-"tetragon-relay"-group test environment (B1/B6/B7's checks
	// are the point), but this confirms Load composes openConfigFile,
	// checkParentDir, readOpenedConfigFile and parse in order: a file
	// that would otherwise parse successfully is still refused on
	// ownership first.
	if os.Getuid() == 0 {
		t.Skip("test process is root")
	}
	path := writeOwnedFile(t, "", "relay.yaml", []byte(validYAML), 0o640)
	if _, err := Load(path); !errors.Is(err, ErrConfigNotOwnedByRoot) {
		t.Fatalf("error = %v, want ErrConfigNotOwnedByRoot", err)
	}
}
