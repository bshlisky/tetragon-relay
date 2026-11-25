package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// errGroupNotFoundForTest stands in for the error os/user.LookupGroup
// returns when the group does not exist, for TestCheckFileSourceable_GroupLookupFailed.
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

// writeOwnedFile writes contents to a fresh file under t.TempDir() with
// the given mode, owned by the current process (the only uid/gid a
// non-root test process can actually create a file as).
func writeOwnedFile(t *testing.T, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return path
}

func TestCheckFileSourceable_NotFound(t *testing.T) {
	if err := checkFileSourceable(filepath.Join(t.TempDir(), "missing.yaml")); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("error = %v, want ErrConfigNotFound", err)
	}
}

func TestCheckFileSourceable_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte("x: 1\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "relay.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := checkFileSourceable(link); !errors.Is(err, ErrConfigIsSymlink) {
		t.Fatalf("error = %v, want ErrConfigIsSymlink", err)
	}
}

func TestCheckFileSourceable_NotRegularFile(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := checkFileSourceable(sub); !errors.Is(err, ErrConfigNotRegularFile) {
		t.Fatalf("error = %v, want ErrConfigNotRegularFile", err)
	}
}

func TestCheckFileSourceable_ModeTooPermissive(t *testing.T) {
	path := writeOwnedFile(t, "relay.yaml", []byte("x: 1\n"), 0o644) // "others read" bit exceeds 0640
	withGroupLookup(t, uint32(os.Getgid()), nil)
	err := checkFileSourceable(path)
	if os.Getuid() == 0 {
		t.Skip("running as root: the owner check below would also need a non-root uid to observe mode independently")
	}
	if !errors.Is(err, ErrConfigModeTooPermissive) {
		t.Fatalf("error = %v, want ErrConfigModeTooPermissive", err)
	}
}

func TestCheckFileSourceable_ExactlyMaxModeAccepted(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner-must-be-root check cannot be exercised as a non-root refusal when already root")
	}
	path := writeOwnedFile(t, "relay.yaml", []byte("x: 1\n"), 0o640)
	withGroupLookup(t, uint32(os.Getgid()), nil)
	err := checkFileSourceable(path)
	// The process is not root, so this must fail on ownership, not mode:
	// proves 0640 itself is accepted by the mode check.
	if !errors.Is(err, ErrConfigNotOwnedByRoot) {
		t.Fatalf("error = %v, want ErrConfigNotOwnedByRoot (mode 0640 should pass the mode check)", err)
	}
}

func TestCheckFileSourceable_MorePermissiveThanMaxRejectedEvenIfOwnerWouldPass(t *testing.T) {
	path := writeOwnedFile(t, "relay.yaml", []byte("x: 1\n"), 0o660)
	withGroupLookup(t, uint32(os.Getgid()), nil)
	if err := checkFileSourceable(path); !errors.Is(err, ErrConfigModeTooPermissive) {
		t.Fatalf("error = %v, want ErrConfigModeTooPermissive", err)
	}
}

func TestCheckFileSourceable_NotOwnedByRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test process is root; cannot exercise the non-root-owner refusal")
	}
	path := writeOwnedFile(t, "relay.yaml", []byte("x: 1\n"), 0o640)
	withGroupLookup(t, uint32(os.Getgid()), nil)
	if err := checkFileSourceable(path); !errors.Is(err, ErrConfigNotOwnedByRoot) {
		t.Fatalf("error = %v, want ErrConfigNotOwnedByRoot", err)
	}
}

func TestCheckFileSourceable_GroupLookupFailed(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("exercising the group-lookup-failure branch past the owner check requires running as root")
	}
	path := writeOwnedFile(t, "relay.yaml", []byte("x: 1\n"), 0o640)
	withGroupLookup(t, 0, errGroupNotFoundForTest)
	if err := checkFileSourceable(path); !errors.Is(err, ErrConfigGroupLookupFailed) {
		t.Fatalf("error = %v, want ErrConfigGroupLookupFailed", err)
	}
}

func TestCheckFileSourceable_WrongGroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("exercising the group-mismatch branch past the owner check requires running as root")
	}
	path := writeOwnedFile(t, "relay.yaml", []byte("x: 1\n"), 0o640)
	withGroupLookup(t, uint32(os.Getgid())+12345, nil) // deliberately wrong gid
	if err := checkFileSourceable(path); !errors.Is(err, ErrConfigWrongGroup) {
		t.Fatalf("error = %v, want ErrConfigWrongGroup", err)
	}
}

func TestReadConfigFile_TooLarge(t *testing.T) {
	big := make([]byte, 0)
	for len(big) <= 1<<20 {
		big = append(big, "x: 1\n"...)
	}
	path := writeOwnedFile(t, "relay.yaml", big, 0o640)
	if _, err := readConfigFile(path); !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("error = %v, want ErrConfigTooLarge", err)
	}
}

func TestReadConfigFile_WithinLimitAccepted(t *testing.T) {
	path := writeOwnedFile(t, "relay.yaml", []byte(validYAML), 0o640)
	raw, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("readConfigFile: %v", err)
	}
	if string(raw) != validYAML {
		t.Fatalf("read bytes do not match what was written")
	}
}

func TestLoad_EndToEnd_NonRootProcessFailsOnOwnership(t *testing.T) {
	// Load() cannot be driven all the way to success in a non-root,
	// non-"tetragon-relay"-group test environment (B1's checks are the
	// point), but this confirms Load composes checkFileSourceable,
	// readConfigFile and parse in order: a file that would otherwise
	// parse successfully is still refused on ownership first.
	if os.Getuid() == 0 {
		t.Skip("test process is root")
	}
	path := writeOwnedFile(t, "relay.yaml", []byte(validYAML), 0o640)
	if _, err := Load(path); !errors.Is(err, ErrConfigNotOwnedByRoot) {
		t.Fatalf("error = %v, want ErrConfigNotOwnedByRoot", err)
	}
}
