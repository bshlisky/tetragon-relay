package hostprobe

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomic_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host-facts.json")
	f := validFacts("boot-a")

	uid, gid := os.Getuid(), os.Getgid()
	if err := WriteAtomic(path, f, uid, gid); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 0640", fi.Mode().Perm())
	}

	got, err := Parse(mustRead(t, path))
	if err != nil {
		t.Fatalf("Parse written file: %v", err)
	}
	if got.BootID != f.BootID || got.KernelRelease != f.KernelRelease {
		t.Fatalf("round-tripped facts = %+v, want matching %+v", got, f)
	}

	// No leftover temp files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory has %d entries after WriteAtomic, want exactly 1 (no leftover temp file): %v", len(entries), entries)
	}
}

func TestWriteAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host-facts.json")
	uid, gid := os.Getuid(), os.Getgid()

	if err := WriteAtomic(path, validFacts("boot-a"), uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, validFacts("boot-b"), uid, gid); err != nil {
		t.Fatal(err)
	}
	got, err := Parse(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if got.BootID != "boot-b" {
		t.Fatalf("BootID = %q, want boot-b (second write should win)", got.BootID)
	}
}

func TestWriteAtomic_BadDirectory(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	err := WriteAtomic("/this/dir/does/not/exist/host-facts.json", validFacts("boot-a"), uid, gid)
	if err == nil {
		t.Fatal("WriteAtomic into a nonexistent directory returned no error")
	}
}

func TestWriteAtomic_ChownFailureWhenNotRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chown(..., 0, ...) would succeed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "host-facts.json")
	err := WriteAtomic(path, validFacts("boot-a"), 0, os.Getgid())
	if err == nil {
		t.Fatal("WriteAtomic chowning to uid 0 as a non-root user returned no error")
	}
	// No leftover temp file after the chown failure's cleanup.
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Fatalf("directory has %d leftover entries after a failed WriteAtomic: %v", len(entries), entries)
	}
}

func TestWriteAtomic_InjectedFailures(t *testing.T) {
	injectErr := errors.New("injected failure")
	cases := []struct {
		name   string
		inject func()
	}{
		{"chmod", func() { chmodFunc = func(*os.File, os.FileMode) error { return injectErr } }},
		{"chown", func() { chownFunc = func(*os.File, int, int) error { return injectErr } }},
		{"sync", func() { syncFunc = func(*os.File) error { return injectErr } }},
	}
	restoreChmod, restoreChown, restoreSync := chmodFunc, chownFunc, syncFunc
	defer func() { chmodFunc, chownFunc, syncFunc = restoreChmod, restoreChown, restoreSync }()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chmodFunc, chownFunc, syncFunc = restoreChmod, restoreChown, restoreSync
			tc.inject()

			dir := t.TempDir()
			path := filepath.Join(dir, "host-facts.json")
			err := WriteAtomic(path, validFacts("boot-a"), os.Getuid(), os.Getgid())
			if !errors.Is(err, injectErr) {
				t.Fatalf("WriteAtomic error = %v, want wrapping the injected failure", err)
			}
			entries, rerr := os.ReadDir(dir)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if len(entries) != 0 {
				t.Fatalf("directory has %d leftover entries after a failed WriteAtomic: %v", len(entries), entries)
			}
		})
	}
}

func TestFsyncDir_MissingDirectory(t *testing.T) {
	if err := fsyncDir("/this/dir/does/not/exist"); err == nil {
		t.Fatal("fsyncDir on a nonexistent directory returned no error")
	}
}

func TestWriteAtomic_RenameFailsOntoExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host-facts.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	err := WriteAtomic(path, validFacts("boot-a"), uid, gid)
	if err == nil {
		t.Fatal("WriteAtomic renaming onto an existing directory returned no error")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
