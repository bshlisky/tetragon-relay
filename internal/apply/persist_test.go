package apply

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistDir_WriteAndOverwrite(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "relay")
	uid, gid := os.Getuid(), os.Getgid()

	name1, _ := LoadedName("p1", 1, []byte("a"))
	err := PersistDir(dir, []PersistedPolicy{{LoadedName: name1, CanonicalJSON: []byte(`{"a":1}`)}}, uid, gid)
	if err != nil {
		t.Fatalf("PersistDir: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != name1+".json" {
		t.Fatalf("entries = %v, want exactly %s.json", entries, name1)
	}
	data, err := os.ReadFile(filepath.Join(dir, name1+".json"))
	if err != nil || string(data) != `{"a":1}` {
		t.Fatalf("file content = %q, %v", data, err)
	}

	// A second PersistDir call with a different set must fully replace
	// the directory contents (old file gone, new file present).
	name2, _ := LoadedName("p2", 1, []byte("b"))
	if err := PersistDir(dir, []PersistedPolicy{{LoadedName: name2, CanonicalJSON: []byte(`{"b":2}`)}}, uid, gid); err != nil {
		t.Fatalf("second PersistDir: %v", err)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != name2+".json" {
		t.Fatalf("after second PersistDir, entries = %v, want exactly %s.json", entries, name2)
	}

	// No stray ".old"/".new-*" directories left behind.
	siblings, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(siblings) != 1 || siblings[0].Name() != "relay" {
		t.Fatalf("root directory has stray entries: %v", siblings)
	}
}

func TestPersistDir_EmptySet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	if err := PersistDir(dir, nil, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("PersistDir(nil): %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected an empty directory, got %v", entries)
	}
}

func TestPersistDir_InvalidLoadedNameRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	err := PersistDir(dir, []PersistedPolicy{{LoadedName: "../../etc/passwd", CanonicalJSON: []byte("x")}}, os.Getuid(), os.Getgid())
	if err == nil {
		t.Fatal("PersistDir accepted a path-traversal loaded name")
	}
	if _, statErr := os.Stat(dir); statErr == nil {
		t.Fatal("PersistDir left a half-written directory in place after rejecting an invalid name")
	}
}

func TestPersistDir_BadParentDirectory(t *testing.T) {
	// A parent that is itself a regular file, not a directory: MkdirTemp
	// must fail.
	root := t.TempDir()
	notADir := filepath.Join(root, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := PersistDir(filepath.Join(notADir, "relay"), nil, os.Getuid(), os.Getgid())
	if err == nil {
		t.Fatal("PersistDir succeeded with a non-directory parent")
	}
}

func TestPersistDir_InjectedFailures(t *testing.T) {
	injectErr := errors.New("injected")
	restoreChmod, restoreSync := chmodFileFunc, syncFileFunc
	defer func() { chmodFileFunc, syncFileFunc = restoreChmod, restoreSync }()

	name, _ := LoadedName("p", 1, []byte("x"))
	policies := []PersistedPolicy{{LoadedName: name, CanonicalJSON: []byte("{}")}}

	t.Run("chmod", func(t *testing.T) {
		chmodFileFunc, syncFileFunc = restoreChmod, restoreSync
		chmodFileFunc = func(*os.File, os.FileMode) error { return injectErr }
		dir := filepath.Join(t.TempDir(), "relay")
		if err := PersistDir(dir, policies, os.Getuid(), os.Getgid()); !errors.Is(err, injectErr) {
			t.Fatalf("PersistDir error = %v, want wrapping the injected chmod failure", err)
		}
	})
	t.Run("sync", func(t *testing.T) {
		chmodFileFunc, syncFileFunc = restoreChmod, restoreSync
		syncFileFunc = func(*os.File) error { return injectErr }
		dir := filepath.Join(t.TempDir(), "relay")
		if err := PersistDir(dir, policies, os.Getuid(), os.Getgid()); !errors.Is(err, injectErr) {
			t.Fatalf("PersistDir error = %v, want wrapping the injected sync failure", err)
		}
	})
}

func TestPersistDir_SyncDirFailure(t *testing.T) {
	restore := syncDirFunc
	defer func() { syncDirFunc = restore }()
	injectErr := errors.New("injected syncdir failure")
	syncDirFunc = func(string) error { return injectErr }

	dir := filepath.Join(t.TempDir(), "relay")
	name, _ := LoadedName("p", 1, []byte("x"))
	err := PersistDir(dir, []PersistedPolicy{{LoadedName: name, CanonicalJSON: []byte("{}")}}, os.Getuid(), os.Getgid())
	if !errors.Is(err, injectErr) {
		t.Fatalf("PersistDir error = %v, want wrapping the injected syncDir failure", err)
	}
}

func TestPersistDir_DuplicateLoadedNameFails(t *testing.T) {
	name, _ := LoadedName("p", 1, []byte("x"))
	dir := filepath.Join(t.TempDir(), "relay")
	policies := []PersistedPolicy{
		{LoadedName: name, CanonicalJSON: []byte("{}")},
		{LoadedName: name, CanonicalJSON: []byte(`{"different":true}`)},
	}
	// O_EXCL on the second write of the same filename must fail; this is
	// not expected to happen in practice (loaded names come from a map
	// keyed by base policy name upstream) but is a defensive invariant.
	if err := PersistDir(dir, policies, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("PersistDir silently accepted two policies with the same loaded name")
	}
}
