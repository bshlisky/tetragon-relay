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
	// the directory contents (old file gone, new file present, no
	// leftover staging directory).
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

	// Nothing written outside dir itself (R3-2: no sibling temp
	// directories in dir's parent).
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
	// Every name is validated before dir is ever created.
	if _, statErr := os.Stat(dir); statErr == nil {
		t.Fatal("PersistDir created dir despite rejecting an invalid name")
	}
}

func TestPersistDir_BadParentDirectory(t *testing.T) {
	// A parent that is itself a regular file, not a directory: MkdirAll
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

func TestPersistDir_NoSiblingTempDirectories(t *testing.T) {
	// R3-2: PersistDir must never need to create anything in dir's
	// parent (the production unit's ReadWritePaths= grants write access
	// to dir, never to its parent /etc/tetragon/tetragon.tp.d). Make the
	// parent read-only and confirm PersistDir still succeeds.
	root := t.TempDir()
	dir := filepath.Join(root, "relay")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(root, 0o750) }() // restore so t.TempDir() cleanup can remove it

	name, _ := LoadedName("p", 1, []byte("x"))
	if err := PersistDir(dir, []PersistedPolicy{{LoadedName: name, CanonicalJSON: []byte("{}")}}, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("PersistDir with a read-only parent directory: %v", err)
	}
}

// TestPersistDir_CrashRecovery implements step-03a-review.md R3-2's
// "crash at every point in the update sequence" requirement: each
// subtest injects a failure at a different point in PersistDir's
// (deliberately non-atomic) sequence, confirms PersistDir itself reports
// the failure, then confirms a subsequent, uninjected PersistDir call for
// the same target set converges to exactly that set — modeling
// Reconcile's own behavior of calling PersistDir again whenever Tetragon
// (after any restart) is found loaded with something other than LKG.
func TestPersistDir_CrashRecovery(t *testing.T) {
	name1, _ := LoadedName("p1", 1, []byte("a"))
	name2, _ := LoadedName("p2", 1, []byte("b"))
	initial := []PersistedPolicy{{LoadedName: name1, CanonicalJSON: []byte(`{"a":1}`)}}
	target := []PersistedPolicy{{LoadedName: name2, CanonicalJSON: []byte(`{"b":2}`)}}
	injectErr := errors.New("injected crash")

	assertConverged := func(t *testing.T, dir string) {
		t.Helper()
		if err := PersistDir(dir, target, os.Getuid(), os.Getgid()); err != nil {
			t.Fatalf("recovery PersistDir failed: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != name2+".json" {
			t.Fatalf("after recovery, entries = %v, want exactly %s.json", entries, name2)
		}
	}

	t.Run("crash_during_staging_write", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "relay")
		if err := PersistDir(dir, initial, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
		restore := chmodFileFunc
		chmodFileFunc = func(*os.File, os.FileMode) error { return injectErr }
		if err := PersistDir(dir, target, os.Getuid(), os.Getgid()); !errors.Is(err, injectErr) {
			t.Fatalf("PersistDir error = %v, want the injected failure", err)
		}
		chmodFileFunc = restore
		assertConverged(t, dir)
	})

	t.Run("crash_during_staging_sync", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "relay")
		if err := PersistDir(dir, initial, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
		restore := syncDirFunc
		syncDirFunc = func(string) error { return injectErr }
		if err := PersistDir(dir, target, os.Getuid(), os.Getgid()); !errors.Is(err, injectErr) {
			t.Fatalf("PersistDir error = %v, want the injected failure", err)
		}
		syncDirFunc = restore
		assertConverged(t, dir)
	})

	t.Run("crash_during_rename", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "relay")
		if err := PersistDir(dir, initial, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
		restore := renameFunc
		renameFunc = func(string, string) error { return injectErr }
		if err := PersistDir(dir, target, os.Getuid(), os.Getgid()); !errors.Is(err, injectErr) {
			t.Fatalf("PersistDir error = %v, want the injected failure", err)
		}
		renameFunc = restore
		// A leftover staging directory (with the never-renamed-in new
		// file still inside it) and the stale old file must both be
		// cleaned up by the next successful call.
		assertConverged(t, dir)
	})

	t.Run("crash_during_stale_removal", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "relay")
		if err := PersistDir(dir, initial, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
		restore := removeAllFunc
		staleFile := filepath.Join(dir, name1+".json")
		removeAllFunc = func(path string) error {
			if path == staleFile {
				return injectErr
			}
			return restore(path)
		}
		if err := PersistDir(dir, target, os.Getuid(), os.Getgid()); !errors.Is(err, injectErr) {
			t.Fatalf("PersistDir error = %v, want the injected failure", err)
		}
		removeAllFunc = restore
		// name2.json was already renamed into place before the stale
		// removal step failed; name1.json is still present too (plus a
		// now-empty leftover staging directory).
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		names := make(map[string]bool, len(entries))
		for _, e := range entries {
			names[e.Name()] = true
		}
		if !names[name1+".json"] || !names[name2+".json"] {
			t.Fatalf("mid-crash entries = %v, want both the stale and the new file present", entries)
		}
		assertConverged(t, dir)
	})

	t.Run("crash_during_final_sync", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "relay")
		if err := PersistDir(dir, initial, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
		restore := syncDirFunc
		calls := 0
		syncDirFunc = func(path string) error {
			calls++
			if calls == 2 { // 1st call is the staging-dir sync; 2nd is dir's own final sync
				return injectErr
			}
			return restore(path)
		}
		if err := PersistDir(dir, target, os.Getuid(), os.Getgid()); !errors.Is(err, injectErr) {
			t.Fatalf("PersistDir error = %v, want the injected failure", err)
		}
		syncDirFunc = restore
		assertConverged(t, dir)
	})

	t.Run("crash_during_final_staging_cleanup", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "relay")
		if err := PersistDir(dir, initial, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
		restore := removeAllFunc
		stagingDir := filepath.Join(dir, stagingDirName)
		calls := 0
		removeAllFunc = func(path string) error {
			if path == stagingDir {
				calls++
				if calls == 2 { // 1st call clears any pre-existing staging; 2nd is the final cleanup
					return injectErr
				}
			}
			return restore(path)
		}
		if err := PersistDir(dir, target, os.Getuid(), os.Getgid()); !errors.Is(err, injectErr) {
			t.Fatalf("PersistDir error = %v, want the injected failure", err)
		}
		removeAllFunc = restore
		// dir itself is already fully correct (name2.json in place,
		// name1.json removed) at this point; only a leftover empty
		// staging directory remains.
		assertConverged(t, dir)
	})
}
