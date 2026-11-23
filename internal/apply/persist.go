package apply

import (
	"fmt"
	"os"
	"path/filepath"
)

// PersistedPolicy is one loaded policy's final (name-rewritten,
// mode-rewritten) canonical JSON, as written to disk by PersistDir.
type PersistedPolicy struct {
	LoadedName    string
	CanonicalJSON []byte
}

// chmodFileFunc/chownFileFunc/syncFileFunc/syncDirFunc are package
// variables purely so tests can inject a failure on a step that is
// otherwise hard to make fail deterministically and portably, mirroring
// internal/hostprobe/write.go's identical pattern.
var (
	chmodFileFunc = func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) }
	syncFileFunc  = func(f *os.File) error { return f.Sync() }
	syncDirFunc   = func(path string) error {
		d, err := os.Open(path) //nolint:gosec // path is operator-configured (architecture doc 8.6), not attacker-controlled
		if err != nil {
			return err
		}
		defer func() { _ = d.Close() }()
		return d.Sync()
	}
)

// PersistDir implements step 3 prompt Part D4: writes policies (every
// policy currently loaded by this engine for domain, after D1's name
// rewrite and D2's mode rewrite) into dir (architecture doc section 8.5:
// /etc/tetragon/tetragon.tp.d/relay/, read by Tetragon at its own startup
// per cmd/tetragon/main.go:694-726 / ADR 0016 — one level of
// subdirectories under /etc/tetragon/tetragon.tp.d, no file extension
// requirement) so Tetragon reloads the exact same set across a restart.
//
// dir is entirely relay-managed (architecture doc section 8.5's
// filesystem table: root:tetragon-relay, mode 2770, exclusively this
// engine's own subdirectory of Tetragon's policy directory) — nothing
// else is expected to write into it, so PersistDir replaces its entire
// contents wholesale rather than reconciling file-by-file. It never
// touches anything outside dir itself.
//
// Atomicity: policies are written into a sibling temp directory in the
// same filesystem (so the final swap is a rename, not a copy across
// filesystems), every file and the temp directory itself are fsynced,
// then the temp directory replaces dir via two renames (dir -> a sibling
// ".old" name, then the temp directory -> dir) since POSIX rename(2)
// cannot atomically replace a non-empty directory in one call. The brief
// window between those two renames where dir does not exist is not an
// enforcement gap: Tetragon only reads this directory at its own startup
// (ADR 0016), which this engine does not race against, never while
// continuously watching it.
func PersistDir(dir string, policies []PersistedPolicy, uid, gid int) error {
	parent := filepath.Dir(dir)
	tmpDir, err := os.MkdirTemp(parent, filepath.Base(dir)+".new-*")
	if err != nil {
		return fmt.Errorf("apply: create temp directory in %s: %w", parent, err)
	}
	cleanupTmp := func() { _ = os.RemoveAll(tmpDir) }

	for _, p := range policies {
		if err := writePersistedFile(tmpDir, p, uid, gid); err != nil {
			cleanupTmp()
			return err
		}
	}
	if err := syncDirFunc(tmpDir); err != nil {
		cleanupTmp()
		return fmt.Errorf("apply: fsync temp directory %s: %w", tmpDir, err)
	}

	oldDir := dir + ".old"
	_ = os.RemoveAll(oldDir) // stale leftover from a previous crashed attempt

	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, oldDir); err != nil {
			cleanupTmp()
			return fmt.Errorf("apply: rename %s to %s: %w", dir, oldDir, err)
		}
	} else if !os.IsNotExist(err) {
		cleanupTmp()
		return fmt.Errorf("apply: stat %s: %w", dir, err)
	}

	if err := os.Rename(tmpDir, dir); err != nil {
		// Best-effort: put the old directory back so a failed persist
		// never leaves Tetragon's policy directory missing entirely.
		_ = os.Rename(oldDir, dir)
		cleanupTmp()
		return fmt.Errorf("apply: rename %s to %s: %w", tmpDir, dir, err)
	}
	if err := syncDirFunc(parent); err != nil {
		return fmt.Errorf("apply: fsync %s: %w", parent, err)
	}
	_ = os.RemoveAll(oldDir)
	return nil
}

func writePersistedFile(dir string, p PersistedPolicy, uid, gid int) error {
	if !loadedNamePattern.MatchString(p.LoadedName) {
		// Defense in depth: every caller is expected to only ever pass a
		// name LoadedName() produced, but this function turns the name
		// directly into a filesystem path, so it re-validates rather
		// than trusting that invariant blindly.
		return fmt.Errorf("apply: refusing to persist invalid loaded name %q", p.LoadedName)
	}
	path := filepath.Join(dir, p.LoadedName+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640) //nolint:gosec // dir is a temp dir this function created; p.LoadedName is validated by loadedNamePattern before this is ever called
	if err != nil {
		return fmt.Errorf("apply: create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(p.CanonicalJSON); err != nil {
		return fmt.Errorf("apply: write %s: %w", path, err)
	}
	if err := chmodFileFunc(f, 0o640); err != nil {
		return fmt.Errorf("apply: chmod %s: %w", path, err)
	}
	if err := f.Chown(uid, gid); err != nil {
		return fmt.Errorf("apply: chown %s: %w", path, err)
	}
	if err := syncFileFunc(f); err != nil {
		return fmt.Errorf("apply: fsync %s: %w", path, err)
	}
	return nil
}
