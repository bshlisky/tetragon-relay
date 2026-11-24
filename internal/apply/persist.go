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

// stagingDirName is PersistDir's staging subdirectory, nested inside dir
// itself (step-03a-review.md R3-2). Tetragon's own --tracing-policy-dir
// loader (cmd/tetragon/main.go:694-726, ADR 0016: "walked with
// fs.WalkDir and tpMaxDepth := 1: ... a directory two or more levels deep
// is skipped (fs.SkipDir)") never descends into it, since dir is already
// one level below Tetragon's root (.../tetragon.tp.d/relay) and
// stagingDirName would be a second level.
const stagingDirName = ".staging"

// chmodFileFunc/syncFileFunc/syncDirFunc/renameFunc/removeAllFunc are
// package variables purely so tests can inject a failure on a step that
// is otherwise hard to make fail deterministically and portably
// (mirroring internal/hostprobe/write.go's identical pattern), including
// at every point along PersistDir's own (deliberately non-atomic, see its
// doc comment) update sequence.
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
	renameFunc    = os.Rename
	removeAllFunc = os.RemoveAll
)

// PersistDir implements step 3 prompt Part D4 (as redesigned by
// step-03a-review.md R3-2): writes policies (every policy currently
// loaded by this engine for domain, after D1's name rewrite and D2's mode
// rewrite) into dir (architecture doc section 8.5:
// /etc/tetragon/tetragon.tp.d/relay/) so Tetragon reloads the exact same
// set across a restart — using ONLY paths inside dir itself, since the
// production unit's ReadWritePaths= (packaging/systemd/
// tetragon-relay.service) grants write access to dir, never to its
// parent /etc/tetragon/tetragon.tp.d (R3-2: 709f3da's version needed the
// parent writable for its sibling-temp-directory swap, which the
// production unit's ProtectSystem=strict/ReadWritePaths= does not allow).
//
// dir is entirely relay-managed (architecture doc section 8.5's
// filesystem table: root:tetragon-relay, mode 2770, exclusively this
// engine's own subdirectory of Tetragon's policy directory) — nothing
// else is expected to write into it, so PersistDir replaces its entire
// contents wholesale rather than reconciling file-by-file.
//
// Sequence (every step operates inside dir or its own stagingDirName
// subdirectory, never dir's parent): every policy is written to a fresh
// stagingDirName subdirectory under its final filename, fsynced, then
// renamed directly into dir (a same-filesystem rename, since
// stagingDirName is a child of dir); stale dir entries not in the new set
// are then removed; dir itself is fsynced; stagingDirName is removed.
//
// Atomicity: unlike the sibling-directory swap this replaced, this
// sequence is NOT atomic — a crash partway through can leave dir with a
// mix of old and new files, or a leftover stagingDirName. This is an
// accepted, documented trade-off (ADR 0019): Tetragon CAN restart at any
// moment, including mid-update (step-03b-review.md R3B-4 — this engine
// has no way to prevent or detect that), but the sequence is constructed
// so that whatever Tetragon's startup read (ADR 0016's
// cmd/tetragon/main.go:694-726, tpMaxDepth := 1) observes at any point is
// always a superset of the old set or the new set: stagingDirName sits
// below tpMaxDepth and is never read mid-update; the rename-then-remove
// order means additions land (superset of old) before any removal
// starts (superset of new). The relay's own Reconcile additionally
// re-asserts the LKG set (calling PersistDir again) whenever Tetragon's
// loaded policies drift from LKG, including after any restart, so a
// crash here converges to the correct final state on the very next
// PersistDir call for the same (or any subsequent) target set — it does
// not need to be atomic to be eventually correct, only to never be a
// strict subset of both sets while non-atomic. Any stale stagingDirName
// left behind by a previous crashed call is removed before a new one is
// created.
func PersistDir(dir string, policies []PersistedPolicy, uid, gid int) error {
	wantNames := make(map[string]bool, len(policies))
	for _, p := range policies {
		if !loadedNamePattern.MatchString(p.LoadedName) {
			// Defense in depth: every caller is expected to only ever
			// pass a name LoadedName() produced, but this function turns
			// the name directly into a filesystem path, so it
			// re-validates (before touching the filesystem at all)
			// rather than trusting that invariant blindly.
			return fmt.Errorf("apply: refusing to persist invalid loaded name %q", p.LoadedName)
		}
		wantNames[p.LoadedName+".json"] = true
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("apply: create %s: %w", dir, err)
	}

	stagingDir := filepath.Join(dir, stagingDirName)
	if err := removeAllFunc(stagingDir); err != nil {
		return fmt.Errorf("apply: remove stale staging directory %s: %w", stagingDir, err)
	}
	if err := os.Mkdir(stagingDir, 0o750); err != nil {
		return fmt.Errorf("apply: create staging directory %s: %w", stagingDir, err)
	}
	cleanupStaging := func() { _ = removeAllFunc(stagingDir) }

	for _, p := range policies {
		if err := writePersistedFile(stagingDir, p, uid, gid); err != nil {
			cleanupStaging()
			return err
		}
	}
	if err := syncDirFunc(stagingDir); err != nil {
		cleanupStaging()
		return fmt.Errorf("apply: fsync staging directory %s: %w", stagingDir, err)
	}

	for name := range wantNames {
		if err := renameFunc(filepath.Join(stagingDir, name), filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("apply: rename %s into %s: %w", name, dir, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("apply: read %s: %w", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == stagingDirName || wantNames[name] {
			continue
		}
		if err := removeAllFunc(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("apply: remove stale %s: %w", name, err)
		}
	}

	if err := syncDirFunc(dir); err != nil {
		return fmt.Errorf("apply: fsync %s: %w", dir, err)
	}
	if err := removeAllFunc(stagingDir); err != nil {
		return fmt.Errorf("apply: remove staging directory %s: %w", stagingDir, err)
	}
	return nil
}

func writePersistedFile(dir string, p PersistedPolicy, uid, gid int) error {
	if !loadedNamePattern.MatchString(p.LoadedName) {
		// Defense in depth: PersistDir already validates every name
		// before calling this, but this function turns the name
		// directly into a filesystem path, so it re-validates rather
		// than trusting that invariant blindly.
		return fmt.Errorf("apply: refusing to persist invalid loaded name %q", p.LoadedName)
	}
	path := filepath.Join(dir, p.LoadedName+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640) //nolint:gosec // dir is a staging dir this function created; p.LoadedName is validated by loadedNamePattern before this is ever called
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
