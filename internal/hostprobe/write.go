package hostprobe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// chmodFunc/chownFunc/syncFunc are package variables purely so tests can
// inject a failure on a step that is otherwise hard to make fail
// deterministically and portably (e.g. simulating a disk-full fsync
// without actually filling a disk).
var (
	chmodFunc = func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) }
	chownFunc = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	syncFunc  = func(f *os.File) error { return f.Sync() }
)

// WriteAtomic implements step 3 prompt Part C4's persistence requirement:
// marshal facts as JSON and write it to path atomically (temp file in the
// same directory, fsync file and directory, rename over the destination),
// owned uid/gid and mode 0640. uid/gid are parameters (not hardcoded to
// root:tetragon-relay) so tests can exercise this as the invoking user;
// cmd/relay-probe (which runs as root) passes the real root uid and the
// configured relay group's gid.
func WriteAtomic(path string, facts *HostFacts, uid, gid int) error {
	data, err := json.Marshal(facts)
	if err != nil {
		return fmt.Errorf("hostprobe: marshal host facts: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".host-facts-*.tmp")
	if err != nil {
		return fmt.Errorf("hostprobe: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("hostprobe: write temp file: %w", err)
	}
	if err := chmodFunc(tmp, 0o640); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("hostprobe: chmod temp file: %w", err)
	}
	if err := chownFunc(tmp, uid, gid); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("hostprobe: chown temp file: %w", err)
	}
	if err := syncFunc(tmp); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("hostprobe: fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("hostprobe: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("hostprobe: rename %s to %s: %w", tmpPath, path, err)
	}
	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("hostprobe: fsync directory %s: %w", dir, err)
	}
	return nil
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // dir is filepath.Dir(path), itself operator-configured (architecture doc 8.6), not attacker-controlled
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
