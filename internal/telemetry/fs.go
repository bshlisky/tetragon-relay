package telemetry

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// File is the subset of *os.File the spool writes through.
type File interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// FS is every filesystem operation the spool performs, so the crash-matrix
// tests can fail after any single operation while every earlier one takes
// effect on disk (the same approach as internal/store's FS). OSFS is
// production.
type FS interface {
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	Remove(name string) error
	Rename(oldpath, newpath string) error
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	FsyncDir(name string) error
}

// OSFS is the real filesystem. Every path is built from the spool's own
// configured directory.
type OSFS struct{}

// OpenFile implements FS.
func (OSFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	return os.OpenFile(name, flag, perm) //nolint:gosec // G304: built from the spool's own directory
}

// Remove implements FS.
func (OSFS) Remove(name string) error { return os.Remove(name) }

// Rename implements FS.
func (OSFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

// ReadFile implements FS.
func (OSFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name) //nolint:gosec // G304: built from the spool's own directory
}

// ReadDir implements FS.
func (OSFS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }

// FsyncDir implements FS.
func (OSFS) FsyncDir(name string) error {
	d, err := os.Open(name) //nolint:gosec // G304: built from the spool's own directory
	if err != nil {
		return err
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return serr
	}
	return cerr
}

// writeAtomic writes b to dir/name: a temp file, fsync, rename, fsync of
// the directory. A crash at any step leaves either the old file or the
// new one, never a partial one under name (a stale temp file is ignored
// and removed at the next Open).
func writeAtomic(fsys FS, dir, name string, b []byte) error {
	tmp := filepath.Join(dir, name+tmpSuffix)
	f, err := fsys.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("telemetry: create %s: %w", tmp, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("telemetry: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("telemetry: fsync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("telemetry: close %s: %w", tmp, err)
	}
	if err := fsys.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("telemetry: rename %s: %w", tmp, err)
	}
	if err := fsys.FsyncDir(dir); err != nil {
		return fmt.Errorf("telemetry: fsync %s: %w", dir, err)
	}
	return nil
}

const tmpSuffix = ".tmp"
