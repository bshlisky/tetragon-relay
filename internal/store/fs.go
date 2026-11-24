package store

import (
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// File is the subset of *os.File this package uses on its write path.
type File interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
	Name() string
}

// FS abstracts every filesystem operation internal/store performs, so a
// test can wrap it with one that fails (simulating a crash) after any
// individual operation while every operation that already completed takes
// effect for real on disk (step-04b.md Part E1: "a fault-injection
// filesystem layer ... an interface around the os calls used"). OSFS is
// the production implementation; faultFS (fault_test.go) is the test
// implementation.
type FS interface {
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	Mkdir(name string, perm fs.FileMode) error
	Remove(name string) error
	Rename(oldpath, newpath string) error
	Stat(name string) (fs.FileInfo, error)
	Lstat(name string) (fs.FileInfo, error)
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	// FsyncDir fsyncs the directory at name, for durability of a rename
	// or create/delete within it.
	FsyncDir(name string) error
	// Flock acquires an exclusive, non-blocking advisory lock on f.
	// Returns an error (unix.EWOULDBLOCK, wrapped) if already locked by
	// another process.
	Flock(f File) error
}

// OSFS is the real filesystem: every method is a thin, directly-mockable
// wrapper around the matching os/golang.org/x/sys/unix call.
type OSFS struct{}

func (OSFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	return os.OpenFile(name, flag, perm)
}

func (OSFS) Mkdir(name string, perm fs.FileMode) error { return os.Mkdir(name, perm) }

func (OSFS) Remove(name string) error { return os.Remove(name) }

func (OSFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (OSFS) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }

func (OSFS) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }

func (OSFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

func (OSFS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }

func (OSFS) FsyncDir(name string) error {
	d, err := os.Open(name)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (OSFS) Flock(f File) error {
	osf, ok := f.(*os.File)
	if !ok {
		return nil // non-*os.File File values (fakes) are not flocked
	}
	return unix.Flock(int(osf.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

var _ FS = OSFS{}
