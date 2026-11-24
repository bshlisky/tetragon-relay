package store

import (
	"fmt"
	"io/fs"
)

// faultFS wraps a real FS and, after a configured number of operations
// have completed for real, fails the NEXT operation instead of performing
// it — simulating a process crash at that exact point in a write sequence.
// Every operation before the crash point has already taken effect on the
// real underlying filesystem (faultFS wraps OSFS, never an in-memory
// fake), so re-opening the same directory with a fresh, non-faulty FS
// afterward sees exactly what a real crash at that point would have left
// behind (step-04b.md Part E1).
type faultFS struct {
	real FS
	// crashAfter is the number of operations to let through before
	// failing the next one. 0 means fail immediately; a negative value
	// (or exceeding the number of operations actually performed) means
	// never crash.
	crashAfter int
	count      int
	crashed    bool
}

// errSimulatedCrash is returned by the operation at the configured crash
// point, and is not wrapped in anything a caller might mistake for a real
// filesystem error class (ENOENT etc.).
type errSimulatedCrash struct{ op string }

func (e errSimulatedCrash) Error() string { return fmt.Sprintf("store: simulated crash at %s", e.op) }

func newFaultFS(real FS, crashAfter int) *faultFS {
	return &faultFS{real: real, crashAfter: crashAfter}
}

// tick reports whether the operation named op should proceed (true) or be
// replaced with a simulated crash (false). Once crashed, every subsequent
// call also reports false: a crashed process performs no further
// operations at all, not just the one write sequence it was in the middle
// of.
func (f *faultFS) tick(op string) bool {
	if f.crashed {
		return false
	}
	if f.count >= f.crashAfter {
		f.crashed = true
		return false
	}
	f.count++
	return true
}

func (f *faultFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	if !f.tick("OpenFile:" + name) {
		return nil, errSimulatedCrash{"OpenFile:" + name}
	}
	real, err := f.real.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &faultFile{real: real, fs: f, name: name}, nil
}

func (f *faultFS) Mkdir(name string, perm fs.FileMode) error {
	if !f.tick("Mkdir:" + name) {
		return errSimulatedCrash{"Mkdir:" + name}
	}
	return f.real.Mkdir(name, perm)
}

func (f *faultFS) Remove(name string) error {
	if !f.tick("Remove:" + name) {
		return errSimulatedCrash{"Remove:" + name}
	}
	return f.real.Remove(name)
}

func (f *faultFS) Rename(oldpath, newpath string) error {
	if !f.tick("Rename:" + oldpath + "->" + newpath) {
		return errSimulatedCrash{"Rename:" + oldpath}
	}
	return f.real.Rename(oldpath, newpath)
}

func (f *faultFS) Stat(name string) (fs.FileInfo, error) { return f.real.Stat(name) }

func (f *faultFS) Lstat(name string) (fs.FileInfo, error) { return f.real.Lstat(name) }

func (f *faultFS) ReadFile(name string) ([]byte, error) { return f.real.ReadFile(name) }

func (f *faultFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.real.ReadDir(name) }

func (f *faultFS) FsyncDir(name string) error {
	if !f.tick("FsyncDir:" + name) {
		return errSimulatedCrash{"FsyncDir:" + name}
	}
	return f.real.FsyncDir(name)
}

func (f *faultFS) Flock(file File) error { return f.real.Flock(file) }

// faultFile wraps a real File so Write/Sync can also be crash points.
type faultFile struct {
	real File
	fs   *faultFS
	name string
}

func (f *faultFile) Write(p []byte) (int, error) {
	if !f.fs.tick("Write:" + f.name) {
		return 0, errSimulatedCrash{"Write:" + f.name}
	}
	return f.real.Write(p)
}

func (f *faultFile) Sync() error {
	if !f.fs.tick("Sync:" + f.name) {
		return errSimulatedCrash{"Sync:" + f.name}
	}
	return f.real.Sync()
}

func (f *faultFile) Close() error {
	// Close is not treated as a crash point: a crash that happens to
	// land exactly on close() has already committed every byte written
	// and fsynced before it (this package always Syncs before Close),
	// so there is nothing left for a close-time crash to lose.
	return f.real.Close()
}

func (f *faultFile) Name() string { return f.name }
