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
	underlying FS
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

func newFaultFS(underlying FS, crashAfter int) *faultFS {
	return &faultFS{underlying: underlying, crashAfter: crashAfter}
}

// tick reports whether the next operation should proceed (true) or be
// replaced with a simulated crash (false). Once crashed, every subsequent
// call also reports false: a crashed process performs no further
// operations at all, not just the one write sequence it was in the middle
// of.
func (f *faultFS) tick() bool {
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
	if !f.tick() {
		return nil, errSimulatedCrash{"OpenFile:" + name}
	}
	underlying, err := f.underlying.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &faultFile{underlying: underlying, fs: f, name: name}, nil
}

func (f *faultFS) Mkdir(name string, perm fs.FileMode) error {
	if !f.tick() {
		return errSimulatedCrash{"Mkdir:" + name}
	}
	return f.underlying.Mkdir(name, perm)
}

func (f *faultFS) Remove(name string) error {
	if !f.tick() {
		return errSimulatedCrash{"Remove:" + name}
	}
	return f.underlying.Remove(name)
}

func (f *faultFS) Rename(oldpath, newpath string) error {
	if !f.tick() {
		return errSimulatedCrash{"Rename:" + oldpath}
	}
	return f.underlying.Rename(oldpath, newpath)
}

func (f *faultFS) Stat(name string) (fs.FileInfo, error) { return f.underlying.Stat(name) }

func (f *faultFS) Lstat(name string) (fs.FileInfo, error) { return f.underlying.Lstat(name) }

func (f *faultFS) ReadFile(name string) ([]byte, error) { return f.underlying.ReadFile(name) }

func (f *faultFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.underlying.ReadDir(name) }

func (f *faultFS) FsyncDir(name string) error {
	if !f.tick() {
		return errSimulatedCrash{"FsyncDir:" + name}
	}
	return f.underlying.FsyncDir(name)
}

func (f *faultFS) Flock(file File) error { return f.underlying.Flock(file) }

// faultFile wraps a real File so Write/Sync can also be crash points.
type faultFile struct {
	underlying File
	fs         *faultFS
	name       string
}

func (f *faultFile) Write(p []byte) (int, error) {
	if !f.fs.tick() {
		return 0, errSimulatedCrash{"Write:" + f.name}
	}
	return f.underlying.Write(p)
}

func (f *faultFile) Sync() error {
	if !f.fs.tick() {
		return errSimulatedCrash{"Sync:" + f.name}
	}
	return f.underlying.Sync()
}

func (f *faultFile) Close() error {
	// Close is not treated as a crash point: a crash that happens to
	// land exactly on close() has already committed every byte written
	// and fsynced before it (this package always Syncs before Close),
	// so there is nothing left for a close-time crash to lose.
	return f.underlying.Close()
}

func (f *faultFile) Name() string { return f.name }
