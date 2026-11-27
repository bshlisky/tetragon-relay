package telemetry

import (
	"bytes"
	"errors"
	"io/fs"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/chainverify"
)

var errCrash = errors.New("injected crash")

// faultFS performs the first crashAfter mutating operations for real, then
// fails every later one, like a process that died at that point: what was
// done is on disk, nothing after it happens (internal/store's approach).
type faultFS struct {
	under      FS
	crashAfter int
	ops        int
}

func (f *faultFS) tick() bool {
	f.ops++
	return f.ops > f.crashAfter
}

type faultFile struct {
	f  File
	fs *faultFS
}

func (w *faultFile) Write(p []byte) (int, error) {
	if w.fs.tick() {
		return 0, errCrash
	}
	return w.f.Write(p)
}

func (w *faultFile) Sync() error {
	if w.fs.tick() {
		return errCrash
	}
	return w.f.Sync()
}

func (w *faultFile) Close() error { return w.f.Close() }

func (f *faultFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	if f.tick() {
		return nil, errCrash
	}
	file, err := f.under.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &faultFile{f: file, fs: f}, nil
}

func (f *faultFS) Remove(name string) error {
	if f.tick() {
		return errCrash
	}
	return f.under.Remove(name)
}

func (f *faultFS) Rename(o, n string) error {
	if f.tick() {
		return errCrash
	}
	return f.under.Rename(o, n)
}

func (f *faultFS) FsyncDir(name string) error {
	if f.tick() {
		return errCrash
	}
	return f.under.FsyncDir(name)
}

func (f *faultFS) ReadFile(name string) ([]byte, error)       { return f.under.ReadFile(name) }
func (f *faultFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.under.ReadDir(name) }

// TestSpool_CrashMatrix crashes an append after every single filesystem
// operation (batch file and head writes, and for the overflow case the
// dropped record and the deletes), restarts with a healthy filesystem, and
// requires: the chain on disk verifies clean, the head is either before or
// after the batch (never in between), a batch above the head is never
// sent, and the next append continues the chain with no gap or fork.
func TestSpool_CrashMatrix(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		crashed := 0
		for n := 0; ; n++ {
			dir := t.TempDir()
			cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
			s := mustOpen(t, cfg)
			big := [][]byte{bytes.Repeat([]byte{1}, 1500)}
			_, _ = s.AppendEvents(batch.ClassNonSecurity, big, 1, 1)
			_, _ = s.AppendEvents(batch.ClassSecurity, big, 1, 1)
			before := s.Stats().LastSeq
			chain := s.Chain()

			ff := &faultFS{under: OSFS{}, crashAfter: n}
			s.cfg.FS = ff
			if overflow {
				s.cfg.MaxBytes = s.Stats().Bytes + 1000
			}
			_, err := s.AppendEvents(batch.ClassSecurity, big, 1, 1)
			if err == nil {
				if crashed == 0 {
					t.Fatalf("overflow=%v: no operation was ever injected", overflow)
				}
				break // n exceeds the number of operations: matrix done
			}
			crashed++

			cfg2 := spoolCfg(t, dir, OSFS{}, "boot-a")
			s2 := mustOpen(t, cfg2)
			if s2.Chain() != chain {
				t.Fatalf("overflow=%v crash@%d: chain restarted after a crash in the same boot", overflow, n)
			}
			after := s2.Stats().LastSeq
			if after < before || after > before+3 {
				t.Fatalf("overflow=%v crash@%d: head seq %d, before %d", overflow, n, after, before)
			}
			if _, err := s2.AppendEvents(batch.ClassSecurity, big, 1, 1); err != nil {
				t.Fatalf("overflow=%v crash@%d: append after restart: %v", overflow, n, err)
			}
			r := chainverify.Verify(testHost, spooled(t, s2))
			for _, f := range r.Findings {
				if f.Kind == chainverify.ChainFork || f.Kind == chainverify.DuplicateMismatch || f.Kind == chainverify.BadHeader || f.Kind == chainverify.HashMismatch {
					t.Fatalf("overflow=%v crash@%d: %+v", overflow, n, f)
				}
				// A gap is allowed only where a dropped record was
				// written but its victims' deletion never ran: they are
				// still on disk, so there is never a gap.
				if f.Kind == chainverify.ChainGap && !overflow {
					t.Fatalf("crash@%d: %+v", n, f)
				}
			}
			if s2.Stats().LastSeq != r.Chains[0].MaxSeq {
				t.Fatalf("overflow=%v crash@%d: head %d, highest spooled %d", overflow, n, s2.Stats().LastSeq, r.Chains[0].MaxSeq)
			}
		}
		if crashed < 10 {
			t.Fatalf("overflow=%v: only %d crash points", overflow, crashed)
		}
	}
}
