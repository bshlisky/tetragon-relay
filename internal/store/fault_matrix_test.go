package store

import (
	"errors"
	"os"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/apply"
)

// This file is step-04b.md Part E1: a fault-injection filesystem layer
// around every os call internal/store's write paths use (faultFS,
// fault_test.go), crashing at every single filesystem operation of every
// write path, re-opening, and asserting the resulting state is exactly
// old or exactly new and Open succeeds without tamper.
//
// The invariant under test is Part C3's: "a crash at any point leaves
// either the old or the new state readable, never a mix" — NOT that a
// non-nil error from the action implies the old state. A real process
// crash could land after the rename that makes the new index visible but
// before writeIndexFile's caller ever observes success (e.g. the
// directory-fsync step failing in-process while the rename itself already
// took effect on disk) — the action reporting an error in that case is
// accurate ("I cannot confirm this committed"), but the on-disk state is
// legitimately already the new generation. check must therefore accept
// EITHER value, and is responsible for confirming it is not some
// third, inconsistent thing.
//
// maxCrashPoints is deliberately generous (comfortably above the number
// of FS operations any single write performs: at most one blob
// create+write+sync+close, one index.tmp create+write+sync+close, one
// rename, one directory fsync — under 10) so the sweep always runs a few
// iterations past the point where the action completes without being
// crashed at all, confirming there is no later, missed crash point.
const maxCrashPoints = 15

func newTestSealer() KeySealer {
	return &FakeKeySealer{Key: []byte("fault-matrix-test-key-0123456789")}
}

// crashMatrix runs action against a freshly-initialized store directory
// (generation 1, first boot already completed with a real, unfaulted FS)
// once per crashAfter value from 0 to maxCrashPoints. The Store's
// filesystem is switched to a faultFS (crashing after exactly crashAfter
// further operations) only for the duration of action itself, so the
// crash points swept are exactly action's own operations, not Open's
// baseline index-loading reads. After each attempt, it re-opens the SAME
// directory with a plain, unfaulted FS and calls check, which must assert
// the resulting state is exactly the old value or exactly the new value
// for this action (never a third, inconsistent value) and call
// s.Close() itself.
func crashMatrix(t *testing.T, action func(s *Store) error, check func(t *testing.T, s *Store)) {
	t.Helper()
	for crashAfter := 0; crashAfter < maxCrashPoints; crashAfter++ {
		t.Run(itoa(crashAfter), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			counter := NewFakeMonotonicCounter()
			sealer := newTestSealer()

			s, err := openWithFS(dir, sealer, counter, OSFS{})
			if err != nil {
				t.Fatalf("baseline Open: %v", err)
			}

			s.fs = newFaultFS(OSFS{}, crashAfter)
			actionErr := action(s)
			_ = s.Close() // release the flock, as a crashed process's exit would.

			if actionErr != nil &&
				!errors.As(actionErr, new(errSimulatedCrash)) &&
				!errors.Is(actionErr, ErrLimitExceeded) {
				t.Fatalf("action returned a non-simulated-crash error: %v", actionErr)
			}

			reopened, err := Open(dir, sealer, counter)
			if err != nil {
				t.Fatalf("recovery Open after crashAfter=%d (action err=%v): %v", crashAfter, actionErr, err)
			}
			check(t, reopened)
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestCrashMatrix_RecordEpoch(t *testing.T) {
	crashMatrix(t,
		func(s *Store) error { return s.RecordEpoch("prod-db", 5) },
		func(t *testing.T, s *Store) {
			defer func() { _ = s.Close() }()
			epoch, err := s.Current("prod-db")
			if err != nil {
				t.Fatalf("Current: %v", err)
			}
			if epoch != 0 && epoch != 5 {
				t.Fatalf("epoch = %d, want 0 (old) or 5 (new)", epoch)
			}
		},
	)
}

func TestCrashMatrix_Put(t *testing.T) {
	set := apply.LKGSet{Mode: "enforce", Policies: []apply.LKGPolicy{
		{Name: "block-shadow-read", Version: 1, CanonicalJSON: []byte(`{"name":"block-shadow-read"}`)},
	}}
	crashMatrix(t,
		func(s *Store) error { return s.Put("prod-db", set) },
		func(t *testing.T, s *Store) {
			defer func() { _ = s.Close() }()
			got, ok := s.Get("prod-db")
			if !ok {
				return // old state: nothing persisted yet.
			}
			if got.Mode != "enforce" || len(got.Policies) != 1 || got.Policies[0].Name != "block-shadow-read" {
				t.Fatalf("Get = %+v, want exactly the new set (or ok=false)", got)
			}
		},
	)
}

func TestCrashMatrix_PersistTrustRoot(t *testing.T) {
	crashMatrix(t,
		func(s *Store) error { return s.PersistTrustRoot([]byte("root-v1-bytes"), 1) },
		func(t *testing.T, s *Store) {
			defer func() { _ = s.Close() }()
			raw, version, ok, err := s.TrustRoot()
			if err != nil {
				t.Fatalf("TrustRoot: %v", err)
			}
			if !ok {
				return // old state: no root persisted yet.
			}
			if version != 1 || string(raw) != "root-v1-bytes" {
				t.Fatalf("TrustRoot = (%q, %d), want exactly the new root (or ok=false)", raw, version)
			}
		},
	)
}

// TestCrashMatrix_RecordEpochTwice chains two successful writes with a
// faulted THIRD write in between, so the "old" state a crash can fall back
// to is itself a non-trivial, already-once-written generation (not just
// "nothing"), exercising commitLocked's generation-increment-from-N path
// under fault rather than only generation 1-from-0.
func TestCrashMatrix_RecordEpochTwice(t *testing.T) {
	for crashAfter := 0; crashAfter < maxCrashPoints; crashAfter++ {
		t.Run(itoa(crashAfter), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			counter := NewFakeMonotonicCounter()
			sealer := newTestSealer()

			s, err := openWithFS(dir, sealer, counter, OSFS{})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if err := s.RecordEpoch("prod-db", 5); err != nil {
				t.Fatalf("first RecordEpoch: %v", err)
			}

			s.fs = newFaultFS(OSFS{}, crashAfter)
			actionErr := s.RecordEpoch("prod-db", 10)
			_ = s.Close()
			if actionErr != nil && !errors.As(actionErr, new(errSimulatedCrash)) {
				t.Fatalf("action returned a non-simulated-crash error: %v", actionErr)
			}

			reopened, err := Open(dir, sealer, counter)
			if err != nil {
				t.Fatalf("recovery Open after crashAfter=%d: %v", crashAfter, err)
			}
			defer func() { _ = reopened.Close() }()
			epoch, err := reopened.Current("prod-db")
			if err != nil {
				t.Fatalf("Current: %v", err)
			}
			if epoch != 5 && epoch != 10 {
				t.Fatalf("epoch = %d, want 5 (old) or 10 (new)", epoch)
			}
		})
	}
}

func TestCrashMatrix_FirstBoot(t *testing.T) {
	for crashAfter := 0; crashAfter < maxCrashPoints; crashAfter++ {
		t.Run(itoa(crashAfter), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			counter := NewFakeMonotonicCounter()
			sealer := newTestSealer()

			faulted, err := openWithFS(dir, sealer, counter, newFaultFS(OSFS{}, crashAfter))
			if err != nil {
				if !errors.As(err, new(errSimulatedCrash)) && !errors.Is(err, ErrTampered) {
					t.Fatalf("Open returned an unexpected error: %v", err)
				}
			} else {
				_ = faulted.Close()
			}

			reopened, err := Open(dir, sealer, counter)
			if err != nil {
				t.Fatalf("recovery Open after crashAfter=%d (first attempt err=%v): %v", crashAfter, err, err)
			}
			defer func() { _ = reopened.Close() }()
			// Either the crash landed before the rename took effect
			// (recovery performs first boot itself, generation 1,
			// FirstBoot()==true) or after (recovery sees an
			// already-initialized generation-1 store,
			// FirstBoot()==false) — both are the single legitimate
			// "new" outcome here (there is no "old" for a first
			// boot). Either way, Generation() must be exactly 1 and
			// Open must not report tamper (already guaranteed by
			// reaching this line without an error).
			if g := reopened.Generation(); g != 1 {
				t.Fatalf("Generation = %d, want 1", g)
			}
		})
	}
}
