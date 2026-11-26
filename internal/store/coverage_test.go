package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// This file contains white-box (package store) tests for branches not
// otherwise exercised by the black-box (store_test, tamper_test,
// fault_matrix_test) suites: internal helper functions' error paths that
// are straightforward to hit directly but awkward to provoke solely
// through the public API.

func TestVerifyIndexLimits_EachBound(t *testing.T) {
	base := func() indexPayload {
		return indexPayload{Schema: indexSchema, Generation: 1, Epochs: map[string]uint64{}, History: map[string][]string{}, LKG: map[string]lkgEntry{}}
	}

	t.Run("too many scopes with an epoch", func(t *testing.T) {
		p := base()
		for i := 0; i < limits.MaxStoreScopes+1; i++ {
			p.Epochs["scope"+strconv.Itoa(i)] = uint64(i)
		}
		if err := verifyIndexLimits(p); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("err = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("too many scopes with history", func(t *testing.T) {
		p := base()
		for i := 0; i < limits.MaxStoreScopes+1; i++ {
			p.History["scope"+strconv.Itoa(i)] = []string{"x"}
		}
		if err := verifyIndexLimits(p); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("err = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("too many history names in one scope", func(t *testing.T) {
		p := base()
		names := make([]string, limits.MaxStoreHistoryNamesPerScope+1)
		for i := range names {
			names[i] = "name" + strconv.Itoa(i)
		}
		p.History["prod-db"] = names
		if err := verifyIndexLimits(p); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("err = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("too many LKG domains", func(t *testing.T) {
		p := base()
		for i := 0; i < limits.MaxStoreDomains+1; i++ {
			p.LKG["domain"+strconv.Itoa(i)] = lkgEntry{BlobDigest: "d", Mode: "enforce"}
		}
		if err := verifyIndexLimits(p); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("err = %v, want ErrLimitExceeded", err)
		}
	})

	t.Run("within every bound", func(t *testing.T) {
		if err := verifyIndexLimits(base()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestDecodeIndexFile_TooLarge(t *testing.T) {
	raw := make([]byte, limits.MaxStoreIndexBytes+1)
	if _, err := decodeIndexFile(raw); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

func TestDecodeIndexFile_WrongSchema(t *testing.T) {
	raw := []byte(`{"payload":{"schema":"wrong","generation":1,"epochs":{},"history":{},"lkg":{}},"hmac":"ab"}`)
	if _, err := decodeIndexFile(raw); err == nil {
		t.Fatalf("expected an error for the wrong schema")
	}
}

func TestDecodeIndexFile_Unparseable(t *testing.T) {
	if _, err := decodeIndexFile([]byte("{not json")); err == nil {
		t.Fatalf("expected a decode error")
	}
}

func TestMarkTampered_ViaGetAfterDiskCorruption(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Put("prod-db", apply.LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Corrupt the blob ON DISK after Open/Put already validated it in
	// memory, simulating a concurrent offline edit the in-process Store
	// object has not yet observed (it only re-reads a blob on demand).
	blobsDir := filepath.Join(dir, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("read blobs: %v (n=%d)", err, len(entries))
	}
	path := filepath.Join(blobsDir, entries[0].Name())
	if err := os.WriteFile(path, []byte("corrupted"), 0o600); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	if _, ok := s.Get("prod-db"); ok {
		t.Fatalf("Get after on-disk corruption: ok = true")
	}
	if err := s.Tampered(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Tampered() = %v after Get hit a corrupted blob, want ErrTampered", err)
	}
	// Once tampered, every other method must also fail closed, even
	// ones whose own data was never touched.
	if _, err := s.Current("prod-db"); !errors.Is(err, ErrTampered) {
		t.Fatalf("Current() after tamper: err = %v, want ErrTampered", err)
	}
}

func TestMarkTampered_ViaTrustRootAfterDiskCorruption(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.PersistTrustRoot([]byte("root-bytes"), 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	blobsDir := filepath.Join(dir, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("read blobs: %v (n=%d)", err, len(entries))
	}
	path := filepath.Join(blobsDir, entries[0].Name())
	if err := os.WriteFile(path, []byte("corrupted"), 0o600); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	if _, _, ok, err := s.TrustRoot(); ok || !errors.Is(err, ErrTampered) {
		t.Fatalf("TrustRoot after corruption = (ok=%v, err=%v), want (false, ErrTampered)", ok, err)
	}
	if err := s.Put("x", apply.LKGSet{}); !errors.Is(err, ErrTampered) {
		t.Fatalf("Put after tamper: err = %v, want ErrTampered", err)
	}
}

func TestFsyncDir_MissingDirectory(t *testing.T) {
	if err := (OSFS{}).FsyncDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatalf("expected an error fsyncing a missing directory")
	}
}

func TestWriteBlobIfMissing_TooLarge(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	big := make([]byte, limits.MaxStoreBlobBytes+1)
	if _, err := s.writeBlobIfMissing(big); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

func TestReadBlob_TooLargeOnDisk(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	big := make([]byte, limits.MaxStoreBlobBytes+1)
	digest := blobDigest(big)
	if err := os.WriteFile(s.blobPath(digest), big, 0o600); err != nil {
		t.Fatalf("write oversized blob: %v", err)
	}
	if _, err := s.readBlob(digest); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func TestGCBlobs_MissingDirIsHarmless(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := os.RemoveAll(filepath.Join(dir, "blobs")); err != nil {
		t.Fatalf("remove blobs dir: %v", err)
	}
	// Must not panic even though blobs/ is gone.
	s.gcBlobs(map[string]struct{}{})
}

func TestOpen_CounterUnavailableAtFirstBoot(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	failing := &failingCounter{err: errCounterBroken}
	if _, err := Open(dir, newTestSealer(), failing); !errors.Is(err, ErrCounterUnavailable) {
		t.Fatalf("err = %v, want ErrCounterUnavailable", err)
	}
}

func TestOpen_FirstBootWithNonzeroCounterIsTampered(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	counter := NewFakeMonotonicCounter()
	counter.Set(5)
	if _, err := Open(dir, newTestSealer(), counter); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

type failingCounter struct{ err error }

func (f *failingCounter) Read() (uint64, error)      { return 0, f.err }
func (f *failingCounter) Increment() (uint64, error) { return 0, f.err }

var errCounterBroken = errors.New("counter broken")

// fakeFileInfoUnknownSys is an os.FileInfo whose Sys() returns a value
// that is not *syscall.Stat_t, simulating a platform (anything other than
// Linux or Darwin) where ownership cannot be determined this way.
// step-04b-review.md R4B-3.
type fakeFileInfoUnknownSys struct {
	mode os.FileMode
}

func (fakeFileInfoUnknownSys) Name() string           { return "store-dir" }
func (fakeFileInfoUnknownSys) Size() int64            { return 0 }
func (f fakeFileInfoUnknownSys) Mode() os.FileMode    { return f.mode }
func (fakeFileInfoUnknownSys) ModTime() (t time.Time) { return t }
func (fakeFileInfoUnknownSys) IsDir() bool            { return true }
func (fakeFileInfoUnknownSys) Sys() interface{}       { return "not-a-syscall-stat-t" }

func TestCheckOwnerAndMode_UnknownPlatformFailsClosed(t *testing.T) {
	fi := fakeFileInfoUnknownSys{mode: 0o700}
	if err := checkOwnerAndMode(fi, 0o700); err == nil {
		t.Fatalf("expected an error when fi.Sys() is not *syscall.Stat_t, got nil (R4B-3: must fail closed, not silently skip the ownership check)")
	}
}

func TestCheckOwnerAndMode_UnknownPlatformStillChecksModeFirst(t *testing.T) {
	// The mode mismatch must still be reported even on an
	// unknown-Sys() platform (checked first, independent of ownership).
	fi := fakeFileInfoUnknownSys{mode: 0o755}
	err := checkOwnerAndMode(fi, 0o700)
	if err == nil {
		t.Fatalf("expected an error for a mode mismatch")
	}
}

func TestPrunedRootHistory_ReferencedVersionWithNoBlobIsOmittedAndEmptyIsNil(t *testing.T) {
	// No TrustRoot and no LKG entries at all: nothing to keep.
	if h := prunedRootHistory(indexPayload{}); h != nil {
		t.Fatalf("prunedRootHistory(empty) = %v, want nil", h)
	}
	// An LKG entry references a root version this package has no blob
	// for at all (should not happen for an index this package itself
	// ever produced); the fail-closed choice is to omit it, not invent
	// or silently keep a phantom reference.
	p := indexPayload{
		LKG: map[string]lkgEntry{
			"domain-a": {BlobDigest: "d", Mode: "enforce", RootVersion: 7},
		},
	}
	h := prunedRootHistory(p)
	if _, ok := h[7]; ok {
		t.Fatalf("prunedRootHistory kept version 7 despite no blob for it: %v", h)
	}
}

func TestRootAtVersion_CorruptedBlobMarksTampered(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.PersistTrustRoot([]byte("root-bytes"), 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	entry := s.committed.TrustRootHistory[1]
	if err := os.WriteFile(s.blobPath(entry.BlobDigest), []byte("corrupted"), 0o600); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}
	if _, ok, err := s.RootAtVersion(1); ok || !errors.Is(err, ErrTampered) {
		t.Fatalf("RootAtVersion after corruption = (ok=%v, err=%v), want (false, ErrTampered)", ok, err)
	}
}

func TestPut_TooLargeRawEnvelope(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	big := make([]byte, limits.MaxStoreBlobBytes+1)
	if err := s.Put("prod-db", apply.LKGSet{Mode: "enforce", RawEnvelope: big}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

func TestPut_AfterCloseReturnsErrClosed(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Put("prod-db", apply.LKGSet{Mode: "enforce"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

func TestVerifyIndexLimits_TooManyRootHistoryVersions(t *testing.T) {
	p := indexPayload{Schema: indexSchema, Generation: 1, Epochs: map[string]uint64{}, History: map[string][]string{}, LKG: map[string]lkgEntry{}}
	p.TrustRootHistory = make(map[uint64]trustRootEntry, limits.MaxStoreRootHistoryVersions+1)
	for i := uint64(0); i < uint64(limits.MaxStoreRootHistoryVersions+1); i++ {
		p.TrustRootHistory[i] = trustRootEntry{Version: i, BlobDigest: "d"}
	}
	if err := verifyIndexLimits(p); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

func TestOpen_NonexistentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter()); err == nil {
		t.Fatalf("expected an error for a nonexistent directory")
	}
}

func TestOpen_IndexIsADirectoryNotAFile(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	if err := os.Mkdir(filepath.Join(dir, "index"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter()); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func TestWriteBlobIfMissing_AlreadyPresentWithMatchingContent(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	b := []byte("some blob content")
	d1, err := s.writeBlobIfMissing(b)
	if err != nil {
		t.Fatalf("writeBlobIfMissing (first): %v", err)
	}
	d2, err := s.writeBlobIfMissing(b)
	if err != nil {
		t.Fatalf("writeBlobIfMissing (second, already present): %v", err)
	}
	if d1 != d2 {
		t.Fatalf("digest changed between calls: %q vs %q", d1, d2)
	}
}

func TestWriteBlobIfMissing_AlreadyPresentFsyncsAgain(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	b := []byte("already present content")
	if _, err := s.writeBlobIfMissing(b); err != nil {
		t.Fatalf("writeBlobIfMissing (first): %v", err)
	}

	// step-04b-review.md R4B-4: the "already present" branch must
	// still fsync the existing file and the blobs directory, not just
	// assume an earlier writer already did. Swap in a faulting FS that
	// fails the very next filesystem operation and confirm the second
	// call (which takes the already-present branch) surfaces that
	// failure, proving it actually touches the filesystem rather than
	// returning success having done nothing durable at all.
	s.fs = newFaultFS(s.fs, 0)
	if _, err := s.writeBlobIfMissing(b); err == nil {
		t.Fatalf("expected an error: the already-present path must still fsync (and so must observe the injected fault)")
	}
}

func TestGCBlobs_SkipsSubdirectories(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := os.Mkdir(filepath.Join(dir, "blobs", "a-subdirectory"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Must not attempt to remove the subdirectory as if it were an
	// unreferenced blob file.
	s.gcBlobs(map[string]struct{}{})
	if _, err := os.Stat(filepath.Join(dir, "blobs", "a-subdirectory")); err != nil {
		t.Fatalf("subdirectory was removed by gcBlobs: %v", err)
	}
}

func TestCommitLocked_CounterIncrementFailsAfterDurableWrite(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	counter := NewFakeMonotonicCounter()
	s, err := Open(dir, newTestSealer(), counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	s.counter = &failingCounter{err: errCounterBroken}
	// step-04b-review.md R4B-5: this specific failure mode (index write
	// durable, counter increment failed right after) is now the
	// distinct ErrCommittedCounterLag, not ErrCounterUnavailable (which
	// means the write itself could not proceed at all).
	if err := s.RecordEpoch("prod-db", 5); !errors.Is(err, ErrCommittedCounterLag) {
		t.Fatalf("err = %v, want ErrCommittedCounterLag", err)
	}
	// The index write itself must still have taken effect (Part C5's
	// crash-window semantics): the in-memory committed state already
	// reflects the new epoch even though Increment failed.
	epoch, err := s.Current("prod-db")
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if epoch != 5 {
		t.Fatalf("epoch = %d, want 5 (the index write durably succeeded despite the counter failure)", epoch)
	}
}

func TestGet_DecodeFailureMarksTampered(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	notJSON := []byte("this is not json at all")
	digest, err := s.writeBlobIfMissing(notJSON)
	if err != nil {
		t.Fatalf("writeBlobIfMissing: %v", err)
	}
	s.committed.LKG["prod-db"] = lkgEntry{BlobDigest: digest, Mode: "enforce"}

	if _, ok := s.Get("prod-db"); ok {
		t.Fatalf("Get with an undecodable blob: ok = true")
	}
	if !errors.Is(s.Tampered(), ErrTampered) {
		t.Fatalf("Tampered() = %v, want ErrTampered", s.Tampered())
	}
}

func TestCloneCommitted_CopiesExistingLKGEntries(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Put("domain-a", apply.LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put domain-a: %v", err)
	}
	if err := s.Put("domain-b", apply.LKGSet{Mode: "monitor"}); err != nil {
		t.Fatalf("Put domain-b: %v", err)
	}
	a, ok := s.Get("domain-a")
	if !ok || a.Mode != "enforce" {
		t.Fatalf("Get domain-a = (%+v, %v), want (enforce, true) -- it must survive domain-b's later commit", a, ok)
	}
}

func TestWriteIndexFile_TooLargeAfterLimitsPass(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	next := s.cloneCommitted()
	// Within every per-field cardinality limit individually, but their
	// product exceeds MaxStoreIndexBytes: 50 scopes (< MaxStoreScopes)
	// each with MaxStoreHistoryNamesPerScope long names.
	for i := 0; i < 50; i++ {
		names := make([]string, limits.MaxStoreHistoryNamesPerScope)
		for j := range names {
			names[j] = strings.Repeat("a", 60) + strconv.Itoa(j)
		}
		next.History["scope"+strconv.Itoa(i)] = names
	}
	if err := s.commitLocked(next); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

func TestOpen_PathIsAFileNotADirectory(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := Open(path, newTestSealer(), NewFakeMonotonicCounter()); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func TestOpen_BlobsPathIsAFileNotADirectory(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, "blobs"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter()); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func TestOpen_CounterUnavailableOnReopen(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	counter := NewFakeMonotonicCounter()
	s, err := Open(dir, newTestSealer(), counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := Open(dir, newTestSealer(), &failingCounter{err: errCounterBroken}); !errors.Is(err, ErrCounterUnavailable) {
		t.Fatalf("err = %v, want ErrCounterUnavailable", err)
	}
}

func TestLoadAndValidateIndex_GenerationZeroIsTampered(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	sealer := newTestSealer()
	counter := NewFakeMonotonicCounter()
	s, err := Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key, _ := sealer.Unseal()
	payload := indexPayload{Schema: indexSchema, Generation: 0, Epochs: map[string]uint64{}, History: map[string][]string{}, LKG: map[string]lkgEntry{}}
	mac, err := computeHMAC(key, payload)
	if err != nil {
		t.Fatalf("computeHMAC: %v", err)
	}
	if _, err := s.loadAndValidateIndex(mustMarshalIndexFile(t, indexFile{Payload: payload, HMAC: mac})); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
	_ = s.Close()
}

func TestLoadAndValidateIndex_TotalBlobBytesExceeded(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	sealer := newTestSealer()
	counter := NewFakeMonotonicCounter()
	s, err := Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Write enough blobs, each just under the per-blob cap, that their
	// sum exceeds the total cap, and reference every one from a
	// hand-built index (one per domain, so Part C8's per-domain count
	// cap is not what trips first).
	numBlobs := int(limits.MaxStoreTotalBlobBytes/limits.MaxStoreBlobBytes) + 2
	chunk := make([]byte, limits.MaxStoreBlobBytes-1)
	lkg := make(map[string]lkgEntry, numBlobs)
	for i := 0; i < numBlobs; i++ {
		chunk[0] = byte(i) // vary content so each blob has a distinct digest
		d, err := s.writeBlobIfMissing(chunk)
		if err != nil {
			t.Fatalf("writeBlobIfMissing: %v", err)
		}
		lkg["domain-"+strconv.Itoa(i)] = lkgEntry{BlobDigest: d, Mode: "enforce"}
	}
	payload := indexPayload{
		Schema: indexSchema, Generation: 1,
		Epochs: map[string]uint64{}, History: map[string][]string{},
		LKG: lkg,
	}
	key, _ := sealer.Unseal()
	mac, err := computeHMAC(key, payload)
	if err != nil {
		t.Fatalf("computeHMAC: %v", err)
	}
	if _, err := s.loadAndValidateIndex(mustMarshalIndexFile(t, indexFile{Payload: payload, HMAC: mac})); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

func TestCommitLocked_LimitExceededViaRecordMonitorNames(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	names := make([]string, limits.MaxStoreHistoryNamesPerScope+1)
	for i := range names {
		names[i] = "name" + strconv.Itoa(i)
	}
	if err := s.RecordMonitorNames("prod-db", names); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

// flakySealer fails Unseal on every call after the first N, so a write's
// SECOND Unseal call (writeIndexFile's own, distinct from Open's one-time
// validation call) can be made to fail independently.
type flakySealer struct {
	key       []byte
	failAfter int
	calls     int
}

func (f *flakySealer) Unseal() ([]byte, error) {
	f.calls++
	if f.calls > f.failAfter {
		return nil, errSealerBroken
	}
	return f.key, nil
}

var errSealerBroken = errors.New("sealer broken")

func TestWriteIndexFile_SealerFailsDuringWrite(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	sealer := &flakySealer{key: []byte("k"), failAfter: 1} // succeeds once (Open's validation is skipped at first boot, but firstBoot's own commitLocked->writeIndexFile call is the first Unseal)
	s, err := Open(dir, sealer, NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.RecordEpoch("prod-db", 1); !errors.Is(err, ErrSealerUnavailable) {
		t.Fatalf("err = %v, want ErrSealerUnavailable", err)
	}
}

func mustMarshalIndexFile(t *testing.T, idx indexFile) []byte {
	t.Helper()
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal index file: %v", err)
	}
	return b
}

// ADR 0035: a persisted revoked marker is validated on load too.
func TestVerifyIndexLimits_RevokedMarker(t *testing.T) {
	base := func() indexPayload {
		return indexPayload{Schema: indexSchema, Generation: 1, Epochs: map[string]uint64{}, History: map[string][]string{}, LKG: map[string]lkgEntry{}}
	}
	p := base()
	p.Revoked = &revokedMarker{Reason: "x"}
	if err := verifyIndexLimits(p); !errors.Is(err, ErrTampered) {
		t.Fatalf("zero-time marker: %v, want ErrTampered", err)
	}
	p = base()
	p.Revoked = &revokedMarker{At: time.Unix(1, 0), Reason: strings.Repeat("a", limits.MaxRevokedReasonBytes+1)}
	if err := verifyIndexLimits(p); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("long reason: %v, want ErrLimitExceeded", err)
	}
	p = base()
	p.Revoked = &revokedMarker{At: time.Unix(1, 0), Reason: "ok"}
	if err := verifyIndexLimits(p); err != nil {
		t.Fatalf("valid marker: %v", err)
	}
}
