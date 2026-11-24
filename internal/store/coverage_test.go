package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

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
	defer s.Close()
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
	defer s.Close()
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
	os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	big := make([]byte, limits.MaxStoreBlobBytes+1)
	if _, err := s.writeBlobIfMissing(big); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
}

func TestReadBlob_TooLargeOnDisk(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
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
	os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := os.RemoveAll(filepath.Join(dir, "blobs")); err != nil {
		t.Fatalf("remove blobs dir: %v", err)
	}
	// Must not panic even though blobs/ is gone.
	s.gcBlobs(map[string]struct{}{})
}

func TestOpen_CounterUnavailableAtFirstBoot(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	failing := &failingCounter{err: errCounterBroken}
	if _, err := Open(dir, newTestSealer(), failing); !errors.Is(err, ErrCounterUnavailable) {
		t.Fatalf("err = %v, want ErrCounterUnavailable", err)
	}
}

func TestOpen_FirstBootWithNonzeroCounterIsTampered(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
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
	os.Chmod(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, "blobs"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter()); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func TestOpen_CounterUnavailableOnReopen(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
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
	os.Chmod(dir, 0o700)
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
	s.Close()
}

func TestLoadAndValidateIndex_TotalBlobBytesExceeded(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	sealer := newTestSealer()
	counter := NewFakeMonotonicCounter()
	s, err := Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

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
	os.Chmod(dir, 0o700)
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
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
	os.Chmod(dir, 0o700)
	sealer := &flakySealer{key: []byte("k"), failAfter: 1} // succeeds once (Open's validation is skipped at first boot, but firstBoot's own commitLocked->writeIndexFile call is the first Unseal)
	s, err := Open(dir, sealer, NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
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
