package store_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
)

// Part E2: each of these must end in ErrTampered from Open, never in
// first-boot initialization.

func setupTamperable(t *testing.T) (dir string, sealer *store.FakeKeySealer, counter *store.FakeMonotonicCounter) {
	t.Helper()
	dir = t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer = &store.FakeKeySealer{Key: []byte("test-hmac-key-0123456789abcdef")}
	counter = store.NewFakeMonotonicCounter()
	s, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RecordEpoch("prod-db", 1); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}
	if err := s.PersistTrustRoot([]byte("root-bytes"), 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	if err := s.Put("prod-db", apply.LKGSet{Mode: "enforce", Policies: []apply.LKGPolicy{
		{Name: "block-shadow-read", Version: 1, CanonicalJSON: []byte(`{"name":"block-shadow-read"}`)},
	}}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return dir, sealer, counter
}

func reopenExpectTampered(t *testing.T, dir string, sealer *store.FakeKeySealer, counter *store.FakeMonotonicCounter) {
	t.Helper()
	s, err := store.Open(dir, sealer, counter)
	if err == nil {
		s.Close()
		t.Fatalf("Open succeeded, want ErrTampered")
	}
	if !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

func readIndexBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "index"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	return b
}

func writeIndexBytes(t *testing.T, dir string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "index"), b, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
}

func TestTamper_FlipByteInIndex(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	raw := readIndexBytes(t, dir)
	raw[len(raw)/2] ^= 0xFF
	writeIndexBytes(t, dir, raw)
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestTamper_FlipByteInEachBlob(t *testing.T) {
	dir, _, _ := setupTamperable(t)
	blobsDir := filepath.Join(dir, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if err != nil {
		t.Fatalf("read blobs dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected at least one blob (LKG or trust root)")
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			dir2, sealer2, counter2 := setupTamperable(t)
			path := filepath.Join(dir2, "blobs", e.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read blob: %v", err)
			}
			b[0] ^= 0xFF
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatalf("write blob: %v", err)
			}
			reopenExpectTampered(t, dir2, sealer2, counter2)
		})
	}
}

func TestTamper_DeleteABlob(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	blobsDir := filepath.Join(dir, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("read blobs dir: %v (entries=%d)", err, len(entries))
	}
	if err := os.Remove(filepath.Join(blobsDir, entries[0].Name())); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestTamper_RestoreOlderIndexAndBlobs_Rollback(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	sealer := &store.FakeKeySealer{Key: []byte("test-hmac-key-0123456789abcdef")}
	counter := store.NewFakeMonotonicCounter()

	s, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.RecordEpoch("prod-db", 1); err != nil {
		t.Fatalf("RecordEpoch 1: %v", err)
	}
	oldIndex := readIndexBytes(t, dir)
	oldBlobs := snapshotBlobs(t, dir)

	if err := s.RecordEpoch("prod-db", 2); err != nil {
		t.Fatalf("RecordEpoch 2: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Restore the OLD index and blobs (a backup taken before the second
	// write), simulating an attacker (or a bad restore procedure)
	// reverting the directory to an earlier, validly-HMAC'd generation.
	// The counter (mirrored outside the directory, e.g. a TPM NV
	// counter) still reflects the later generation, so this must be
	// detected as a rollback.
	writeIndexBytes(t, dir, oldIndex)
	restoreBlobs(t, dir, oldBlobs)

	reopenExpectTampered(t, dir, sealer, counter)
}

func snapshotBlobs(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("read blobs: %v", err)
	}
	snap := make(map[string][]byte, len(entries))
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, "blobs", e.Name()))
		if err != nil {
			t.Fatalf("read blob %s: %v", e.Name(), err)
		}
		snap[e.Name()] = b
	}
	return snap
}

func restoreBlobs(t *testing.T, dir string, snap map[string][]byte) {
	t.Helper()
	blobsDir := filepath.Join(dir, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if err != nil {
		t.Fatalf("read blobs: %v", err)
	}
	// Remove anything the snapshot doesn't have (written after the
	// snapshot was taken).
	for _, e := range entries {
		if _, ok := snap[e.Name()]; !ok {
			os.Remove(filepath.Join(blobsDir, e.Name()))
		}
	}
	for name, b := range snap {
		if err := os.WriteFile(filepath.Join(blobsDir, name), b, 0o600); err != nil {
			t.Fatalf("restore blob %s: %v", name, err)
		}
	}
}

func TestTamper_WrongDirectoryPermissions(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestTamper_WrongIndexFilePermissions(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	if err := os.Chmod(filepath.Join(dir, "index"), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestTamper_SymlinkInsteadOfDirectory(t *testing.T) {
	realDir := t.TempDir()
	os.Chmod(realDir, 0o700)
	sealer := &store.FakeKeySealer{Key: []byte("k")}
	counter := store.NewFakeMonotonicCounter()
	s, err := store.Open(realDir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Close()

	parent := t.TempDir()
	linkPath := filepath.Join(parent, "store-link")
	if err := os.Symlink(realDir, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	reopenExpectTampered(t, linkPath, sealer, counter)
}

func TestTamper_SymlinkInsteadOfIndexFile(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	indexPath := filepath.Join(dir, "index")
	target := filepath.Join(dir, "index-target")
	if err := os.Rename(indexPath, target); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.Symlink(target, indexPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestTamper_IndexGenerationAheadByTwo(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	counter.Set(mustCounterValue(t, counter) - 2) // simulate the counter falling behind by 2
	reopenExpectTampered(t, dir, sealer, counter)
}

func mustCounterValue(t *testing.T, c *store.FakeMonotonicCounter) uint64 {
	t.Helper()
	v, err := c.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return v
}

func TestTamper_UnreadableIndex(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	if err := os.Chmod(filepath.Join(dir, "index"), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Restore read access to the directory itself (needed by Lstat) but
	// not the index file. On a process not running as root,
	// os.ReadFile on a 0000 file fails with permission denied.
	if os.Getuid() == 0 {
		t.Skip("running as root: permission bits on the index file are not enforced")
	}
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestTamper_UnparseableIndex(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	writeIndexBytes(t, dir, []byte("not json at all"))
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestTamper_IndexWithWrongSchema(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	raw := readIndexBytes(t, dir)
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(generic["payload"], &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	payload["schema"] = json.RawMessage(`"not-the-real-schema"`)
	pb, _ := json.Marshal(payload)
	generic["payload"] = pb
	b, _ := json.Marshal(generic)
	writeIndexBytes(t, dir, b)
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestTamper_SealerUnavailableIsNotTamperedButIsDistinctError(t *testing.T) {
	dir, _, counter := setupTamperable(t)
	failingSealer := &store.FakeKeySealer{Err: errFakeSealUnavailable}
	_, err := store.Open(dir, failingSealer, counter)
	if !errors.Is(err, store.ErrSealerUnavailable) {
		t.Fatalf("err = %v, want ErrSealerUnavailable", err)
	}
	if errors.Is(err, store.ErrTampered) {
		t.Fatalf("a sealer failure must not be reported as ErrTampered")
	}
}

var errFakeSealUnavailable = errors.New("tpm not ready")
