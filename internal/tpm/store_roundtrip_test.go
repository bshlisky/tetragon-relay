package tpm

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
)

// This file is docs/prompts/step-05a.md D1's required "store round-trip
// that uses the real sealer and counter across a simulated restart": a
// genuine internal/store.Store, opened against *tpm.KeySealer and
// *tpm.Counter backed by a real (software) TPM, not internal/store's own
// FakeKeySealer/FakeMonotonicCounter. A "restart" is simulated by closing
// the store and reopening it with FRESH KeySealer/Counter instances
// against the SAME swtpm connection (the same TPM state), exactly as a
// real agent restart would reconnect to the same physical TPM.

func TestStoreRoundTrip_RealSealerAndCounterSurviveSimulatedRestart(t *testing.T) {
	tt := startSWTPM(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	blobPath := filepath.Join(dir, "sealed-hmac-key.json")
	counterHandle := testCounterHandle

	if _, err := ProvisionSRK(tt, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	if err := ProvisionCounter(tt, counterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}

	openStore := func() *store.Store {
		t.Helper()
		sealer, err := NewKeySealer(tt, blobPath)
		if err != nil {
			t.Fatalf("NewKeySealer: %v", err)
		}
		counter, err := OpenCounter(tt, counterHandle)
		if err != nil {
			t.Fatalf("OpenCounter: %v", err)
		}
		st, err := store.Open(dir, sealer, counter)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		return st
	}

	st := openStore()
	if !st.FirstBoot() {
		t.Fatalf("FirstBoot() = false on a fresh store directory")
	}
	rootRaw := []byte("fake-root-metadata-bytes-for-store-roundtrip-test")
	if err := st.PersistTrustRoot(rootRaw, 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	if err := st.RecordEpoch("prod-db", 5); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}
	if err := st.Put(apply.RelayDomain, apply.LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	genBefore := st.Generation()
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Simulated restart: fresh KeySealer/Counter instances (as a
	// freshly-exec'd relayd process would construct), same TPM, same
	// store directory.
	st2 := openStore()
	defer func() { _ = st2.Close() }()
	if st2.FirstBoot() {
		t.Fatalf("FirstBoot() = true after a restart; the real sealer/counter did not actually persist state")
	}
	if st2.Generation() != genBefore {
		t.Fatalf("Generation() = %d after restart, want %d", st2.Generation(), genBefore)
	}
	gotRoot, version, ok, err := st2.TrustRoot()
	if err != nil {
		t.Fatalf("TrustRoot: %v", err)
	}
	if !ok || version != 1 || !bytes.Equal(gotRoot, rootRaw) {
		t.Fatalf("TrustRoot after restart = (%q, %d, %v), want (%q, 1, true)", gotRoot, version, ok, rootRaw)
	}
	epoch, err := st2.Current("prod-db")
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if epoch != 5 {
		t.Fatalf("Current(\"prod-db\") after restart = %d, want 5", epoch)
	}
	if _, ok := st2.Get(apply.RelayDomain); !ok {
		t.Fatalf("Get(RelayDomain) after restart: ok = false")
	}
}

func TestStoreRoundTrip_RollbackOfOlderCopyIsDetectedViaRealCounter(t *testing.T) {
	tt := startSWTPM(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	blobPath := filepath.Join(dir, "sealed-hmac-key.json")
	counterHandle := testCounterHandle
	if _, err := ProvisionSRK(tt, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	if err := ProvisionCounter(tt, counterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}

	sealer, err := NewKeySealer(tt, blobPath)
	if err != nil {
		t.Fatalf("NewKeySealer: %v", err)
	}
	counter, err := OpenCounter(tt, counterHandle)
	if err != nil {
		t.Fatalf("OpenCounter: %v", err)
	}
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.RecordEpoch("prod-db", 1); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Snapshot the store directory (simulating an attacker's offline
	// backup of an earlier, valid generation) before any further writes.
	backupDir := t.TempDir()
	if err := copyDirForTest(t, dir, backupDir); err != nil {
		t.Fatalf("copyDirForTest: %v", err)
	}

	// Advance the real store (new generation, counter incremented for
	// real on the TPM).
	sealer2, err := NewKeySealer(tt, blobPath)
	if err != nil {
		t.Fatalf("NewKeySealer (2nd open): %v", err)
	}
	counter2, err := OpenCounter(tt, counterHandle)
	if err != nil {
		t.Fatalf("OpenCounter (2nd open): %v", err)
	}
	st2, err := store.Open(dir, sealer2, counter2)
	if err != nil {
		t.Fatalf("store.Open (2nd open): %v", err)
	}
	if err := st2.RecordEpoch("prod-db", 2); err != nil {
		t.Fatalf("RecordEpoch (advance): %v", err)
	}
	if err := st2.Close(); err != nil {
		t.Fatalf("Close (2nd): %v", err)
	}

	// Restore the OLDER backup over the current (now-advanced) store
	// directory: the TPM counter has moved on past what this restored
	// index claims, which must be detected as tamper -- the real point
	// of the TPM NV counter, proven here against a real TPM rather than
	// FakeMonotonicCounter.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := copyDirForTest(t, backupDir, dir); err != nil {
		t.Fatalf("restore backup: %v", err)
	}
	sealer3, err := NewKeySealer(tt, blobPath)
	if err != nil {
		t.Fatalf("NewKeySealer (3rd open): %v", err)
	}
	counter3, err := OpenCounter(tt, counterHandle)
	if err != nil {
		t.Fatalf("OpenCounter (3rd open): %v", err)
	}
	if _, err := store.Open(dir, sealer3, counter3); err == nil {
		t.Fatalf("store.Open on a restored older backup unexpectedly succeeded (rollback not detected)")
	}
}

func copyDirForTest(t *testing.T, src, dst string) error {
	t.Helper()
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: test helper copying a t.TempDir() tree
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode())
	})
}
