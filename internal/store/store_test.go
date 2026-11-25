package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
)

func newTestStore(t *testing.T) (*store.Store, string, *store.FakeMonotonicCounter) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("test-hmac-key-0123456789abcdef")}
	counter := store.NewFakeMonotonicCounter()
	s, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir, counter
}

func TestOpen_FirstBoot(t *testing.T) {
	s, _, _ := newTestStore(t)
	if !s.FirstBoot() {
		t.Fatalf("FirstBoot() = false, want true on an empty directory")
	}
	if g := s.Generation(); g != 1 {
		t.Fatalf("Generation() = %d, want 1", g)
	}
	if err := s.Tampered(); err != nil {
		t.Fatalf("Tampered() = %v, want nil", err)
	}
}

func TestOpen_ReopenIsNotFirstBoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("test-hmac-key-0123456789abcdef")}
	counter := store.NewFakeMonotonicCounter()

	s1, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if s2.FirstBoot() {
		t.Fatalf("FirstBoot() = true on a re-open, want false")
	}
}

func TestEpoch_RoundTripsAndPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	sealer := &store.FakeKeySealer{Key: []byte("test-hmac-key-0123456789abcdef")}
	counter := store.NewFakeMonotonicCounter()

	s1, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if e, err := s1.Current("prod-db"); err != nil || e != 0 {
		t.Fatalf("Current (unseen scope) = (%d, %v), want (0, nil)", e, err)
	}
	if err := s1.RecordEpoch("prod-db", 10); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}
	if e, err := s1.Current("prod-db"); err != nil || e != 10 {
		t.Fatalf("Current = (%d, %v), want (10, nil)", e, err)
	}
	// A non-increasing epoch must be rejected.
	if err := s1.RecordEpoch("prod-db", 10); err == nil {
		t.Fatalf("RecordEpoch with an equal epoch should have failed")
	}
	if err := s1.RecordEpoch("prod-db", 5); err == nil {
		t.Fatalf("RecordEpoch with a lower epoch should have failed")
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if e, err := s2.Current("prod-db"); err != nil || e != 10 {
		t.Fatalf("Current after reopen = (%d, %v), want (10, nil)", e, err)
	}
}

func TestPolicyHistory_RoundTrips(t *testing.T) {
	s, _, _ := newTestStore(t)
	if seen, err := s.SeenInMonitor("prod-db", "block-shadow-read"); err != nil || seen {
		t.Fatalf("SeenInMonitor before recording = (%v, %v), want (false, nil)", seen, err)
	}
	if err := s.RecordMonitorNames("prod-db", []string{"block-shadow-read", "another-policy"}); err != nil {
		t.Fatalf("RecordMonitorNames: %v", err)
	}
	if seen, err := s.SeenInMonitor("prod-db", "block-shadow-read"); err != nil || !seen {
		t.Fatalf("SeenInMonitor = (%v, %v), want (true, nil)", seen, err)
	}
	if seen, _ := s.SeenInMonitor("prod-db", "never-seen"); seen {
		t.Fatalf("SeenInMonitor(never-seen) = true, want false")
	}
	if seen, _ := s.SeenInMonitor("other-scope", "block-shadow-read"); seen {
		t.Fatalf("SeenInMonitor must be scoped: got true for a different scope")
	}
	// Recording the same names again must be a no-op, not an error and
	// not a duplicate.
	if err := s.RecordMonitorNames("prod-db", []string{"block-shadow-read"}); err != nil {
		t.Fatalf("RecordMonitorNames (duplicate): %v", err)
	}
}

func TestLKGStore_RoundTrips(t *testing.T) {
	s, _, _ := newTestStore(t)
	if _, ok := s.Get("prod-db"); ok {
		t.Fatalf("Get on an empty store returned ok=true")
	}
	set := apply.LKGSet{
		Mode: "enforce",
		Policies: []apply.LKGPolicy{
			{Name: "block-shadow-read", Version: 7, CanonicalJSON: []byte(`{"name":"block-shadow-read"}`)},
		},
	}
	if err := s.Put("prod-db", set); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Get("prod-db")
	if !ok {
		t.Fatalf("Get after Put: ok = false")
	}
	if got.Mode != "enforce" || len(got.Policies) != 1 || got.Policies[0].Name != "block-shadow-read" || got.Policies[0].Version != 7 {
		t.Fatalf("Get returned %+v, want a round trip of the Put value", got)
	}
	if string(got.Policies[0].CanonicalJSON) != `{"name":"block-shadow-read"}` {
		t.Fatalf("CanonicalJSON = %q, want round trip", got.Policies[0].CanonicalJSON)
	}
}

func TestRootHistory_RetainedWhileReferencedThenGarbageCollected(t *testing.T) {
	// ADR 0025 (step-04b-review.md R4B-2): a root rotation does not
	// retroactively re-verify every domain's existing LKG, so an old
	// root version's blob must stay retrievable (via RootAtVersion) for
	// as long as any LKG.RootVersion still references it, and be
	// garbage-collected once nothing does.
	s, _, _ := newTestStore(t)

	if err := s.PersistTrustRoot([]byte("root-v1-bytes"), 1); err != nil {
		t.Fatalf("PersistTrustRoot v1: %v", err)
	}
	if err := s.Put("domain-a", apply.LKGSet{Mode: "enforce", RawEnvelope: []byte("envelope-v1"), RootVersion: 1}); err != nil {
		t.Fatalf("Put (root version 1): %v", err)
	}

	if err := s.PersistTrustRoot([]byte("root-v2-bytes"), 2); err != nil {
		t.Fatalf("PersistTrustRoot v2: %v", err)
	}

	// Still referenced by domain-a's LKG: must still be retrievable even
	// though it is no longer the current root.
	raw, ok, err := s.RootAtVersion(1)
	if err != nil || !ok || string(raw) != "root-v1-bytes" {
		t.Fatalf("RootAtVersion(1) = (%q, ok=%v, err=%v), want (root-v1-bytes, true, nil) while still referenced", raw, ok, err)
	}
	raw2, ok2, err2 := s.RootAtVersion(2)
	if err2 != nil || !ok2 || string(raw2) != "root-v2-bytes" {
		t.Fatalf("RootAtVersion(2) = (%q, ok=%v, err=%v), want (root-v2-bytes, true, nil)", raw2, ok2, err2)
	}

	// Re-apply domain-a's LKG under the new root version: nothing
	// references version 1 anymore.
	if err := s.Put("domain-a", apply.LKGSet{Mode: "enforce", RawEnvelope: []byte("envelope-v2"), RootVersion: 2}); err != nil {
		t.Fatalf("Put (root version 2): %v", err)
	}
	if _, ok, err := s.RootAtVersion(1); err != nil || ok {
		t.Fatalf("RootAtVersion(1) after nothing references it = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

func TestDomains_ListsEveryPersistedDomain(t *testing.T) {
	s, _, _ := newTestStore(t)
	if domains, err := s.Domains(); err != nil || len(domains) != 0 {
		t.Fatalf("Domains on an empty store = (%v, %v), want (empty, nil)", domains, err)
	}
	if err := s.Put("domain-a", apply.LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put domain-a: %v", err)
	}
	if err := s.Put("domain-b", apply.LKGSet{Mode: "monitor"}); err != nil {
		t.Fatalf("Put domain-b: %v", err)
	}
	domains, err := s.Domains()
	if err != nil {
		t.Fatalf("Domains: %v", err)
	}
	seen := map[string]bool{}
	for _, d := range domains {
		seen[d] = true
	}
	if !seen["domain-a"] || !seen["domain-b"] || len(domains) != 2 {
		t.Fatalf("Domains = %v, want exactly [domain-a domain-b]", domains)
	}
}

func TestRootAtVersion_NotFoundAndClosed(t *testing.T) {
	s, _, _ := newTestStore(t)
	if _, ok, err := s.RootAtVersion(1); err != nil || ok {
		t.Fatalf("RootAtVersion(1) on an empty store = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if err := s.PersistTrustRoot([]byte("root-bytes"), 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	if raw, ok, err := s.RootAtVersion(1); err != nil || !ok || string(raw) != "root-bytes" {
		t.Fatalf("RootAtVersion(1) = (%q, ok=%v, err=%v), want (root-bytes, true, nil)", raw, ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, err := s.RootAtVersion(1); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("RootAtVersion after Close: err = %v, want ErrClosed", err)
	}
	if _, err := s.Domains(); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("Domains after Close: err = %v, want ErrClosed", err)
	}
}

func TestTrustRoot_PersistAndDowngradeProtection(t *testing.T) {
	s, _, _ := newTestStore(t)
	if _, _, ok, err := s.TrustRoot(); err != nil || ok {
		t.Fatalf("TrustRoot on an empty store = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if err := s.PersistTrustRoot([]byte("root-v1-bytes"), 1); err != nil {
		t.Fatalf("PersistTrustRoot v1: %v", err)
	}
	raw, version, ok, err := s.TrustRoot()
	if err != nil || !ok || version != 1 || string(raw) != "root-v1-bytes" {
		t.Fatalf("TrustRoot = (%q, %d, %v, %v), want (root-v1-bytes, 1, true, nil)", raw, version, ok, err)
	}
	if err := s.PersistTrustRoot([]byte("root-v2-bytes"), 2); err != nil {
		t.Fatalf("PersistTrustRoot v2: %v", err)
	}
	// A downgrade (equal or lower version) must be rejected and the
	// persisted root left untouched.
	if err := s.PersistTrustRoot([]byte("root-v1-again"), 1); !errors.Is(err, store.ErrRootDowngrade) {
		t.Fatalf("PersistTrustRoot with version 1 after 2: err = %v, want ErrRootDowngrade", err)
	}
	if err := s.PersistTrustRoot([]byte("root-v2-again"), 2); !errors.Is(err, store.ErrRootDowngrade) {
		t.Fatalf("PersistTrustRoot with an equal version: err = %v, want ErrRootDowngrade", err)
	}
	raw, version, ok, err = s.TrustRoot()
	if err != nil || !ok || version != 2 || string(raw) != "root-v2-bytes" {
		t.Fatalf("TrustRoot after rejected downgrades = (%q, %d, %v, %v), want (root-v2-bytes, 2, true, nil)", raw, version, ok, err)
	}
}

func TestOpen_AlreadyOpenByAnotherHandle(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	sealer := &store.FakeKeySealer{Key: []byte("k")}
	counter := store.NewFakeMonotonicCounter()
	s1, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	defer func() { _ = s1.Close() }()

	if _, err := store.Open(dir, sealer, store.NewFakeMonotonicCounter()); !errors.Is(err, store.ErrAlreadyOpen) {
		t.Fatalf("second concurrent Open: err = %v, want ErrAlreadyOpen", err)
	}
}

func TestOpen_WrongDirectoryMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("k")}
	counter := store.NewFakeMonotonicCounter()
	if _, err := store.Open(dir, sealer, counter); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("Open with mode 0755: err = %v, want ErrTampered", err)
	}
}

func TestClosed_EveryMethodReturnsErrClosed(t *testing.T) {
	s, _, _ := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := s.Current("x"); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("Current after Close: err = %v, want ErrClosed", err)
	}
	if err := s.RecordEpoch("x", 1); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("RecordEpoch after Close: err = %v, want ErrClosed", err)
	}
	if _, err := s.SeenInMonitor("x", "y"); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("SeenInMonitor after Close: err = %v, want ErrClosed", err)
	}
	if _, ok := s.Get("x"); ok {
		t.Fatalf("Get after Close: ok = true")
	}
	if err := s.Put("x", apply.LKGSet{}); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("Put after Close: err = %v, want ErrClosed", err)
	}
	if err := s.RecordMonitorNames("x", []string{"y"}); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("RecordMonitorNames after Close: err = %v, want ErrClosed", err)
	}
	if _, _, _, err := s.TrustRoot(); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("TrustRoot after Close: err = %v, want ErrClosed", err)
	}
	if err := s.PersistTrustRoot([]byte("x"), 1); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("PersistTrustRoot after Close: err = %v, want ErrClosed", err)
	}
	// Closing twice must not panic or error.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestIndexFilePermissionsOnDisk(t *testing.T) {
	s, dir, _ := newTestStore(t)
	if err := s.RecordEpoch("prod-db", 1); err != nil {
		t.Fatalf("RecordEpoch: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "index"))
	if err != nil {
		t.Fatalf("stat index: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("index mode = %o, want 0600", fi.Mode().Perm())
	}
	blobs, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("read blobs dir: %v", err)
	}
	for _, b := range blobs {
		info, err := b.Info()
		if err != nil {
			t.Fatalf("blob info: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("blob %s mode = %o, want 0600", b.Name(), info.Mode().Perm())
		}
	}
}
