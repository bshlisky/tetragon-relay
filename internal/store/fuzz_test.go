package store

import (
	"encoding/json"
	"os"
	"testing"
)

// FuzzStoreIndex is step-04b.md Part E5: a fuzz target for the index JSON
// parser (decodeIndexFile), which is the first thing this package ever
// does with an on-disk index file's bytes -- untrusted until the HMAC
// check (loadAndValidateIndex, which runs after decodeIndexFile) has run.
// It asserts only that decodeIndexFile never panics on any input; it is
// not a correctness oracle (store_test.go/tamper_test.go/coverage_test.go
// already cover decodeIndexFile's and loadAndValidateIndex's behavior on
// specific, hand-built inputs).
func FuzzStoreIndex(f *testing.F) {
	// Seed from real index files this package itself produces (every
	// field populated, including the new ADR 0025 TrustRootHistory map),
	// plus a handful of small, hand-built or malformed variants.
	f.Add(mustMarshalRealIndexFileForFuzz(f))
	f.Add([]byte(`{"payload":{"schema":"relay.store.index.v1","generation":1,"epochs":{},"history":{},"lkg":{}},"hmac":"00"}`))
	f.Add([]byte(`{"payload":{"schema":"wrong","generation":1,"epochs":{},"history":{},"lkg":{}},"hmac":"ab"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(``))
	f.Add([]byte(`{"payload":{"schema":"relay.store.index.v1","generation":0,"epochs":{"a":1},"history":{"b":["c","d"]},"lkg":{"d":{"blob_digest":"x","mode":"enforce","root_version":1}},"trust_root":{"version":1,"blob_digest":"y"},"trust_root_history":{"1":{"version":1,"blob_digest":"y"}}},"hmac":"deadbeef"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v (raw=%q)", r, raw)
			}
		}()
		_, _ = decodeIndexFile(raw)
	})
}

// mustMarshalRealIndexFileForFuzz builds and marshals a real indexFile
// (via a live Store, so it carries a real HMAC and every field this
// package's own write paths actually populate) for FuzzStoreIndex's seed
// corpus.
func mustMarshalRealIndexFileForFuzz(f *testing.F) []byte {
	f.Helper()
	dir := f.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		f.Fatalf("chmod: %v", err)
	}
	s, err := Open(dir, newTestSealer(), NewFakeMonotonicCounter())
	if err != nil {
		f.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.RecordEpoch("prod-db", 5); err != nil {
		f.Fatalf("RecordEpoch: %v", err)
	}
	if err := s.PersistTrustRoot([]byte("root-bytes"), 1); err != nil {
		f.Fatalf("PersistTrustRoot: %v", err)
	}
	raw, err := s.fs.ReadFile(dir + "/index")
	if err != nil {
		f.Fatalf("read real index file: %v", err)
	}
	// Round-trip through json to confirm it is itself valid JSON before
	// handing it to the fuzzer as a seed (defense in depth; it always
	// will be, since this package wrote it).
	var probe json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		f.Fatalf("real index file is not valid JSON: %v", err)
	}
	return raw
}
