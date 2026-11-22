package trust_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/testvectors"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

// FuzzRootUpdate seeds from the real committed root-metadata vectors (both
// trust_load and trust_update kinds, which between them cover valid and
// several kinds of invalid root metadata) and asserts that neither
// LoadInitialRoot nor Update ever panics, on any mutation of either the
// initial or candidate root bytes.
func FuzzRootUpdate(f *testing.F) {
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		f.Fatalf("load vectors: %v", err)
	}
	seeded := 0
	for _, v := range vectors {
		if v.RootMetadataB64 != "" {
			b := mustB64DecodeFuzz(f, v.RootMetadataB64)
			newB := []byte(nil)
			if v.NewRootMetadataB64 != "" {
				newB = mustB64DecodeFuzz(f, v.NewRootMetadataB64)
			}
			f.Add(b, newB)
			seeded++
		}
	}
	if seeded == 0 {
		f.Fatalf("no seed corpus found in %s", vectorsDir)
	}

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, initial, candidate []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v (initial=%q candidate=%q)", r, initial, candidate)
			}
		}()
		root, err := trust.LoadInitialRoot(initial)
		if err != nil {
			return
		}
		if len(candidate) == 0 {
			return
		}
		_, _ = root.Update(candidate, now)
	})
}

func mustB64DecodeFuzz(f *testing.F, s string) []byte {
	f.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		f.Fatalf("decode base64: %v", err)
	}
	return b
}
