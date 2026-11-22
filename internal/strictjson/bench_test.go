//go:build !race

// The -race detector's per-operation instrumentation overhead makes a
// wall-clock performance budget meaningless under it (see
// internal/verify/bench_test.go for the same reasoning); Go's toolchain
// sets the "race" build tag automatically when -race is passed, so this
// file is simply excluded from race-enabled test runs.

package strictjson

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// worstCaseKeysObject builds a ~1 MiB JSON object at exactly
// limits.MaxKeysPerObject keys (the maximum this package will validate),
// each key unique and each value padded so the whole object is close to 1
// MiB. This is the worst case step 1 review A11 asks to be bounded: before
// the fix, validateKeys' duplicate-key check was O(n^2) in the number of
// keys per object (a 256 KiB object with ~30k keys took ~1.8s; 1 MiB took
// ~28s). With the fold-key map fix, cost is dominated by MaxKeysPerObject
// (4096), not by how many bytes of padding surround it.
func worstCaseKeysObject() []byte {
	const target = 1 << 20
	n := limits.MaxKeysPerObject
	// Budget per entry so the whole object lands close to target bytes.
	perEntry := target/n - 20 // minus room for `"k000000":"...",`
	if perEntry < 0 {
		perEntry = 0
	}
	pad := strings.Repeat("x", perEntry)
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf(`"k%06d":%q`, i, pad))
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

// TestDecodeStrict_WorstCaseKeysPerformance is the step 1 review's A11
// requirement: a ~1 MiB object at the maximum key count must validate in
// under 50ms.
func TestDecodeStrict_WorstCaseKeysPerformance(t *testing.T) {
	data := worstCaseKeysObject()
	t.Logf("worst-case object size: %d bytes", len(data))

	const attempts = 5
	var best time.Duration
	for i := 0; i < attempts; i++ {
		var v interface{}
		start := time.Now()
		if err := DecodeStrict(data, 32, &v); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		elapsed := time.Since(start)
		if i == 0 || elapsed < best {
			best = elapsed
		}
	}

	const budget = 50 * time.Millisecond
	if best > budget {
		t.Fatalf("best of %d DecodeStrict runs took %s, want < %s", attempts, best, budget)
	}
	t.Logf("best of %d worst-case DecodeStrict runs took %s (budget %s)", attempts, best, budget)
}

func BenchmarkDecodeStrict_WorstCaseKeys(b *testing.B) {
	data := worstCaseKeysObject()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var v interface{}
		if err := DecodeStrict(data, 32, &v); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
