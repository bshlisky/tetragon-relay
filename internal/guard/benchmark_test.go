//go:build !race

// The -race detector adds substantial per-operation instrumentation
// overhead that has nothing to do with this code's real cost (measured
// directly: ~2.7ms uninstrumented vs ~95ms under -race for this file's
// worst-case input). Go's toolchain defines the "race" build tag
// automatically when -race is passed, so excluding this file under it
// means `make test-race` / `go test -race` simply skip the hard-budget
// performance assertion, while `make test` / a plain `go test` (and the
// benchmark, run deliberately without -race) still enforce and report it.
// Same precedent as internal/verify/bench_test.go (step 1 review A4).

package guard

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

// largestAllowedBundleYAML builds a single policy at exactly
// limits.MaxHooksPerBundle hooks, each with one selector holding as many
// selector values as fit under limits.MaxSelectorValuesPerBundle, every
// selector scoped safely (In on a non-protected binary) so Check reaches
// every rule (G1-G5) rather than short-circuiting on the first hook: the
// worst case the step 2 prompt's G4 benchmark requirement describes.
func largestAllowedBundleYAML() string {
	var sb strings.Builder
	sb.WriteString("apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"bench\"\nspec:\n  kprobes:\n")
	valuesPerHook := limits.MaxSelectorValuesPerBundle / limits.MaxHooksPerBundle
	for i := 0; i < limits.MaxHooksPerBundle; i++ {
		fmt.Fprintf(&sb, "  - call: \"call%d\"\n    selectors:\n    - matchBinaries:\n      - operator: \"In\"\n        values:\n", i)
		for j := 0; j < valuesPerHook; j++ {
			fmt.Fprintf(&sb, "        - \"/usr/bin/app%d-%d\"\n", i, j)
		}
		sb.WriteString("      matchActions:\n      - action: \"Sigkill\"\n")
	}
	return sb.String()
}

func BenchmarkCheck_WorstCase(b *testing.B) {
	doc, err := policydoc.Parse("bench", largestAllowedBundleYAML())
	if err != nil {
		b.Fatalf("Parse: %v", err)
	}
	g := newGuard()
	ctx := GuardContext{Scope: "s", Mode: "monitor"}
	docs := []*policydoc.Doc{doc}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := g.Check(ctx, docs); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// TestCheck_WorstCasePerformance is the test-suite-visible, CI-friendly
// counterpart of BenchmarkCheck_WorstCase: the step 2 prompt requires
// "< 50 ms for the largest allowed bundle", not just a benchmark number
// left for a human to read. It takes the minimum over several attempts,
// not a single sample, for the same reason
// internal/verify.TestVerify_WorstCasePerformance (step 1 review A4) does:
// a single wall-clock sample competing with other packages' tests/fuzzers
// (or, as here, the race detector's instrumentation) for CPU can be
// stretched by GC pauses or scheduler preemption unrelated to this code's
// actual cost; the minimum across attempts is what a dedicated run (and
// BenchmarkCheck_WorstCase) would show.
func TestCheck_WorstCasePerformance(t *testing.T) {
	doc, err := policydoc.Parse("bench", largestAllowedBundleYAML())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	g := newGuard()
	ctx := GuardContext{Scope: "s", Mode: "monitor"}
	docs := []*policydoc.Doc{doc}

	const attempts = 7
	var best time.Duration
	for i := 0; i < attempts; i++ {
		start := time.Now()
		if err := g.Check(ctx, docs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		elapsed := time.Since(start)
		if i == 0 || elapsed < best {
			best = elapsed
		}
	}
	t.Logf("Check on the largest allowed bundle (%d hooks, %d selector values), best of %d: %s", limits.MaxHooksPerBundle, limits.MaxSelectorValuesPerBundle, attempts, best)
	if best > 50*time.Millisecond {
		t.Fatalf("best-of-%d Check took %s, want < 50ms", attempts, best)
	}
}
