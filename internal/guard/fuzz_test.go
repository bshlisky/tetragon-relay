package guard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

// FuzzGuard fuzzes Check over structured mutations of valid policies (step
// 2 prompt Part D): seeds are the upstream corpus plus the hand-written
// scenarios from guard_test.go, each fuzzed together with a mutated mode
// string. Check must never panic or hang, regardless of what
// policydoc.Parse accepts.
func FuzzGuard(f *testing.F) {
	entries, err := os.ReadDir("../../testdata/upstream")
	if err == nil {
		for _, e := range entries {
			ext := filepath.Ext(e.Name())
			if ext != ".yaml" && ext != ".yml" {
				continue
			}
			data, err := os.ReadFile(filepath.Join("../../testdata/upstream", e.Name()))
			if err == nil {
				f.Add(string(data), "monitor")
				f.Add(string(data), "enforce")
			}
		}
	}
	f.Add(overrideKprobeSpecFuzzSeed(), "monitor")
	f.Add(overrideKprobeSpecFuzzSeed(), "enforce")
	f.Add("", "bogus")

	f.Fuzz(func(_ *testing.T, y, mode string) {
		doc, err := policydoc.Parse("fuzz", y)
		if err != nil {
			return
		}
		g := &Guardrails{
			Capabilities: allowAllCapabilities,
			History:      fakeHistory{seen: map[string]bool{"s/fuzz": true}},
		}
		_ = g.Check(GuardContext{Scope: "s", Mode: mode}, []*policydoc.Doc{doc})
	})
}

func overrideKprobeSpecFuzzSeed() string {
	return policyYAML("fuzz", overrideKprobeSpec(`matchBinaries:
      - operator: "In"
        values: ["/usr/bin/safe"]
      `))
}
