package policydoc

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzPolicyParse fuzzes Parse directly on raw YAML, seeded from the
// upstream corpus (step 2 prompt Part D). It must never panic, hang, or
// (since no seed/mutation can possibly produce a validly signed bundle
// name) accept with a name other than "fuzz": the only interesting
// property is "no crash", mirroring FuzzVerifyEnvelope and FuzzStrictJSON
// from steps 1/2A.
func FuzzPolicyParse(f *testing.F) {
	entries, err := os.ReadDir("../../testdata/upstream")
	if err == nil {
		for _, e := range entries {
			ext := filepath.Ext(e.Name())
			if ext != ".yaml" && ext != ".yml" {
				continue
			}
			data, err := os.ReadFile(filepath.Join("../../testdata/upstream", e.Name()))
			if err == nil {
				f.Add(string(data))
			}
		}
	}
	f.Add(validPolicy)
	f.Add("")
	f.Add("not: valid: yaml: [")
	f.Add("apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: &a x\nspec:\n  kprobes:\n  - call: *a\n")

	f.Fuzz(func(t *testing.T, y string) {
		doc, err := Parse("fuzz", y)
		if err != nil {
			if doc != nil {
				t.Fatalf("non-nil Doc returned alongside error %v", err)
			}
			return
		}
		if doc.Name() != "fuzz" {
			t.Fatalf("accepted document with mismatched name: %q", doc.Name())
		}
		// Re-parsing the canonical JSON as YAML (it is also valid YAML)
		// and re-canonicalizing must be idempotent: this is the
		// parser-differential / stability check from step 2 prompt Part
		// D, folded into the fuzz target instead of a separate 1000-run
		// loop so it runs on every corpus-discovered input, not just the
		// fixed seeds.
		again, err := Parse("fuzz", string(doc.CanonicalJSON()))
		if err != nil {
			t.Fatalf("canonical JSON did not re-parse: %v\ncanonical: %s", err, doc.CanonicalJSON())
		}
		if again.CanonicalSHA256() != doc.CanonicalSHA256() {
			t.Fatalf("CanonicalSHA256 not stable across re-parse")
		}
	})
}
