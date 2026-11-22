package policydoc

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var probeNameRe = regexp.MustCompile(`(?m)^\s*name:\s*"?([a-zA-Z0-9._-]+)"?\s*$`)

func probeGuessName(data []byte) string {
	m := probeNameRe.FindSubmatch(data)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// TestCorpusProbe is a diagnostic, not an assertion: it runs every upstream
// example through Parse and logs pass/fail + error, to build the step
// 2 report's corpus table manually. Not part of the regular suite's pass
// criteria.
func TestCorpusProbe(t *testing.T) {
	entries, err := os.ReadDir("../../testdata/upstream")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".yaml" && filepath.Ext(e.Name()) != ".yml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("../../testdata/upstream", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		// Try to pull metadata.name out loosely to pass as the expected
		// name; fall back to the mismatch error, which is still useful
		// signal for the probe.
		doc, err := Parse(probeGuessName(data), string(data))
		if err != nil {
			t.Logf("%-55s REJECT  %v", e.Name(), err)
			continue
		}
		t.Logf("%-55s ACCEPT  name=%s hooks=%d", e.Name(), doc.Name(), len(doc.Hooks()))
	}
}
