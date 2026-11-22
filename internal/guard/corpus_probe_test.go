package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

var probeNameRe = regexp.MustCompile(`(?m)^\s*name:\s*"?([a-zA-Z0-9._-]+)"?\s*$`)

func probeGuessName(data []byte) string {
	m := probeNameRe.FindSubmatch(data)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// TestCorpusProbe_ParseAndGuard is a diagnostic (not a pass/fail gate on
// its own beyond "must not panic") that runs the full upstream corpus
// through policydoc.Parse + guard.Check and logs the outcome of each, for
// docs/reports/step-02b.md section 11's table.
func TestCorpusProbe_ParseAndGuard(t *testing.T) {
	entries, err := os.ReadDir("../../testdata/upstream")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	g := &Guardrails{Capabilities: allowAllCapabilities, History: allowAllHistoryFake{}}
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("../../testdata/upstream", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		name := probeGuessName(data)
		doc, err := policydoc.Parse(name, string(data))
		if err != nil {
			t.Logf("%-55s PARSE-REJECT  %v", e.Name(), err)
			continue
		}
		err = g.Check(GuardContext{Scope: "s", Mode: "monitor"}, []*policydoc.Doc{doc})
		if err != nil {
			t.Logf("%-55s GUARD-REJECT  %v", e.Name(), err)
			continue
		}
		t.Logf("%-55s ACCEPT        hooks=%d", e.Name(), len(doc.Hooks()))
	}
}

type allowAllHistoryFake struct{}

func (allowAllHistoryFake) SeenInMonitor(string, string) (bool, error) { return true, nil }
