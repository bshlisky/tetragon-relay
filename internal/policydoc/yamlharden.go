package policydoc

import (
	"gopkg.in/yaml.v3"

	"github.com/bshlisky/tetragon-relay/internal/yamlharden"
)

// parseHardenedYAML implements step 2 prompt Part B1: it decodes raw as
// exactly one YAML document, rejects every construct listed in the prompt,
// and returns the single root content node (the document's one child, e.g.
// a mapping node) for conversion to canonical JSON.
//
// docs/prompts/step-06a.md Part B2: the hardening rules themselves now
// live in internal/yamlharden, shared with internal/config's relay.yaml
// ingestion, rather than being duplicated. This function is a thin
// delegate so every other file in this package (and every existing test)
// can keep calling parseHardenedYAML exactly as before; behavior is
// byte-for-byte unchanged (see docs/reports/step-06a.md for the proof:
// this package's full existing test suite, unmodified except for the
// handful of white-box tests that moved to internal/yamlharden because
// they exercised the walker's unexported internals directly, still
// passes).
func parseHardenedYAML(raw []byte) (*yaml.Node, error) {
	return yamlharden.Parse(raw)
}
