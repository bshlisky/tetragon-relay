package apply

import (
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

// yamlMetadataName extracts metadata.name from a YAML (or, since canonical
// JSON is valid YAML, JSON) document, for the fake server to key its
// in-memory state on the same name the real Tetragon would (Part D1's
// loaded name is literally metadata.name at that point).
func yamlMetadataName(doc string) (string, error) {
	var v struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
		return "", fmt.Errorf("yamlMetadataName: %w", err)
	}
	if v.Metadata.Name == "" {
		return "", fmt.Errorf("yamlMetadataName: empty metadata.name")
	}
	return v.Metadata.Name, nil
}

// fakeDoc is a minimal Doc implementation for tests that don't need a real
// *policydoc.Doc.
type fakeDoc struct {
	name string
	json []byte
}

func (d fakeDoc) Name() string          { return d.name }
func (d fakeDoc) CanonicalJSON() []byte { return d.json }

// fakePolicyParser maps a policy name to a pre-built Doc (or an error),
// avoiding a dependency on real YAML in tests that only care about
// Engine's orchestration logic, not policydoc.Parse itself (which has its
// own exhaustive test suite).
type fakePolicyParser struct {
	mu    sync.Mutex
	docs  map[string]Doc
	errs  map[string]error
	calls []string
}

func newFakePolicyParser() *fakePolicyParser {
	return &fakePolicyParser{docs: map[string]Doc{}, errs: map[string]error{}}
}

func (p *fakePolicyParser) Parse(name, _ string) (Doc, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, name)
	if err, ok := p.errs[name]; ok {
		return nil, err
	}
	if d, ok := p.docs[name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("fakePolicyParser: no doc registered for %q", name)
}

// policyJSON builds a minimal, schema-shaped canonical JSON document (one
// kprobe, one matchBinaries selector, one matchActions entry) for tests
// that exercise the mode-rewrite and name-computation logic without
// needing a full policydoc.Parse round trip.
func policyJSON(name, action string) []byte {
	return []byte(fmt.Sprintf(
		`{"apiVersion":"cilium.io/v1alpha1","kind":"TracingPolicy","metadata":{"name":%q},"spec":{"kprobes":[{"call":"security_bprm_check","selectors":[{"matchActions":[{"action":%q}],"matchBinaries":[{"operator":"In","values":["/usr/bin/x"]}]}]}]}}`,
		name, action,
	))
}
