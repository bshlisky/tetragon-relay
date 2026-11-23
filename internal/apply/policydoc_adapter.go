package apply

import "github.com/bshlisky/tetragon-relay/internal/policydoc"

// RealPolicyParser adapts internal/policydoc.Parse to the PolicyParser
// interface. This is the only production implementation; every test in
// this package uses a fake instead.
type RealPolicyParser struct{}

// Parse implements PolicyParser.
func (RealPolicyParser) Parse(name, yamlDoc string) (Doc, error) {
	return policydoc.Parse(name, yamlDoc)
}
