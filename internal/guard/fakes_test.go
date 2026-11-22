package guard

import "github.com/bshlisky/tetragon-relay/internal/policydoc"

type fakeCapabilities struct {
	kprobeOverride bool
	lsmBPF         bool
}

func (f fakeCapabilities) KprobeOverride() bool { return f.kprobeOverride }
func (f fakeCapabilities) LSMBPF() bool         { return f.lsmBPF }

var allowAllCapabilities = fakeCapabilities{kprobeOverride: true, lsmBPF: true}
var denyAllCapabilities = fakeCapabilities{kprobeOverride: false, lsmBPF: false}

type fakeHistory struct {
	seen map[string]bool // "scope/name" -> seen in monitor
	err  error
}

func (f fakeHistory) SeenInMonitor(scope, name string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.seen == nil {
		return false, nil
	}
	return f.seen[scope+"/"+name], nil
}

type fakeProtectedSetSource struct {
	binaries []string
	paths    []string
}

func (f fakeProtectedSetSource) ExtraBinaries() []string { return f.binaries }
func (f fakeProtectedSetSource) ExtraPaths() []string    { return f.paths }

func mustParseDoc(t interface{ Fatalf(string, ...interface{}) }, name, yaml string) *policydoc.Doc {
	d, err := policydoc.Parse(name, yaml)
	if err != nil {
		t.Fatalf("policydoc.Parse(%q): %v", name, err)
	}
	return d
}
