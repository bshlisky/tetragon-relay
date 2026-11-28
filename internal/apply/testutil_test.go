package apply

import (
	"fmt"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
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

// fakeSentinel is a Sentinel whose Fire hands the matching Tetragon event
// to deliver (instead of a kernel hook), after plan(n) says how: n is the
// 1-based firing count; delay is how long the "pipeline" takes, drop
// loses it. Policy name and Nonce parsing are the real FileSentinel's.
type fakeSentinel struct {
	real    *FileSentinel
	deliver func(tetra.Event)

	mu      sync.Mutex
	n       int
	plan    func(n int) (delay time.Duration, drop bool)
	fireErr error
}

func newFakeSentinel(t interface{ Fatalf(string, ...any) }, deliver func(tetra.Event)) *fakeSentinel {
	fs, err := NewFileSentinel("/usr/libexec/tetragon-relay/relayd", "/var/lib/tetragon-relay/sentinel")
	if err != nil {
		t.Fatalf("NewFileSentinel: %v", err)
	}
	return &fakeSentinel{real: fs, deliver: deliver}
}

func (s *fakeSentinel) PolicyName() string                  { return s.real.PolicyName() }
func (s *fakeSentinel) PolicyJSON() []byte                  { return s.real.PolicyJSON() }
func (s *fakeSentinel) Nonce(ev tetra.Event) (string, bool) { return s.real.Nonce(ev) }

func (s *fakeSentinel) setPlan(plan func(n int) (time.Duration, bool)) {
	s.mu.Lock()
	s.plan = plan
	s.mu.Unlock()
}

func (s *fakeSentinel) Fire(nonce string) error {
	s.mu.Lock()
	s.n++
	n, plan, ferr := s.n, s.plan, s.fireErr
	s.mu.Unlock()
	if ferr != nil {
		return ferr
	}
	var delay time.Duration
	if plan != nil {
		var drop bool
		if delay, drop = plan(n); drop {
			return nil
		}
	}
	ev := sentinelEvent(s.real.PolicyName(), s.real.dir+"/"+nonce)
	if delay <= 0 {
		go s.deliver(ev)
		return nil
	}
	time.AfterFunc(delay, func() { s.deliver(ev) })
	return nil
}

func sentinelEvent(policy, path string) tetra.Event {
	return tetra.Event{Kprobe: &tetragonpb.ProcessKprobe{
		PolicyName:   policy,
		FunctionName: "security_file_open",
		Process:      &tetragonpb.Process{Binary: "/usr/libexec/tetragon-relay/relayd"},
		Args:         []*tetragonpb.KprobeArgument{{Arg: &tetragonpb.KprobeArgument_FileArg{FileArg: &tetragonpb.KprobeFile{Path: path}}}},
		Action:       tetragonpb.KprobeAction_KPROBE_ACTION_POST,
	}}
}
