package apply

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
	"github.com/bshlisky/tetragon-relay/internal/verify"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

func TestNewFileSentinel_Validation(t *testing.T) {
	for _, tc := range []struct{ bin, dir string }{
		{"", "/var/lib/x"},
		{"relayd", "/var/lib/x"},
		{"/usr/bin/../bin/relayd", "/var/lib/x"},
		{"/usr/bin/relayd", ""},
		{"/usr/bin/relayd", "/"},
		{"/usr/bin/relayd", "/var/lib/x/"},
		{"/usr/bin/relayd", "var/lib/x"},
		{"/usr/bin/relay\nd", "/var/lib/x"},
		{"/usr/bin/relayd", "/var/lib/\x7fx"},
		{"/" + strings.Repeat("a", 300), "/var/lib/x"},
	} {
		if _, err := NewFileSentinel(tc.bin, tc.dir); err == nil {
			t.Errorf("NewFileSentinel(%q, %q) accepted", tc.bin, tc.dir)
		}
	}
}

func TestFileSentinel_PolicyDocument(t *testing.T) {
	s, err := NewFileSentinel("/usr/libexec/tetragon-relay/relayd", DefaultSentinelDir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.PolicyName(), SentinelPolicyPrefix) || len(s.PolicyName()) != len(SentinelPolicyPrefix)+8 {
		t.Fatalf("name %q", s.PolicyName())
	}
	if loadedNamePattern.MatchString(s.PolicyName()) || isRelayManaged(s.PolicyName(), RelayDomain) {
		t.Fatalf("the sentinel's name %q reads as an LKG-managed policy", s.PolicyName())
	}
	var doc struct {
		Metadata struct{ Name string } `json:"metadata"`
		Spec     struct {
			Kprobes []struct {
				Call string `json:"call"`
				Args []struct {
					Index int
					Type  string
				} `json:"args"`
				Selectors []map[string]json.RawMessage `json:"selectors"`
			} `json:"kprobes"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(s.PolicyJSON(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Name != s.PolicyName() || len(doc.Spec.Kprobes) != 1 || doc.Spec.Kprobes[0].Call != "security_file_open" {
		t.Fatalf("doc %s", s.PolicyJSON())
	}
	sel := doc.Spec.Kprobes[0].Selectors
	if len(sel) != 1 || sel[0]["matchActions"] != nil {
		t.Fatalf("the sentinel must have exactly one selector and no actions: %s", s.PolicyJSON())
	}
	if !strings.Contains(string(sel[0]["matchArgs"]), `"/var/lib/tetragon-relay/sentinel/"`) ||
		!strings.Contains(string(sel[0]["matchBinaries"]), `"/usr/libexec/tetragon-relay/relayd"`) {
		t.Fatalf("selector %s", s.PolicyJSON())
	}
	// PolicyJSON returns a copy.
	b := s.PolicyJSON()
	b[0] = 'X'
	if s.PolicyJSON()[0] == 'X' {
		t.Fatal("PolicyJSON aliases internal state")
	}
	// Content-addressed: another binary or directory, another name; same
	// inputs, same name.
	s2, _ := NewFileSentinel("/usr/local/bin/relayd", DefaultSentinelDir)
	s3, _ := NewFileSentinel("/usr/libexec/tetragon-relay/relayd", "/var/lib/other")
	s4, _ := NewFileSentinel("/usr/libexec/tetragon-relay/relayd", DefaultSentinelDir)
	if s2.PolicyName() == s.PolicyName() || s3.PolicyName() == s.PolicyName() || s4.PolicyName() != s.PolicyName() {
		t.Fatalf("names: %s %s %s %s", s.PolicyName(), s2.PolicyName(), s3.PolicyName(), s4.PolicyName())
	}
}

func TestFileSentinel_FireCreatesAndRemoves(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sentinel")
	s, err := NewFileSentinel("/usr/bin/relayd", dir)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := newNonce()
	if err := s.Fire(nonce); err != nil {
		t.Fatalf("Fire: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir: %v %v", fi, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("Fire left %d files behind", len(entries))
	}
	if err := s.Fire("../escape"); err == nil {
		t.Fatal("Fire accepted a bad nonce")
	}
	// A file already at the nonce's path (O_EXCL) is an error, not success.
	if err := os.WriteFile(filepath.Join(dir, nonce), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Fire(nonce); err == nil {
		t.Fatal("Fire succeeded on an existing path")
	}
	// An unwritable location fails.
	bad, _ := NewFileSentinel("/usr/bin/relayd", "/proc/self/nonexistent-sentinel")
	if err := bad.Fire(nonce); err == nil {
		t.Fatal("Fire succeeded in an unwritable directory")
	}
}

func TestFileSentinel_Nonce(t *testing.T) {
	s, _ := NewFileSentinel("/usr/bin/relayd", "/var/lib/tetragon-relay/sentinel")
	n := strings.Repeat("0a", 16)
	if got, ok := s.Nonce(sentinelEvent(s.PolicyName(), "/var/lib/tetragon-relay/sentinel/"+n)); !ok || got != n {
		t.Fatalf("Nonce = %q %t", got, ok)
	}
	for _, ev := range []tetra.Event{
		{},
		{Lsm: &tetragonpb.ProcessLsm{}},
		sentinelEvent("other-policy", "/var/lib/tetragon-relay/sentinel/"+n),
		sentinelEvent(s.PolicyName(), "/var/lib/tetragon-relay/other/"+n),
		sentinelEvent(s.PolicyName(), "/var/lib/tetragon-relay/sentinel/"+n+"x"),
		sentinelEvent(s.PolicyName(), "/var/lib/tetragon-relay/sentinel/"+strings.ToUpper(n)),
		sentinelEvent(s.PolicyName(), "/var/lib/tetragon-relay/sentinelX/"+n),
	} {
		if got, ok := s.Nonce(ev); ok {
			t.Errorf("Nonce accepted %+v -> %q", ev.Kprobe, got)
		}
	}
}

func TestEnsureSentinel(t *testing.T) {
	f := newFakeServer()
	e, auditor, _ := newTestEngine(t, f, newFakePolicyParser())
	ctx := context.Background()
	if err := e.EnsureSentinel(ctx); err != nil {
		t.Fatal(err)
	}
	name := e.cfg.Sentinel.PolicyName()
	f.mu.Lock()
	f.sentinels["relay-sentinel-deadbeef"] = RelayDomain // stale: another binary
	f.sentinels["relay-sentinel-foreign0"] = "other-domain"
	_, ours := f.sentinels[name]
	f.mu.Unlock()
	if !ours {
		t.Fatal("sentinel not loaded")
	}
	if err := e.EnsureSentinel(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	_, stale := f.sentinels["relay-sentinel-deadbeef"]
	_, foreign := f.sentinels["relay-sentinel-foreign0"]
	f.mu.Unlock()
	if stale || !foreign {
		t.Fatalf("stale left=%t, foreign-domain removed=%t", stale, !foreign)
	}
	loaded := 0
	for _, ev := range auditor.Events {
		if ev.Step == "sentinel_loaded" {
			loaded++
		}
	}
	if loaded != 1 {
		t.Fatalf("sentinel_loaded audited %d times, want 1 (idempotent)", loaded)
	}

	// Errors.
	f.mu.Lock()
	f.listErr = errors.New("list down")
	f.mu.Unlock()
	if err := e.EnsureSentinel(ctx); err == nil {
		t.Fatal("EnsureSentinel ignored a list error")
	}
	e2 := NewEngine(e.client, newFakePolicyParser(), NewFakeLKGStore(), &FakeReachabilityChecker{}, &FakeAuditor{}, Config{})
	if err := e2.EnsureSentinel(ctx); !errors.Is(err, ErrNoSentinel) {
		t.Fatalf("no sentinel: %v", err)
	}
}

func TestEnsureSentinel_AddFails(t *testing.T) {
	f := newFakeServer()
	client, cleanup := startFakeServer(t, f)
	t.Cleanup(cleanup)
	e := NewEngine(&addFailClient{TetragonClient: client}, newFakePolicyParser(), NewFakeLKGStore(), &FakeReachabilityChecker{}, &FakeAuditor{}, Config{Sentinel: newFakeSentinel(t, f.pushLive)})
	if err := e.EnsureSentinel(context.Background()); err == nil {
		t.Fatal("EnsureSentinel ignored an add error")
	}
}

type addFailClient struct{ TetragonClient }

func (addFailClient) AddTracingPolicy(context.Context, string, string) error {
	return errors.New("add refused")
}

// Without a sentinel Apply changes nothing (APPLY_FAILED before any add).
func TestApply_NoSentinel_ApplyFailedNothingLoaded(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	client, cleanup := startFakeServer(t, f)
	t.Cleanup(cleanup)
	e := NewEngine(client, parser, NewFakeLKGStore(), &FakeReachabilityChecker{ReachableValue: true}, &FakeAuditor{}, Config{PersistDir: t.TempDir(), HealthWindow: fastHealthWindow()})
	res, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 1, YAML: "unused"}))
	if !errors.Is(err, ErrApplyFailed) || res == nil || res.Status != StatusApplyFailed || !strings.Contains(res.Detail, "sentinel") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.domain) != 0 || f.addCount != 0 {
		t.Fatalf("Apply loaded something without a sentinel: %v", f.domain)
	}
}

// The P5 outcome on the fake: the observation path is stalled (sentinels
// never arrive), so the enforce bundle must end ROLLED_BACK_UNVERIFIABLE
// with LKG re-asserted, never APPLIED.
func TestApply_StalledPath_RolledBackUnverifiable(t *testing.T) {
	f := newFakeServer()
	parser := newFakePolicyParser()
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Post")}
	e, auditor, lkg := newTestEngine(t, f, parser)
	if _, err := e.Apply(context.Background(), acceptedBundle("monitor", verify.Policy{Name: "p1", Version: 1, YAML: "unused"})); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	before, _ := lkg.Get(RelayDomain)

	e.cfg.Sentinel.(*fakeSentinel).setPlan(func(int) (time.Duration, bool) { return 0, true })
	e.cfg.HealthWindow.MaxWindow = 1500 * time.Millisecond
	e.cfg.HealthWindow.SentinelMaxLatency = 200 * time.Millisecond
	parser.docs["p1"] = fakeDoc{name: "p1", json: policyJSON("p1", "Sigkill")}
	res, err := e.Apply(context.Background(), acceptedBundle("enforce", verify.Policy{Name: "p1", Version: 2, YAML: "unused"}))
	if !errors.Is(err, ErrRolledBackUnverifiable) || res.Status != StatusRolledBackUnverifiable {
		t.Fatalf("res=%+v err=%v, want ROLLED_BACK_UNVERIFIABLE", res, err)
	}
	if res.Status.String() != "ROLLED_BACK_UNVERIFIABLE" || !strings.Contains(res.Detail, "health_unverifiable") || !strings.Contains(res.Detail, "sentinels fired=") {
		t.Fatalf("detail %q", res.Detail)
	}
	after, _ := lkg.Get(RelayDomain)
	if len(after.Policies) != 1 || after.Policies[0].Version != before.Policies[0].Version {
		t.Fatalf("LKG changed: %+v", after)
	}
	f.mu.Lock()
	for name := range f.domain {
		if !strings.HasPrefix(name, "p1-v1-") {
			t.Errorf("loaded after rollback: %s", name)
		}
	}
	f.mu.Unlock()
	var stats, unverifiable bool
	for _, ev := range auditor.Events {
		stats = stats || (ev.Step == "health_window_stats" && strings.Contains(ev.Detail, "passed=false"))
		unverifiable = unverifiable || ev.Step == "health_window_unverifiable"
	}
	if !stats || !unverifiable {
		t.Fatalf("audit: stats=%t unverifiable=%t", stats, unverifiable)
	}
}

func TestReconcile_ReassertsSentinel(t *testing.T) {
	f := newFakeServer()
	e, _, _ := newTestEngine(t, f, newFakePolicyParser())
	if _, err := e.Reconcile(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	_, ok := f.sentinels[e.cfg.Sentinel.PolicyName()]
	f.mu.Unlock()
	if !ok {
		t.Fatal("Reconcile did not load the sentinel")
	}
	// A sentinel failure does not fail Reconcile; it is audited.
	e2 := NewEngine(&addFailClient{TetragonClient: e.client}, newFakePolicyParser(), NewFakeLKGStore(), &FakeReachabilityChecker{}, &FakeAuditor{}, Config{Sentinel: newFakeSentinel(t, f.pushLive)})
	f.mu.Lock()
	delete(f.sentinels, e.cfg.Sentinel.PolicyName())
	f.mu.Unlock()
	rep, err := e2.Reconcile(context.Background(), false)
	if err != nil || !rep.InSync {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
	if aud := e2.auditor.(*FakeAuditor); len(aud.Events) == 0 || aud.Events[0].Step != "reconcile_sentinel_failed" {
		t.Fatalf("audit %+v", aud.Events)
	}
}

func TestNewSelfSentinel(t *testing.T) {
	s, err := NewSelfSentinel(filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	if s.binary != exe {
		t.Fatalf("binary %q, want %q", s.binary, exe)
	}
}
