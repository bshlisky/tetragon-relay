package apply

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

func TestStatus_String(t *testing.T) {
	cases := map[Status]string{
		StatusApplied:        "APPLIED",
		StatusRolledBack:     "ROLLED_BACK",
		StatusApplyFailed:    "APPLY_FAILED",
		StatusRollbackFailed: "ROLLBACK_FAILED",
		Status(99):           "UNKNOWN",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestConfig_Defaults(t *testing.T) {
	var c Config
	if c.domain() != RelayDomain {
		t.Errorf("domain() = %q, want %q", c.domain(), RelayDomain)
	}
	if c.persistDir() != "/etc/tetragon/tetragon.tp.d/relay" {
		t.Errorf("persistDir() = %q", c.persistDir())
	}
	c2 := Config{Domain: "x", PersistDir: "/tmp/y"}
	if c2.domain() != "x" || c2.persistDir() != "/tmp/y" {
		t.Errorf("configured Domain/PersistDir not honored: %+v", c2)
	}
}

func TestHealthWindowConfig_Defaults(t *testing.T) {
	var c HealthWindowConfig
	if c.window() <= 0 {
		t.Error("window() default should be positive")
	}
	if c.surgeThreshold() <= 0 {
		t.Error("surgeThreshold() default should be positive")
	}
	if c.pollInterval() <= 0 {
		t.Error("pollInterval() default should be positive")
	}
	c2 := HealthWindowConfig{Window: 5 * time.Second, SurgeThreshold: 10, PollInterval: time.Second}
	if c2.window() != 5*time.Second || c2.surgeThreshold() != 10 || c2.pollInterval() != time.Second {
		t.Errorf("configured values not honored: %+v", c2)
	}
}

func TestClampHealthWindow(t *testing.T) {
	if got := ClampHealthWindow(1 * time.Second); got != 15*time.Second {
		t.Errorf("ClampHealthWindow(1s) = %v, want 15s floor", got)
	}
	if got := ClampHealthWindow(1000 * time.Second); got != 600*time.Second {
		t.Errorf("ClampHealthWindow(1000s) = %v, want 600s ceiling", got)
	}
	if got := ClampHealthWindow(60 * time.Second); got != 60*time.Second {
		t.Errorf("ClampHealthWindow(60s) = %v, want unchanged", got)
	}
}

func TestLoadedName(t *testing.T) {
	name, err := LoadedName("mypolicy", 3, []byte("content"))
	if err != nil {
		t.Fatalf("LoadedName: %v", err)
	}
	if !strings.HasPrefix(name, "mypolicy-v3-") {
		t.Fatalf("LoadedName = %q, want prefix mypolicy-v3-", name)
	}
	if len(name) != len("mypolicy-v3-")+8 {
		t.Fatalf("LoadedName = %q, want exactly 8 trailing hex chars", name)
	}

	if _, err := LoadedName("Invalid_Name", 1, nil); err == nil {
		t.Fatal("LoadedName accepted an invalid policy name")
	}
	if _, err := LoadedName("ok", 0, nil); err == nil {
		t.Fatal("LoadedName accepted version 0")
	}
	if _, err := LoadedName("ok", -1, nil); err == nil {
		t.Fatal("LoadedName accepted a negative version")
	}

	// Deterministic: same inputs, same output.
	n1, _ := LoadedName("a", 1, []byte("x"))
	n2, _ := LoadedName("a", 1, []byte("x"))
	if n1 != n2 {
		t.Fatalf("LoadedName not deterministic: %q vs %q", n1, n2)
	}
	// Different content -> different name.
	n3, _ := LoadedName("a", 1, []byte("y"))
	if n1 == n3 {
		t.Fatal("LoadedName did not change for different content")
	}
}

func TestParseLoadedName(t *testing.T) {
	name, _ := LoadedName("my-policy", 42, []byte("x"))
	base, version, hexPrefix, ok := parseLoadedName(name)
	if !ok || base != "my-policy" || version != 42 || len(hexPrefix) != 8 {
		t.Fatalf("parseLoadedName(%q) = %q, %d, %q, %v", name, base, version, hexPrefix, ok)
	}

	cases := []string{"", "not-a-loaded-name", "foo-v1", "foo-vX-aaaaaaaa", "foo-v1-tooShort", "foo-v1-AAAAAAAA"}
	for _, c := range cases {
		if _, _, _, ok := parseLoadedName(c); ok {
			t.Errorf("parseLoadedName(%q) = ok, want rejected", c)
		}
	}
}

func TestIsRelayManaged(t *testing.T) {
	name, _ := LoadedName("p", 1, []byte("x"))
	if !isRelayManaged(name, RelayDomain) {
		t.Error("isRelayManaged should be true for a correctly-named, correctly-domained policy")
	}
	if isRelayManaged(name, "some-other-domain") {
		t.Error("isRelayManaged should be false for the wrong domain")
	}
	if isRelayManaged("not-a-loaded-name", RelayDomain) {
		t.Error("isRelayManaged should be false for a name that doesn't match the pattern")
	}
}

func TestRewriteActionsToPost(t *testing.T) {
	in := policyJSON("p", "Sigkill")
	out, err := rewriteActionsToPost(in)
	if err != nil {
		t.Fatalf("rewriteActionsToPost: %v", err)
	}
	if !strings.Contains(string(out), `"action":"Post"`) {
		t.Fatalf("Sigkill was not rewritten: %s", out)
	}
	if strings.Contains(string(out), "Sigkill") {
		t.Fatalf("original action value leaked through: %s", out)
	}

	// Post itself is left alone.
	out2, err := rewriteActionsToPost(policyJSON("p", "Post"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out2), `"action":"Post"`) {
		t.Fatalf("Post action was altered: %s", out2)
	}

	if _, err := rewriteActionsToPost([]byte("not json")); err == nil {
		t.Fatal("rewriteActionsToPost accepted invalid JSON")
	}
}

func TestSetMetadataName(t *testing.T) {
	out, err := setMetadataName(policyJSON("original", "Post"), "rewritten-v1-deadbeef")
	if err != nil {
		t.Fatalf("setMetadataName: %v", err)
	}
	if !strings.Contains(string(out), `"name":"rewritten-v1-deadbeef"`) {
		t.Fatalf("name was not rewritten: %s", out)
	}

	if _, err := setMetadataName([]byte(`{"no":"metadata"}`), "x"); err == nil {
		t.Fatal("setMetadataName accepted a document with no metadata object")
	}
	if _, err := setMetadataName([]byte(`[1,2,3]`), "x"); err == nil {
		t.Fatal("setMetadataName accepted a non-object root")
	}
	if _, err := setMetadataName([]byte("not json"), "x"); err == nil {
		t.Fatal("setMetadataName accepted invalid JSON")
	}
}

func TestDigest(t *testing.T) {
	name, _ := LoadedName("p1", 1, []byte("x"))
	statuses := []tetra.TracingPolicyStatus{
		{Name: name, Domain: RelayDomain, State: tetragonpb.TracingPolicyState_TP_STATE_ENABLED, Sensors: []string{"b", "a"}},
		{Name: "foreign-policy", Domain: "", State: tetragonpb.TracingPolicyState_TP_STATE_ENABLED},
	}
	d1 := Digest(statuses)
	if d1 == "" {
		t.Fatal("Digest returned empty string")
	}

	// Sensor order must not matter.
	statuses2 := []tetra.TracingPolicyStatus{
		{Name: name, Domain: RelayDomain, State: tetragonpb.TracingPolicyState_TP_STATE_ENABLED, Sensors: []string{"a", "b"}},
	}
	if Digest(statuses2) != Digest([]tetra.TracingPolicyStatus{statuses[0]}) {
		t.Fatal("Digest is sensitive to sensor slice order")
	}

	// Foreign (non-relay-managed) policies must not affect the digest.
	if d1 != Digest([]tetra.TracingPolicyStatus{statuses[0]}) {
		t.Fatal("Digest is affected by a foreign policy")
	}

	if Digest(nil) == d1 {
		t.Fatal("Digest(nil) collided with a non-empty digest")
	}
}

func TestIsAdminPathBinary(t *testing.T) {
	if !isAdminPathBinary("/usr/sbin/sshd") || !isAdminPathBinary("/bin/bash") {
		t.Error("expected admin-path binaries not recognized")
	}
	if isAdminPathBinary("/usr/bin/cat") {
		t.Error("/usr/bin/cat should not be an admin-path binary")
	}
}

func TestIsEnforcementKprobeAction(t *testing.T) {
	yes := []tetragonpb.KprobeAction{
		tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL,
		tetragonpb.KprobeAction_KPROBE_ACTION_SIGNAL,
		tetragonpb.KprobeAction_KPROBE_ACTION_OVERRIDE,
	}
	for _, a := range yes {
		if !isEnforcementKprobeAction(a) {
			t.Errorf("isEnforcementKprobeAction(%v) = false, want true", a)
		}
	}
	no := []tetragonpb.KprobeAction{
		tetragonpb.KprobeAction_KPROBE_ACTION_POST,
		tetragonpb.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER,
		tetragonpb.KprobeAction_KPROBE_ACTION_SET,
	}
	for _, a := range no {
		if isEnforcementKprobeAction(a) {
			t.Errorf("isEnforcementKprobeAction(%v) = true, want false", a)
		}
	}
}

func TestProcessTreeHitsAdminPath(t *testing.T) {
	admin := &tetragonpb.Process{Binary: "/usr/sbin/sshd"}
	other := &tetragonpb.Process{Binary: "/usr/bin/cat"}

	if !processTreeHitsAdminPath(admin, nil, nil) {
		t.Error("process itself in admin path not detected")
	}
	if !processTreeHitsAdminPath(other, admin, nil) {
		t.Error("parent in admin path not detected")
	}
	if !processTreeHitsAdminPath(other, nil, []*tetragonpb.Process{other, admin}) {
		t.Error("ancestor in admin path not detected")
	}
	if processTreeHitsAdminPath(other, other, []*tetragonpb.Process{other}) {
		t.Error("false positive: no admin-path binary anywhere in the tree")
	}
	if processTreeHitsAdminPath(nil, nil, nil) {
		t.Error("nil process tree should not match")
	}
}

func TestEvaluateEvent(t *testing.T) {
	admin := &tetragonpb.Process{Binary: "/usr/sbin/sshd"}
	other := &tetragonpb.Process{Binary: "/usr/bin/cat"}

	cases := []struct {
		name       string
		ev         tetra.Event
		wantFailed bool
	}{
		{"kprobe_admin_sigkill", tetra.Event{Kprobe: &tetragonpb.ProcessKprobe{Process: admin, Action: tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL}}, true},
		{"kprobe_nonadmin_sigkill", tetra.Event{Kprobe: &tetragonpb.ProcessKprobe{Process: other, Action: tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL}}, false},
		{"kprobe_admin_post", tetra.Event{Kprobe: &tetragonpb.ProcessKprobe{Process: admin, Action: tetragonpb.KprobeAction_KPROBE_ACTION_POST}}, false},
		{"uprobe_admin_override", tetra.Event{Uprobe: &tetragonpb.ProcessUprobe{Process: admin, Action: tetragonpb.KprobeAction_KPROBE_ACTION_OVERRIDE}}, true},
		{"lsm_admin_signal", tetra.Event{Lsm: &tetragonpb.ProcessLsm{Process: admin, Action: tetragonpb.KprobeAction_KPROBE_ACTION_SIGNAL}}, true},
		{"empty_event", tetra.Event{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, failed := evaluateEvent(tc.ev)
			if failed != tc.wantFailed {
				t.Errorf("evaluateEvent(%s) failed=%v, want %v", tc.name, failed, tc.wantFailed)
			}
		})
	}
}

func TestSlidingEventCounter(t *testing.T) {
	c := newSlidingEventCounter(time.Minute)
	now := time.Now()
	c.add(now.Add(-2 * time.Minute)) // outside window
	c.add(now.Add(-30 * time.Second))
	c.add(now)
	if got := c.count(now); got != 2 {
		t.Fatalf("count = %d, want 2 (old entry should have been pruned)", got)
	}
}

func TestRealPolicyParser(t *testing.T) {
	const validYAML = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "security_bprm_check"
    selectors:
      - matchBinaries:
        - operator: "In"
          values:
          - "/usr/bin/sample-exec"
        matchActions:
        - action: "Post"
`
	doc, err := RealPolicyParser{}.Parse("sample", validYAML)
	if err != nil {
		t.Fatalf("RealPolicyParser.Parse: %v", err)
	}
	if doc.Name() != "sample" {
		t.Fatalf("Name() = %q", doc.Name())
	}
	if len(doc.CanonicalJSON()) == 0 {
		t.Fatal("CanonicalJSON() is empty")
	}

	if _, err := (RealPolicyParser{}).Parse("sample", "not: valid: yaml: ["); err == nil {
		t.Fatal("RealPolicyParser.Parse accepted invalid YAML")
	}
}

func TestLKGStore_Fake_NilMapInitializedByPut(t *testing.T) {
	var s FakeLKGStore // zero value: sets map is nil
	if err := s.Put("d", LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put on a zero-value FakeLKGStore: %v", err)
	}
	got, ok := s.Get("d")
	if !ok || got.Mode != "enforce" {
		t.Fatalf("Get after Put on a zero-value store = %+v, %v", got, ok)
	}
}

func TestMarshalCanonical_Failure(t *testing.T) {
	if _, err := marshalCanonical(make(chan int)); err == nil {
		t.Fatal("marshalCanonical accepted an unmarshalable value")
	}
}

func TestLKGStore_Fake(t *testing.T) {
	s := NewFakeLKGStore()
	if _, ok := s.Get("d"); ok {
		t.Fatal("Get on an empty store returned ok=true")
	}
	set := LKGSet{Mode: "enforce"}
	if err := s.Put("d", set); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Get("d")
	if !ok || got.Mode != "enforce" {
		t.Fatalf("Get after Put = %+v, %v", got, ok)
	}
}

func TestFakeAuditor(t *testing.T) {
	a := &FakeAuditor{}
	a.Record(AuditEvent{Step: "x"})
	if len(a.Events) != 1 || a.Events[0].Step != "x" {
		t.Fatalf("FakeAuditor.Events = %+v", a.Events)
	}
}

func TestFakeReachabilityChecker(t *testing.T) {
	r := &FakeReachabilityChecker{ReachableValue: true}
	if !r.Reachable(context.Background()) {
		t.Fatal("Reachable() = false, want true")
	}
}

func TestEnforcementActionNamesMatchGuard(t *testing.T) {
	// Mirrors internal/guard/actions.go's enforcementActions exactly
	// (that map is unexported, so this is a literal list, not a live
	// import; keep in sync by hand if that list ever changes).
	want := map[string]bool{"Sigkill": true, "Signal": true, "NotifyEnforcer": true, "Override": true, "Set": true}
	if len(want) != len(enforcementActionNames) {
		t.Fatalf("enforcementActionNames has %d entries, want %d", len(enforcementActionNames), len(want))
	}
	for k := range want {
		if !enforcementActionNames[k] {
			t.Errorf("enforcementActionNames missing %q", k)
		}
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	all := []error{ErrApplyInProgress, ErrNotAccepted, ErrApplyFailed, ErrRolledBack, ErrRollbackFailed, ErrUnsupportedTetragonVersion}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("error %v is treated as %v", a, b)
			}
		}
	}
}
