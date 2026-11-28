//go:build integration

package apply

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// integrationSentinel is the real FileSentinel for this test binary, in a
// short fresh directory (Tetragon matches the path prefix in BPF).
func integrationSentinel(t *testing.T) *FileSentinel {
	t.Helper()
	dir, err := os.MkdirTemp("", "snt")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s, err := NewSelfSentinel(dir)
	if err != nil {
		t.Fatalf("NewSelfSentinel: %v", err)
	}
	return s
}

// TestIntegration_SentinelArrives verifies ADR 0042's hook on the real
// Tetragon v1.8.0 (step-07b-decisions-3.md F0.1: "verify it, don't
// guess"): the relay-sentinel policy loads ENABLED, an open of
// <dir>/<nonce> by this binary arrives on a GetEvents stream filtered to
// the sentinel policy, the event carries the nonce, its action is Post,
// and an open by another binary (/usr/bin/cat) does not arrive.
func TestIntegration_SentinelArrives(t *testing.T) {
	client := dialIntegration(t)
	s := integrationSentinel(t)
	e := NewEngine(client, RealPolicyParser{}, NewFakeLKGStore(), &FakeReachabilityChecker{ReachableValue: true}, &FakeAuditor{}, Config{
		PersistDir: t.TempDir(), Sentinel: s,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := e.EnsureSentinel(ctx); err != nil {
		t.Fatalf("EnsureSentinel: %v", err)
	}
	statuses, err := client.ListTracingPolicies(ctx, RelayDomain)
	if err != nil {
		t.Fatalf("ListTracingPolicies: %v", err)
	}
	found := false
	for _, st := range statuses {
		if st.Name == s.PolicyName() {
			found = true
			t.Logf("SENTINEL policy=%s state=%s sensors=%v", st.Name, st.State, st.Sensors)
			if st.State.String() != "TP_STATE_ENABLED" {
				t.Fatalf("sentinel policy state %s, want TP_STATE_ENABLED", st.State)
			}
		}
		if isRelayManaged(st.Name, st.Domain) && st.Name == s.PolicyName() {
			t.Fatalf("the sentinel policy reads as an LKG-managed policy")
		}
	}
	if !found {
		t.Fatalf("sentinel policy %s not listed: %+v", s.PolicyName(), statuses)
	}
	if d := Digest(statuses); d != Digest(nil) {
		t.Fatalf("the sentinel changed loaded_digest: %s", d)
	}
	// Idempotent: a second EnsureSentinel adds nothing.
	if err := e.EnsureSentinel(ctx); err != nil {
		t.Fatalf("EnsureSentinel (again): %v", err)
	}

	streamCtx, stop := context.WithCancel(ctx)
	defer stop()
	events, errc := client.GetEvents(streamCtx, []string{s.PolicyName()})
	time.Sleep(time.Second) // let the subscription register

	// A foreign binary opening a sentinel-shaped path must not arrive.
	foreign := s.dir + "/" + "ffffffffffffffffffffffffffffffff"
	if err := os.WriteFile(foreign, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if out, err := exec.Command("/usr/bin/cat", foreign).CombinedOutput(); err != nil {
		t.Fatalf("cat: %v %s", err, out)
	}
	_ = os.Remove(foreign)

	var lat []time.Duration
	for i := 0; i < 5; i++ {
		nonce, err := newNonce()
		if err != nil {
			t.Fatal(err)
		}
		fired := time.Now()
		if err := s.Fire(nonce); err != nil {
			t.Fatalf("Fire: %v", err)
		}
		deadline := time.After(10 * time.Second)
	wait:
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					t.Fatalf("stream closed: %v", <-errc)
				}
				got, isSentinel := s.Nonce(ev)
				if ev.Kprobe != nil {
					t.Logf("SENTINEL event policy=%s fn=%s binary=%s action=%s args=%d nonce_ok=%t",
						ev.Kprobe.GetPolicyName(), ev.Kprobe.GetFunctionName(), ev.Kprobe.GetProcess().GetBinary(), ev.Kprobe.GetAction(), len(ev.Kprobe.GetArgs()), isSentinel)
					if ev.Kprobe.GetProcess().GetBinary() == "/usr/bin/cat" {
						t.Fatalf("an open by /usr/bin/cat matched the sentinel policy")
					}
					if ev.Kprobe.GetAction().String() != "KPROBE_ACTION_POST" {
						t.Fatalf("sentinel action %s, want POST", ev.Kprobe.GetAction())
					}
				}
				if isSentinel && got == nonce {
					lat = append(lat, time.Since(fired))
					break wait
				}
			case <-deadline:
				t.Fatalf("sentinel %d did not arrive within 10s", i)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("SENTINEL latencies on an idle runner: %v", lat)
}
