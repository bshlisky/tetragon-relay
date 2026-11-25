package agent

import (
	"testing"
	"time"
)

// fakeClock is a simple, test-controlled clock (ADR 0008's
// clock-injection convention): Now() returns whatever t currently is,
// advanced explicitly by the test, never the wall clock.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func TestNewLivenessRegistry_NilClockRejected(t *testing.T) {
	if _, err := NewLivenessRegistry(nil); err == nil {
		t.Fatal("NewLivenessRegistry(nil) did not error")
	}
}

func TestLivenessRegistry_AllHealthy(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	reg, err := NewLivenessRegistry(clock.Now)
	if err != nil {
		t.Fatalf("NewLivenessRegistry: %v", err)
	}
	reg.Register("session_runner", 20*time.Second)
	reg.Register("reconcile", 90*time.Second)

	if healthy, stale, _ := reg.Healthy(); !healthy {
		t.Fatalf("Healthy() = false, stale=%q; want true (fresh registration)", stale)
	}

	clock.Advance(10 * time.Second)
	reg.Touch("session_runner")
	clock.Advance(10 * time.Second)
	reg.Touch("reconcile")
	if healthy, stale, _ := reg.Healthy(); !healthy {
		t.Fatalf("Healthy() = false, stale=%q; want true (both touched within their interval)", stale)
	}
}

func TestLivenessRegistry_StalledComponentWithholdsHealthy(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	reg, err := NewLivenessRegistry(clock.Now)
	if err != nil {
		t.Fatalf("NewLivenessRegistry: %v", err)
	}
	reg.Register("session_runner", 20*time.Second)
	reg.Register("reconcile", 90*time.Second)

	// session_runner keeps reporting; reconcile stops (simulating a
	// deadlocked apply, a stuck stream: R6A-1's whole point is that
	// this must be caught, not just "a timer still fires").
	clock.Advance(15 * time.Second)
	reg.Touch("session_runner")
	clock.Advance(100 * time.Second) // reconcile's 90s interval is now well exceeded

	healthy, stale, staleFor := reg.Healthy()
	if healthy {
		t.Fatal("Healthy() = true; want false, reconcile has not reported within its interval")
	}
	if stale != "reconcile" {
		t.Fatalf("stale component = %q, want %q", stale, "reconcile")
	}
	if staleFor <= 90*time.Second {
		t.Fatalf("staleFor = %v, want > 90s", staleFor)
	}
}

func TestLivenessRegistry_ReRegisterResetsInterval(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	reg, err := NewLivenessRegistry(clock.Now)
	if err != nil {
		t.Fatalf("NewLivenessRegistry: %v", err)
	}
	reg.Register("session_runner", 20*time.Second)
	clock.Advance(50 * time.Second)
	if healthy, _, _ := reg.Healthy(); healthy {
		t.Fatal("Healthy() = true after 50s with no Touch and a 20s interval; want false")
	}
	reg.Register("session_runner", 20*time.Second) // simulates a reconnect: the component restarted, not stalled
	if healthy, stale, _ := reg.Healthy(); !healthy {
		t.Fatalf("Healthy() = false, stale=%q after re-Register; want true", stale)
	}
}

func TestLivenessRegistry_TouchOfUnregisteredComponentIsNoop(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	reg, err := NewLivenessRegistry(clock.Now)
	if err != nil {
		t.Fatalf("NewLivenessRegistry: %v", err)
	}
	reg.Touch("never_registered") // must not panic
	if healthy, stale, _ := reg.Healthy(); !healthy {
		t.Fatalf("Healthy() = false, stale=%q; want true (nothing registered)", stale)
	}
}
