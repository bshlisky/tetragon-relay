package apply

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// inProcessClient is a lightweight, in-memory TetragonClient for
// runHealthWindow's own unit tests: deterministic and fast (no real
// network I/O). events are sent first; then anything handed to live (the
// fake sentinel's deliveries) is forwarded until ctx ends. A nil live
// channel is a stub stream that delivers nothing after events.
type inProcessClient struct {
	healthy      bool
	events       []tetra.Event
	getEventsErr error
	// closeAfterEvents ends the stream (closes both channels) once events
	// were sent.
	closeAfterEvents bool
	live             chan tetra.Event

	mu    sync.Mutex
	names []string
}

func newInProcessClient(healthy bool) *inProcessClient {
	return &inProcessClient{healthy: healthy, live: make(chan tetra.Event, 1024)}
}

func (c *inProcessClient) deliver(ev tetra.Event) {
	if c.live != nil {
		c.live <- ev
	}
}

func (c *inProcessClient) AddTracingPolicy(context.Context, string, string) error    { return nil }
func (c *inProcessClient) DeleteTracingPolicy(context.Context, string, string) error { return nil }
func (c *inProcessClient) ListTracingPolicies(context.Context, string) ([]tetra.TracingPolicyStatus, error) {
	return nil, nil
}
func (c *inProcessClient) RequireVersion(context.Context) (string, error) { return "v1.8.0", nil }

func (c *inProcessClient) GetHealth(context.Context) ([]*tetragonpb.HealthStatus, error) {
	status := tetragonpb.HealthStatusResult_HEALTH_STATUS_RUNNING
	if !c.healthy {
		status = tetragonpb.HealthStatusResult_HEALTH_STATUS_ERROR
	}
	return []*tetragonpb.HealthStatus{{Status: status}}, nil
}

func (c *inProcessClient) GetEvents(ctx context.Context, names []string) (<-chan tetra.Event, <-chan error) {
	c.mu.Lock()
	c.names = append([]string(nil), names...)
	c.mu.Unlock()
	events := make(chan tetra.Event)
	errc := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errc)
		if c.getEventsErr != nil {
			errc <- c.getEventsErr
			return
		}
		for _, ev := range c.events {
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
		if c.closeAfterEvents {
			return
		}
		for {
			select {
			case ev := <-c.live: // nil live blocks forever: the stub stream
				select {
				case events <- ev:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return events, errc
}

var _ TetragonClient = (*inProcessClient)(nil)

// fastWindow: a 100 ms nominal window, sentinels every 10 ms that must
// arrive within 40 ms, 5 ms settle, at most 600 ms in all.
func fastWindow() HealthWindowConfig {
	return HealthWindowConfig{
		Window: 100 * time.Millisecond, PollInterval: 20 * time.Millisecond,
		SentinelInterval: 10 * time.Millisecond, SentinelMaxLatency: 40 * time.Millisecond,
		SettleMargin: 5 * time.Millisecond, MaxWindow: 600 * time.Millisecond,
	}
}

func run(t *testing.T, c *inProcessClient, s Sentinel, reachable bool, cfg HealthWindowConfig) windowOutcome {
	t.Helper()
	return runHealthWindow(context.Background(), c, &FakeReachabilityChecker{ReachableValue: reachable}, s, cfg, []string{"p1-v1-00000000"})
}

func TestRunHealthWindow_Pass(t *testing.T) {
	c := newInProcessClient(true)
	s := newFakeSentinel(t, c.deliver)
	start := time.Now()
	out := run(t, c, s, true, fastWindow())
	if !out.passed {
		t.Fatalf("window failed: %s (%s)", out.reason, out.stats.Summary())
	}
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Fatalf("passed after %s, before the nominal 100ms", el)
	}
	if out.stats.Arrived == 0 || out.stats.Late != 0 || out.stats.Restarts != 0 {
		t.Fatalf("stats = %s", out.stats.Summary())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.names) != 2 || c.names[1] != s.PolicyName() {
		t.Fatalf("GetEvents names = %v, want the bundle's policies plus %s", c.names, s.PolicyName())
	}
}

// TestRunHealthWindow_StubStreamDeliversNothing_NeverPasses is F0.3's unit
// mutation test: the exact P5 failure (silence read as health). A stream
// that delivers nothing, sentinels included, must end unverifiable.
func TestRunHealthWindow_StubStreamDeliversNothing_NeverPasses(t *testing.T) {
	c := &inProcessClient{healthy: true} // live == nil: delivers nothing
	s := newFakeSentinel(t, func(tetra.Event) {})
	start := time.Now()
	out := run(t, c, s, true, fastWindow())
	if out.passed || out.reason != reasonUnverifiable {
		t.Fatalf("passed=%t reason=%s, want unverifiable", out.passed, out.reason)
	}
	if el := time.Since(start); el < 600*time.Millisecond {
		t.Fatalf("gave up after %s, before MaxWindow", el)
	}
	if out.stats.Arrived != 0 || out.stats.Fired == 0 || out.stats.Late == 0 {
		t.Fatalf("stats = %s", out.stats.Summary())
	}
}

func TestRunHealthWindow_NoSentinel_NeverPasses(t *testing.T) {
	c := newInProcessClient(true)
	out := run(t, c, nil, true, fastWindow())
	if out.passed || out.reason != reasonUnverifiable {
		t.Fatalf("passed=%t reason=%s, want unverifiable", out.passed, out.reason)
	}
}

func TestRunHealthWindow_FireErrors_NeverPasses(t *testing.T) {
	c := newInProcessClient(true)
	s := newFakeSentinel(t, c.deliver)
	s.fireErr = errors.New("EACCES")
	out := run(t, c, s, true, fastWindow())
	if out.passed || out.reason != reasonUnverifiable || out.stats.FireErrors == 0 {
		t.Fatalf("passed=%t reason=%s stats=%s, want unverifiable with fire errors", out.passed, out.reason, out.stats.Summary())
	}
}

// Late for the first 150 ms, then current: the window extends and passes
// a full nominal window after recovery.
func TestRunHealthWindow_LateThenRecovers_ExtendsAndPasses(t *testing.T) {
	c := newInProcessClient(true)
	s := newFakeSentinel(t, c.deliver)
	t0 := time.Now()
	s.setPlan(func(int) (time.Duration, bool) {
		if time.Since(t0) < 150*time.Millisecond {
			return 80 * time.Millisecond, false // over the 40 ms limit
		}
		return 0, false
	})
	out := run(t, c, s, true, fastWindow())
	if !out.passed {
		t.Fatalf("window failed: %s (%s)", out.reason, out.stats.Summary())
	}
	if out.stats.Late == 0 || out.stats.Restarts == 0 {
		t.Fatalf("expected late sentinels and a restart: %s", out.stats.Summary())
	}
	if el := time.Since(t0); el < 250*time.Millisecond {
		t.Fatalf("passed after %s; want at least 150ms late + 100ms clean", el)
	}
}

func TestRunHealthWindow_AlwaysLate_Unverifiable(t *testing.T) {
	c := newInProcessClient(true)
	s := newFakeSentinel(t, c.deliver)
	s.setPlan(func(int) (time.Duration, bool) { return 60 * time.Millisecond, false })
	out := run(t, c, s, true, fastWindow())
	if out.passed || out.reason != reasonUnverifiable {
		t.Fatalf("passed=%t reason=%s, want unverifiable", out.passed, out.reason)
	}
	if out.stats.Arrived == 0 || out.stats.MaxLatency < 40*time.Millisecond || len(out.stats.Latencies) == 0 {
		t.Fatalf("latencies not recorded: %s", out.stats.Summary())
	}
	if !strings.Contains(out.stats.Summary(), "last_ms=[") {
		t.Fatalf("summary lacks latencies: %s", out.stats.Summary())
	}
}

// Every other sentinel is lost: never a clean span, never a pass.
func TestRunHealthWindow_IntermittentLoss_Unverifiable(t *testing.T) {
	c := newInProcessClient(true)
	s := newFakeSentinel(t, c.deliver)
	s.setPlan(func(n int) (time.Duration, bool) { return 0, n%2 == 0 })
	out := run(t, c, s, true, fastWindow())
	if out.passed || out.reason != reasonUnverifiable {
		t.Fatalf("passed=%t reason=%s, want unverifiable", out.passed, out.reason)
	}
}

// Reordering: the closing sentinel arrives while an earlier one in the
// span is still outstanding (within its latency). The window must wait for
// it, and passes once it arrives.
func TestRunHealthWindow_WaitsForOutstandingEarlierSentinel(t *testing.T) {
	c := newInProcessClient(true)
	s := newFakeSentinel(t, c.deliver)
	s.setPlan(func(n int) (time.Duration, bool) {
		if n == 9 {
			return 35 * time.Millisecond, false // late-ish but within 40 ms
		}
		return 0, false
	})
	out := run(t, c, s, true, fastWindow())
	if !out.passed {
		t.Fatalf("window failed: %s (%s)", out.reason, out.stats.Summary())
	}
}

func TestRunHealthWindow_NotServing(t *testing.T) {
	c := newInProcessClient(false)
	out := run(t, c, newFakeSentinel(t, c.deliver), true, fastWindow())
	if out.passed || out.reason != reasonHealthNotServing {
		t.Fatalf("passed=%t reason=%s, want reasonHealthNotServing", out.passed, out.reason)
	}
}

func TestRunHealthWindow_ControlPlaneDownEntireWindow(t *testing.T) {
	c := newInProcessClient(true)
	out := run(t, c, newFakeSentinel(t, c.deliver), false, fastWindow())
	if out.passed || out.reason != reasonControlPlaneDown {
		t.Fatalf("passed=%t reason=%s, want reasonControlPlaneDown", out.passed, out.reason)
	}
}

func adminKill() tetra.Event {
	return tetra.Event{Kprobe: &tetragonpb.ProcessKprobe{Process: &tetragonpb.Process{Binary: "/usr/sbin/sshd"}, Action: tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL}}
}

func TestRunHealthWindow_AdminPathEvent(t *testing.T) {
	c := newInProcessClient(true)
	c.events = []tetra.Event{adminKill()}
	out := run(t, c, newFakeSentinel(t, c.deliver), true, fastWindow())
	if out.passed || out.reason != reasonAdminPathEnforced {
		t.Fatalf("passed=%t reason=%s, want reasonAdminPathEnforced", out.passed, out.reason)
	}
}

// The P5 shape: sentinels late (the path is behind), then the kill event
// arrives during the extension. The window must fail on it, not end
// unverifiable and not pass.
func TestRunHealthWindow_AdminPathEventDuringExtension(t *testing.T) {
	c := newInProcessClient(true)
	s := newFakeSentinel(t, c.deliver)
	s.setPlan(func(int) (time.Duration, bool) { return 0, true }) // path stalled
	time.AfterFunc(200*time.Millisecond, func() { c.deliver(adminKill()) })
	out := run(t, c, s, true, fastWindow())
	if out.passed || out.reason != reasonAdminPathEnforced {
		t.Fatalf("passed=%t reason=%s, want reasonAdminPathEnforced", out.passed, out.reason)
	}
}

func TestRunHealthWindow_Surge(t *testing.T) {
	c := newInProcessClient(true)
	for i := 0; i < 10; i++ {
		c.events = append(c.events, tetra.Event{Kprobe: &tetragonpb.ProcessKprobe{Process: &tetragonpb.Process{Binary: "/usr/bin/other"}, Action: tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL}})
	}
	cfg := fastWindow()
	cfg.SurgeThreshold = 3
	out := run(t, c, newFakeSentinel(t, c.deliver), true, cfg)
	if out.passed || out.reason != reasonEnforcementSurge {
		t.Fatalf("passed=%t reason=%s, want reasonEnforcementSurge", out.passed, out.reason)
	}
}

// Sentinel events never count toward the surge or the admin-path rule.
func TestRunHealthWindow_SentinelsAreNotEnforcementEvents(t *testing.T) {
	c := newInProcessClient(true)
	cfg := fastWindow()
	cfg.SurgeThreshold = 1
	out := run(t, c, newFakeSentinel(t, c.deliver), true, cfg)
	if !out.passed {
		t.Fatalf("window failed: %s (%s)", out.reason, out.stats.Summary())
	}
}

// A sentinel-shaped event with an unknown nonce, or from another policy,
// proves nothing.
func TestRunHealthWindow_ForeignSentinelEventsIgnored(t *testing.T) {
	c := &inProcessClient{healthy: true}
	s := newFakeSentinel(t, func(tetra.Event) {})
	c.events = []tetra.Event{
		sentinelEvent(s.PolicyName(), "/var/lib/tetragon-relay/sentinel/"+strings.Repeat("a", 32)),
		sentinelEvent("someone-else", "/var/lib/tetragon-relay/sentinel/"+strings.Repeat("b", 32)),
	}
	out := run(t, c, s, true, fastWindow())
	if out.passed || out.reason != reasonUnverifiable || out.stats.Arrived != 0 {
		t.Fatalf("passed=%t reason=%s stats=%s, want unverifiable with nothing arrived", out.passed, out.reason, out.stats.Summary())
	}
}

func TestRunHealthWindow_GetEventsError(t *testing.T) {
	c := newInProcessClient(true)
	c.getEventsErr = errors.New("stream broke")
	out := run(t, c, newFakeSentinel(t, c.deliver), true, fastWindow())
	if out.passed || (out.reason != reasonEventStreamClosed && out.reason != reasonHealthNotServing) {
		t.Fatalf("passed=%t reason=%s", out.passed, out.reason)
	}
}

// No deadline is ever set on the window's stream, so a timeout from it is
// never "the window ended" (ADR 0042 retired the deadline-tolerance rule).
func TestRunHealthWindow_StreamTimeout_Fails(t *testing.T) {
	c := newInProcessClient(true)
	c.getEventsErr = fmt.Errorf("x: %w", tetra.ErrTimeout)
	out := run(t, c, newFakeSentinel(t, c.deliver), true, fastWindow())
	if out.passed {
		t.Fatalf("a stream timeout passed the window")
	}
}

func TestRunHealthWindow_StreamClosesEarly_Fails(t *testing.T) {
	c := newInProcessClient(true)
	c.closeAfterEvents = true
	out := run(t, c, newFakeSentinel(t, c.deliver), true, fastWindow())
	if out.passed || out.reason != reasonEventStreamClosed {
		t.Fatalf("passed=%t reason=%s, want reasonEventStreamClosed", out.passed, out.reason)
	}
}

func TestRunHealthWindow_Canceled_NeverPasses(t *testing.T) {
	c := newInProcessClient(true)
	s := newFakeSentinel(t, c.deliver)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	out := runHealthWindow(ctx, c, &FakeReachabilityChecker{ReachableValue: true}, s, fastWindow(), nil)
	if out.passed || out.reason != reasonCanceled {
		t.Fatalf("passed=%t reason=%s, want reasonCanceled", out.passed, out.reason)
	}
}

func TestRunHealthWindow_CPUStatDelta(t *testing.T) {
	c := newInProcessClient(true)
	cfg := fastWindow()
	var calls int
	cfg.CPUStat = func() (uint64, uint64, error) {
		calls++
		return uint64(calls) * 50_000, uint64(calls) * 3, nil
	}
	out := run(t, c, newFakeSentinel(t, c.deliver), true, cfg)
	if !out.passed || !out.stats.CPUOK || out.stats.CPUUsec != 50_000 || out.stats.Throttled != 3 {
		t.Fatalf("passed=%t stats=%+v", out.passed, out.stats)
	}
	if !strings.Contains(out.stats.Summary(), "nr_throttled=+3") {
		t.Fatalf("summary: %s", out.stats.Summary())
	}
}

func TestHealthWindowConfig_MaxWindowNeverBelowWindow(t *testing.T) {
	cfg := HealthWindowConfig{Window: time.Hour, MaxWindow: time.Minute}
	if cfg.maxWindow() != time.Hour {
		t.Fatalf("maxWindow = %s", cfg.maxWindow())
	}
	if (HealthWindowConfig{}).maxWindow() != 600*time.Second {
		t.Fatal("default maxWindow is not 600s")
	}
}

func TestCheckHealthServing_EmptyResponseIsNotServing(t *testing.T) {
	c := newInProcessClient(true)
	_, ok := checkHealthServing(context.Background(), emptyHealthClient{c})
	if ok {
		t.Fatal("checkHealthServing treated an empty HealthStatus list as serving")
	}
}

type emptyHealthClient struct{ TetragonClient }

func (emptyHealthClient) GetHealth(context.Context) ([]*tetragonpb.HealthStatus, error) {
	return nil, nil
}
