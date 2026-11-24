package apply

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// inProcessClient is a lightweight, in-memory TetragonClient for
// runHealthWindow's own unit tests: deterministic and fast (no real
// network I/O), so tests that need the ticker to actually fire several
// times within a short window (surge threshold, admin-path mid-window)
// are not flaky the way a real gRPC round trip under the race detector
// can be.
type inProcessClient struct {
	healthy      bool
	events       []tetra.Event
	getEventsErr error
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

func (c *inProcessClient) GetEvents(ctx context.Context, _ []string) (<-chan tetra.Event, <-chan error) {
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
		<-ctx.Done()
	}()
	return events, errc
}

var _ TetragonClient = (*inProcessClient)(nil)

func TestRunHealthWindow_Pass(t *testing.T) {
	c := &inProcessClient{healthy: true}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 100 * time.Millisecond, PollInterval: 20 * time.Millisecond}, nil)
	if !ok {
		t.Fatalf("runHealthWindow failed: %s", reason)
	}
}

func TestRunHealthWindow_NotServing(t *testing.T) {
	c := &inProcessClient{healthy: false}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 200 * time.Millisecond, PollInterval: 20 * time.Millisecond}, nil)
	if ok || reason != reasonHealthNotServing {
		t.Fatalf("reason=%s ok=%v, want reasonHealthNotServing/false", reason, ok)
	}
}

func TestRunHealthWindow_ControlPlaneDownEntireWindow(t *testing.T) {
	c := &inProcessClient{healthy: true}
	reach := &FakeReachabilityChecker{ReachableValue: false}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 100 * time.Millisecond, PollInterval: 20 * time.Millisecond}, nil)
	if ok || reason != reasonControlPlaneDown {
		t.Fatalf("reason=%s ok=%v, want reasonControlPlaneDown/false", reason, ok)
	}
}

func TestRunHealthWindow_AdminPathEvent(t *testing.T) {
	c := &inProcessClient{
		healthy: true,
		events: []tetra.Event{
			{Kprobe: &tetragonpb.ProcessKprobe{Process: &tetragonpb.Process{Binary: "/usr/sbin/sshd"}, Action: tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL}},
		},
	}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 500 * time.Millisecond, PollInterval: 50 * time.Millisecond}, nil)
	if ok || reason != reasonAdminPathEnforced {
		t.Fatalf("reason=%s ok=%v, want reasonAdminPathEnforced/false", reason, ok)
	}
}

func TestRunHealthWindow_Surge(t *testing.T) {
	var events []tetra.Event
	for i := 0; i < 10; i++ {
		events = append(events, tetra.Event{Kprobe: &tetragonpb.ProcessKprobe{Process: &tetragonpb.Process{Binary: "/usr/bin/other"}, Action: tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL}})
	}
	c := &inProcessClient{healthy: true, events: events}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 500 * time.Millisecond, PollInterval: 50 * time.Millisecond, SurgeThreshold: 3}, nil)
	if ok || reason != reasonEnforcementSurge {
		t.Fatalf("reason=%s ok=%v, want reasonEnforcementSurge/false", reason, ok)
	}
}

// TestRunHealthWindow_GetEventsError's fake (inProcessClient.GetEvents)
// sends the error to errc and then closes both errc and events together
// (mirroring internal/tetra.GetEvents' own defer close(events)/close(errc)
// pattern), well before the 200ms window ends. Which of the two closed/
// ready channels select picks first is a genuine, harmless race (the same
// one TestRunHealthWindow_ErrorBeforeDeadline_Fails documents): either the
// errc branch (err != nil, windowCtx still open -> reasonHealthNotServing)
// or the events branch (closed, windowCtx still open -> an early,
// otherwise-unexplained stream close -> reasonEventStreamClosed) is
// correct here, since the window is nowhere near its own deadline in
// either case. Only these two named reasons are accepted — not "any
// error" — so a real regression that produced some other reason, or
// ok=true, would still fail this test.
func TestRunHealthWindow_GetEventsError(t *testing.T) {
	c := &inProcessClient{healthy: true, getEventsErr: errors.New("stream broke")}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 200 * time.Millisecond, PollInterval: 20 * time.Millisecond}, nil)
	if ok || (reason != reasonHealthNotServing && reason != reasonEventStreamClosed) {
		t.Fatalf("reason=%s ok=%v, want false with reasonHealthNotServing or reasonEventStreamClosed", reason, ok)
	}
}

// ctxControlledClient is a TetragonClient whose GetEvents lets a test
// control exactly when, relative to ctx's own cancellation, the stream
// errors or closes — step-03a-review.md R3-4's deterministic, no-sleep
// tests of the windowCtx/errc/events race at runHealthWindow's deadline.
type ctxControlledClient struct {
	healthy   bool
	getEvents func(ctx context.Context) (<-chan tetra.Event, <-chan error)
}

func (c *ctxControlledClient) AddTracingPolicy(context.Context, string, string) error    { return nil }
func (c *ctxControlledClient) DeleteTracingPolicy(context.Context, string, string) error { return nil }
func (c *ctxControlledClient) ListTracingPolicies(context.Context, string) ([]tetra.TracingPolicyStatus, error) {
	return nil, nil
}
func (c *ctxControlledClient) RequireVersion(context.Context) (string, error) { return "v1.8.0", nil }

func (c *ctxControlledClient) GetHealth(context.Context) ([]*tetragonpb.HealthStatus, error) {
	status := tetragonpb.HealthStatusResult_HEALTH_STATUS_RUNNING
	if !c.healthy {
		status = tetragonpb.HealthStatusResult_HEALTH_STATUS_ERROR
	}
	return []*tetragonpb.HealthStatus{{Status: status}}, nil
}

func (c *ctxControlledClient) GetEvents(ctx context.Context, _ []string) (<-chan tetra.Event, <-chan error) {
	return c.getEvents(ctx)
}

var _ TetragonClient = (*ctxControlledClient)(nil)

// TestRunHealthWindow_ErrorExactlyAtDeadline_Passes is the R3-4
// regression: a stream error that is only ever sent strictly after
// windowCtx has already ended (synchronized via <-ctx.Done(), not a
// sleep) must never fail an otherwise-healthy window, regardless of
// which select branch (windowCtx.Done() or errc) happens to run first.
func TestRunHealthWindow_ErrorExactlyAtDeadline_Passes(t *testing.T) {
	c := &ctxControlledClient{
		healthy: true,
		getEvents: func(ctx context.Context) (<-chan tetra.Event, <-chan error) {
			events := make(chan tetra.Event)
			errc := make(chan error, 1)
			go func() {
				defer close(events)
				defer close(errc)
				<-ctx.Done() // only send once windowCtx has actually ended
				errc <- errors.New("stream error racing the deadline")
			}()
			return events, errc
		},
	}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 50 * time.Millisecond, PollInterval: 10 * time.Millisecond}, nil)
	if !ok {
		t.Fatalf("reason=%s ok=%v, want ok=true (an error strictly after the deadline must not fail an otherwise-healthy window)", reason, ok)
	}
}

// TestRunHealthWindow_ErrorBeforeDeadline_Fails covers the same error
// path when the window is nowhere near its deadline: it must still fail
// health. The window is deliberately far longer than this test could
// possibly run (no sleep is used; the error is sent synchronously,
// essentially immediately), so "before the deadline" is structural, not
// timing-dependent. The fake closes events right after sending the
// error (mirroring internal/tetra.GetEvents' own defer close(events)),
// so either select branch (errc's error, or events closing first) is a
// legitimate, race-free outcome here — both are a failure before the
// deadline; this only asserts that the window fails, not which of the
// two "before the deadline" reasons is observed.
func TestRunHealthWindow_ErrorBeforeDeadline_Fails(t *testing.T) {
	c := &ctxControlledClient{
		healthy: true,
		getEvents: func(context.Context) (<-chan tetra.Event, <-chan error) {
			events := make(chan tetra.Event)
			errc := make(chan error, 1)
			go func() {
				defer close(events)
				defer close(errc)
				errc <- errors.New("stream error well before the deadline")
			}()
			return events, errc
		},
	}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: time.Hour, PollInterval: time.Hour}, nil)
	if ok || (reason != reasonHealthNotServing && reason != reasonEventStreamClosed) {
		t.Fatalf("reason=%s ok=%v, want false with reasonHealthNotServing or reasonEventStreamClosed", reason, ok)
	}
}

// TestRunHealthWindow_StreamClosesEarly_Fails covers R3-4's other
// required case: the events channel closing cleanly (no error at all)
// well before the window's deadline must also fail health — Tetragon
// ending the event stream early is itself a health signal, not something
// to silently ignore.
func TestRunHealthWindow_StreamClosesEarly_Fails(t *testing.T) {
	c := &ctxControlledClient{
		healthy: true,
		getEvents: func(context.Context) (<-chan tetra.Event, <-chan error) {
			events := make(chan tetra.Event)
			errc := make(chan error, 1)
			close(events)
			close(errc)
			return events, errc
		},
	}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: time.Hour, PollInterval: time.Hour}, nil)
	if ok || reason != reasonEventStreamClosed {
		t.Fatalf("reason=%s ok=%v, want reasonEventStreamClosed/false", reason, ok)
	}
}

// TestRunHealthWindow_ErrTimeoutBeforeWindowCtxErrObserved_Passes covers a
// real race found running TestApply_HappyPath_Enforce -count=200 -race
// (step-03a-review.md R3-4's required stress run): internal/tetra.
// GetEvents has no timeout of its own separate from windowCtx (Part B3;
// unlike every other RPC method), so a gRPC DeadlineExceeded status for
// it — even one that arrives, under scheduling load, before this
// goroutine's own windowCtx.Err() happens to have been set yet — can only
// ever mean windowCtx's own deadline. This sends a tetra.ErrTimeout-
// wrapped error on errc immediately, before the window's local deadline,
// confirming the window still passes without relying on windowCtx.Err()
// being observably non-nil yet.
func TestRunHealthWindow_ErrTimeoutBeforeWindowCtxErrObserved_Passes(t *testing.T) {
	c := &ctxControlledClient{
		healthy: true,
		getEvents: func(context.Context) (<-chan tetra.Event, <-chan error) {
			events := make(chan tetra.Event)
			errc := make(chan error, 1)
			go func() {
				defer close(events)
				defer close(errc)
				errc <- fmt.Errorf("%w: GetEvents", tetra.ErrTimeout)
			}()
			return events, errc
		},
	}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: time.Hour, PollInterval: time.Hour}, nil)
	if !ok {
		t.Fatalf("reason=%s ok=%v, want ok=true (a tetra.ErrTimeout from GetEvents can only mean windowCtx's own deadline)", reason, ok)
	}
}

// TestRunHealthWindow_StreamClosesExactlyAtDeadline_Passes mirrors
// TestRunHealthWindow_ErrorExactlyAtDeadline_Passes for a clean close
// instead of an error: internal/tetra.GetEvents closes both channels,
// without sending, exactly when its ctx ends (client.go's ctx.Err()
// check) — ending up here as events closing (ok=false) right at the
// deadline, which must still pass.
func TestRunHealthWindow_StreamClosesExactlyAtDeadline_Passes(t *testing.T) {
	c := &ctxControlledClient{
		healthy: true,
		getEvents: func(ctx context.Context) (<-chan tetra.Event, <-chan error) {
			events := make(chan tetra.Event)
			errc := make(chan error, 1)
			go func() {
				defer close(events)
				defer close(errc)
				<-ctx.Done()
			}()
			return events, errc
		},
	}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 50 * time.Millisecond, PollInterval: 10 * time.Millisecond}, nil)
	if !ok {
		t.Fatalf("reason=%s ok=%v, want ok=true (the stream closing exactly at the deadline must not fail an otherwise-healthy window)", reason, ok)
	}
}

func TestCheckHealthServing_EmptyResponseIsNotServing(t *testing.T) {
	c := &inProcessClient{healthy: true}
	// Override GetHealth via a thin wrapper that returns an empty slice.
	_, ok := checkHealthServing(context.Background(), emptyHealthClient{c})
	if ok {
		t.Fatal("checkHealthServing treated an empty HealthStatus list as serving")
	}
}

type emptyHealthClient struct{ TetragonClient }

func (emptyHealthClient) GetHealth(context.Context) ([]*tetragonpb.HealthStatus, error) {
	return nil, nil
}
