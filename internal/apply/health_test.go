package apply

import (
	"context"
	"errors"
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

func TestRunHealthWindow_GetEventsError(t *testing.T) {
	c := &inProcessClient{healthy: true, getEventsErr: errors.New("stream broke")}
	reach := &FakeReachabilityChecker{ReachableValue: true}
	reason, ok := runHealthWindow(context.Background(), c, reach, HealthWindowConfig{Window: 200 * time.Millisecond, PollInterval: 20 * time.Millisecond}, nil)
	if ok || reason != reasonHealthNotServing {
		t.Fatalf("reason=%s ok=%v, want reasonHealthNotServing/false", reason, ok)
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
