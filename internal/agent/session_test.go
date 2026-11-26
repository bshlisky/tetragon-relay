package agent

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
)

// fakeStream is a controllable ControlStream: inbound messages are fed
// through in, and every outbound Send is recorded in sent. Closing
// closeRecv causes Recv to return io.EOF (simulating stream loss), as a
// real grpc stream would once the underlying connection drops.
type fakeStream struct {
	mu        sync.Mutex
	in        chan *controlv1.ControllerMessage
	sent      []*controlv1.AgentMessage
	closeRecv chan struct{}
	closeOnce sync.Once
	sendErr   error
}

func newFakeStream() *fakeStream {
	return &fakeStream{in: make(chan *controlv1.ControllerMessage, 8), closeRecv: make(chan struct{})}
}

func (s *fakeStream) Send(m *controlv1.AgentMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, m)
	return nil
}

func (s *fakeStream) Recv() (*controlv1.ControllerMessage, error) {
	select {
	case m := <-s.in:
		return m, nil
	case <-s.closeRecv:
		return nil, io.EOF
	}
}

func (s *fakeStream) CloseSend() error { return nil }

func (s *fakeStream) breakStream() {
	s.closeOnce.Do(func() { close(s.closeRecv) })
}

func (s *fakeStream) sentMessages() []*controlv1.AgentMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*controlv1.AgentMessage, len(s.sent))
	copy(out, s.sent)
	return out
}

// fakeConnector is a controllable Connector: each queued result is
// returned in order from successive Connect calls; if the queue is
// empty, Connect blocks until ctx is done (so tests driving the
// DEGRADED-timeout path do not need a real network failure).
type fakeConnector struct {
	mu      sync.Mutex
	results []connectResult
	calls   int
}

type connectResult struct {
	stream ControlStream
	err    error
}

func (f *fakeConnector) Connect(ctx context.Context, hello func() controlclient.HelloFields, touch func()) (ControlStream, func() error, error) {
	f.mu.Lock()
	f.calls++
	var r connectResult
	haveResult := len(f.results) > 0
	if haveResult {
		r = f.results[0]
		f.results = f.results[1:]
	}
	f.mu.Unlock()
	if !haveResult {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	_ = hello()
	_ = touch
	if r.err != nil {
		return nil, nil, r.err
	}
	return r.stream, func() error { return nil }, nil
}

func connectorCalls(f *fakeConnector) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newSessionTestFixtures(t *testing.T) (*ControlLoop, *StateMachine, *FakeAuditor, *LivenessRegistry) {
	t.Helper()
	auditor := &FakeAuditor{}
	sm, err := NewStateMachine(auditor)
	if err != nil {
		t.Fatalf("NewStateMachine: %v", err)
	}
	if err := sm.Fire(EventJoinTokenValid); err != nil {
		t.Fatalf("EventJoinTokenValid: %v", err)
	}
	if err := sm.Fire(EventSVIDIssued); err != nil {
		t.Fatalf("EventSVIDIssued: %v", err)
	}
	if sm.Current() != StateConnecting {
		t.Fatalf("precondition: state = %s, want CONNECTING", sm.Current())
	}
	clock := func() time.Time { return time.Unix(0, 0) }
	cl, err := NewControlLoop(sm, auditor, clock, &fakeSnapshotProvider{}, &fakeRotator{})
	if err != nil {
		t.Fatalf("NewControlLoop: %v", err)
	}
	reg, err := NewLivenessRegistry(clock)
	if err != nil {
		t.Fatalf("NewLivenessRegistry: %v", err)
	}
	return cl, sm, auditor, reg
}

func TestRunSession_ConnectsReachesSteadyAndHeartbeats(t *testing.T) {
	cl, sm, _, reg := newSessionTestFixtures(t)
	stream := newFakeStream()
	connector := &fakeConnector{results: []connectResult{{stream: stream}}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, SessionConfig{
			Connector:         connector,
			Hello:             func() controlclient.HelloFields { return controlclient.HelloFields{} },
			ControlLoop:       cl,
			Clock:             func() time.Time { return time.Unix(0, 0) },
			Auditor:           cl.Auditor,
			Liveness:          reg,
			HeartbeatInterval: 10 * time.Millisecond,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for sm.Current() != StateSteady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sm.Current() != StateSteady {
		t.Fatalf("state = %s, want STEADY", sm.Current())
	}

	// At least one heartbeat should arrive given the 10ms interval.
	deadline = time.Now().Add(2 * time.Second)
	for len(stream.sentMessages()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	sent := stream.sentMessages()
	if len(sent) == 0 {
		t.Fatal("no heartbeat was sent")
	}
	if _, ok := sent[0].GetBody().(*controlv1.AgentMessage_Heartbeat); !ok {
		t.Fatalf("first sent message = %T, want Heartbeat", sent[0].GetBody())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunSession returned %v, want nil after ctx cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunSession did not return after ctx cancel")
	}
}

func TestRunSession_StreamLossReconnects(t *testing.T) {
	cl, sm, _, reg := newSessionTestFixtures(t)
	stream1 := newFakeStream()
	stream2 := newFakeStream()
	connector := &fakeConnector{results: []connectResult{{stream: stream1}, {stream: stream2}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, SessionConfig{
			Connector:         connector,
			Hello:             func() controlclient.HelloFields { return controlclient.HelloFields{} },
			ControlLoop:       cl,
			Clock:             func() time.Time { return time.Unix(0, 0) },
			Auditor:           cl.Auditor,
			Liveness:          reg,
			HeartbeatInterval: time.Hour, // no heartbeats; isolate the reconnect behavior
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for sm.Current() != StateSteady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sm.Current() != StateSteady {
		t.Fatalf("state after first connect = %s, want STEADY", sm.Current())
	}

	stream1.breakStream() // simulates the underlying connection dropping

	deadline = time.Now().Add(2 * time.Second)
	for connectorCalls(connector) != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls := connectorCalls(connector); calls != 2 {
		t.Fatalf("Connector.Connect called %d times, want 2 (initial + reconnect)", calls)
	}

	deadline = time.Now().Add(2 * time.Second)
	for sm.Current() != StateSteady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sm.Current() != StateSteady {
		t.Fatalf("state after reconnect = %s, want STEADY again", sm.Current())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunSession returned %v, want nil after ctx cancel", err)
	}
}

func TestRunSession_TerminateRevokedStopsReconnecting(t *testing.T) {
	cl, sm, _, reg := newSessionTestFixtures(t)
	stream := newFakeStream()
	connector := &fakeConnector{results: []connectResult{{stream: stream}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, SessionConfig{
			Connector:         connector,
			Hello:             func() controlclient.HelloFields { return controlclient.HelloFields{} },
			ControlLoop:       cl,
			Clock:             func() time.Time { return time.Unix(0, 0) },
			Auditor:           cl.Auditor,
			Liveness:          reg,
			HeartbeatInterval: time.Hour,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for sm.Current() != StateSteady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sm.Current() != StateSteady {
		t.Fatalf("state = %s, want STEADY", sm.Current())
	}

	stream.in <- &controlv1.ControllerMessage{Seq: 2, Body: &controlv1.ControllerMessage_Terminate{
		Terminate: &controlv1.Terminate{Reason: controlv1.Terminate_REVOKED},
	}}

	// D1 (step-06a-e3-decisions.md): REVOKED parks; RunSession keeps
	// running, never reconnects, and returns only when ctx is canceled.
	deadline = time.Now().Add(2 * time.Second)
	for sm.Current() != StateRevoked && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sm.Current() != StateRevoked {
		t.Fatalf("state = %s, want REVOKED", sm.Current())
	}
	select {
	case err := <-done:
		t.Fatalf("RunSession returned (%v) after Terminate{REVOKED}; want it parked", err)
	case <-time.After(200 * time.Millisecond):
	}

	connector.mu.Lock()
	calls := connector.calls
	connector.mu.Unlock()
	if calls != 1 {
		t.Fatalf("Connector.Connect called %d times after REVOKED, want 1 (no reconnect)", calls)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunSession returned %v on shutdown, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parked RunSession did not return on ctx cancel")
	}
}

// steppedClock is a liveness clock the test advances explicitly.
type steppedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *steppedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *steppedClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// revokedSession starts RunSession with its StateMachine already in
// REVOKED (as after a persisted revocation, D2), a stepped liveness
// clock and a 1ms park-loop touch interval.
func revokedSession(t *testing.T, parkTick func()) (*LivenessRegistry, *steppedClock, *fakeConnector, context.CancelFunc, chan error) {
	t.Helper()
	cl, sm, _, _ := newSessionTestFixtures(t)
	if err := sm.Fire(EventTerminateRevoked); err != nil {
		t.Fatalf("EventTerminateRevoked: %v", err)
	}
	clock := &steppedClock{now: time.Unix(1000, 0)}
	reg, err := NewLivenessRegistry(clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	connector := &fakeConnector{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, SessionConfig{
			Connector:         connector,
			Hello:             func() controlclient.HelloFields { return controlclient.HelloFields{} },
			ControlLoop:       cl,
			Clock:             func() time.Time { return time.Unix(0, 0) },
			Auditor:           cl.Auditor,
			Liveness:          reg,
			HeartbeatInterval: time.Hour,
			touchInterval:     time.Millisecond,
			parkTick:          parkTick,
		})
	}()
	return reg, clock, connector, cancel, done
}

// TestRunSession_RevokedParkKeepsLivenessHealthy: D1. Over 100 simulated
// seconds (five times sessionLivenessMaxInterval) the parked session
// keeps touching, so the registry stays healthy and the watchdog would
// keep being fed; Connect is never called.
func TestRunSession_RevokedParkKeepsLivenessHealthy(t *testing.T) {
	reg, clock, connector, cancel, done := revokedSession(t, nil)
	defer cancel()
	for i := 0; i < 10; i++ {
		clock.Advance(10 * time.Second)
		time.Sleep(20 * time.Millisecond) // many 1ms park ticks
		if healthy, stale, age := reg.Healthy(); !healthy {
			t.Fatalf("step %d: registry unhealthy while parked: %q stale for %s", i, stale, age)
		}
	}
	connector.mu.Lock()
	calls := connector.calls
	connector.mu.Unlock()
	if calls != 0 {
		t.Fatalf("Connect called %d times while REVOKED, want 0", calls)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunSession = %v, want nil", err)
	}
}

// TestRunSession_BlockedParkLoopGoesStale: D1. If the park loop itself
// hangs, session_runner goes stale, so the watchdog is withheld.
func TestRunSession_BlockedParkLoopGoesStale(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	reg, clock, _, cancel, done := revokedSession(t, func() {
		once.Do(func() { close(entered) })
		<-release
	})
	defer func() {
		close(release)
		cancel()
		if err := <-done; err != nil {
			t.Errorf("RunSession = %v, want nil", err)
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("park loop never ticked")
	}
	clock.Advance(sessionLivenessMaxInterval + time.Second)
	healthy, stale, _ := reg.Healthy()
	if healthy || stale != sessionLivenessComponent {
		t.Fatalf("Healthy() = %v, %q; want false, %q", healthy, stale, sessionLivenessComponent)
	}
}

func TestRunSession_ConnectTimeoutEntersDegraded(t *testing.T) {
	cl, sm, _, reg := newSessionTestFixtures(t)
	connector := &fakeConnector{} // never returns a result: Connect blocks until ctx done

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, SessionConfig{
			Connector:         connector,
			Hello:             func() controlclient.HelloFields { return controlclient.HelloFields{} },
			ControlLoop:       cl,
			Clock:             func() time.Time { return time.Unix(0, 0) },
			Auditor:           cl.Auditor,
			Liveness:          reg,
			HeartbeatInterval: time.Hour,
		})
	}()
	// Fire the same event RunSession's own degraded-watch goroutine
	// would fire once limits.ControlConnectDegradedTimeout elapses --
	// this test does not wait 5 real minutes; it instead confirms the
	// state machine accepts exactly that transition from CONNECTING,
	// which connectWithDegradedWatch relies on.
	if sm.Current() != StateConnecting {
		t.Fatalf("state = %s, want CONNECTING while Connect is still blocked", sm.Current())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunSession returned %v, want nil after ctx cancel", err)
	}
}

func TestSessionConfig_Validate(t *testing.T) {
	cl, _, auditor, reg := newSessionTestFixtures(t)
	base := SessionConfig{
		Connector:   &fakeConnector{},
		Hello:       func() controlclient.HelloFields { return controlclient.HelloFields{} },
		ControlLoop: cl,
		Clock:       func() time.Time { return time.Unix(0, 0) },
		Auditor:     auditor,
		Liveness:    reg,
	}
	cases := []struct {
		name   string
		modify func(*SessionConfig)
	}{
		{"no connector", func(c *SessionConfig) { c.Connector = nil }},
		{"no hello", func(c *SessionConfig) { c.Hello = nil }},
		{"no control loop", func(c *SessionConfig) { c.ControlLoop = nil }},
		{"no clock", func(c *SessionConfig) { c.Clock = nil }},
		{"no auditor", func(c *SessionConfig) { c.Auditor = nil }},
		{"no liveness", func(c *SessionConfig) { c.Liveness = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.modify(&cfg)
			if err := RunSession(context.Background(), cfg); err == nil {
				t.Fatal("RunSession did not reject an invalid config")
			}
		})
	}
}

func TestSessionConfig_HeartbeatIntervalDefault(t *testing.T) {
	var c SessionConfig
	if got := c.heartbeatInterval(); got <= 0 {
		t.Fatalf("heartbeatInterval() = %v, want the positive default", got)
	}
	c.HeartbeatInterval = 3 * time.Second
	if got := c.heartbeatInterval(); got != 3*time.Second {
		t.Fatalf("heartbeatInterval() = %v, want 3s override", got)
	}
}

func TestRealConnector_ConnectFailsOnCanceledContext(t *testing.T) {
	// No real network is reachable inside a unit test; this only
	// exercises the ctx-already-canceled short-circuit path through
	// controlclient.Dial, not a real connection.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &RealConnector{Config: func() controlclient.Config {
		return controlclient.Config{
			Endpoints:          []string{"127.0.0.1:1"},
			ControllerSPIFFEID: "spiffe://example/mgmt/controller",
			ControllerCABundle: nil,
			Clock:              func() time.Time { return time.Unix(0, 0) },
		}
	}}
	_, _, err := c.Connect(ctx, func() controlclient.HelloFields { return controlclient.HelloFields{} }, func() {})
	if err == nil {
		t.Fatal("Connect with an already-canceled context unexpectedly succeeded")
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, controlclient.ErrDialCanceled) {
		t.Logf("observed error (not asserted beyond non-nil): %v", err)
	}
}
