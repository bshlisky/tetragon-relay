package agent

import (
	"context"
	"fmt"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// sessionLivenessComponent is this package's own name for RunSession in
// a LivenessRegistry (R6A-1): the first registered component, per
// step-06a-resume.md's D3/R6A-1 ordering.
const sessionLivenessComponent = "session_runner"

// sessionLivenessMaxInterval is how long RunSession may go without
// calling Liveness.Touch before it is considered stalled. It must stay
// comfortably under WatchdogSec/2 (packaging/systemd/tetragon-relay.
// service: WatchdogSec=30s, so cmd/relayd's watchdog loop checks every
// 15s): RunSession's own heartbeat ticker (limits.DefaultHeartbeatInterval,
// 15s) and sessionLivenessTouchInterval (5s, connector.go) both report
// well inside this window during ordinary operation and while blocked
// waiting on a reconnect backoff or a Recv with nothing to read.
const sessionLivenessMaxInterval = 20 * time.Second

// SessionConfig is everything RunSession needs to drive one agent's
// control-channel session (architecture doc 6.3) end to end: connect,
// Hello/HelloAck, the inbound message loop and periodic heartbeats, and
// reconnect-with-backoff on stream loss, until ctx is canceled.
type SessionConfig struct {
	// Connector produces each reconnect cycle's open, Hello/HelloAck-
	// completed stream (production: *RealConnector).
	Connector Connector
	// Hello builds this attempt's Hello fields. Called fresh on every
	// (re)connect, since epochs/digests/host facts can change between
	// attempts; never cached across calls.
	Hello func() controlclient.HelloFields
	// ControlLoop dispatches inbound messages and builds heartbeats.
	// Its own StateMachine (ControlLoop.SM) must already be in
	// StateConnecting when RunSession is first called (step-06a-
	// resume.md D3: "once an identity exists" -- the caller is
	// responsible for having already fired EventJoinTokenValid then
	// EventSVIDIssued to reach CONNECTING from UNENROLLED, since a
	// production build with a persisted identity chain has no
	// enrollment step of its own left to run).
	ControlLoop *ControlLoop
	// Clock is used for CheckCertExpiry's "now". Required.
	Clock func() time.Time
	// Auditor records session-level events (connect failures, forced
	// DEGRADED transitions). Required.
	Auditor Auditor
	// Liveness is Touch-ed throughout RunSession's life (R6A-1).
	// Required.
	Liveness *LivenessRegistry
	// HeartbeatInterval overrides limits.DefaultHeartbeatInterval (15s)
	// if positive; tests use a short interval so they do not block for
	// 15 real seconds.
	HeartbeatInterval time.Duration
}

func (c SessionConfig) validate() error {
	switch {
	case c.Connector == nil:
		return fmt.Errorf("agent: RunSession: Connector must not be nil")
	case c.Hello == nil:
		return fmt.Errorf("agent: RunSession: Hello must not be nil")
	case c.ControlLoop == nil:
		return fmt.Errorf("agent: RunSession: ControlLoop must not be nil")
	case c.Clock == nil:
		return fmt.Errorf("agent: RunSession: Clock must not be nil")
	case c.Auditor == nil:
		return fmt.Errorf("agent: RunSession: Auditor must not be nil")
	case c.Liveness == nil:
		return fmt.Errorf("agent: RunSession: Liveness must not be nil")
	}
	return nil
}

func (c SessionConfig) heartbeatInterval() time.Duration {
	if c.HeartbeatInterval > 0 {
		return c.HeartbeatInterval
	}
	return limits.DefaultHeartbeatInterval
}

// RunSession implements step-06a-resume.md D3: once an identity exists,
// dial with Connector, run Hello/HelloAck, then drive ControlLoop
// (inbound dispatch), a heartbeat ticker and the state machine
// (CONNECTING -> SYNCING -> STEADY; stream loss -> CONNECTING with
// full-jitter backoff, applied inside Connector; DEGRADED after 5
// minutes without a stream; Terminate{REVOKED} stops reconnecting).
//
// RunSession returns nil on any clean stop: ctx canceled, or
// Terminate{REVOKED} received (cfg.ControlLoop's StateMachine is left in
// StateRevoked; architecture doc 8.4's REVOKED -> UNENROLLED transition
// is an explicit operator re-enrollment action this step does not
// drive). It registers itself with cfg.Liveness under
// sessionLivenessComponent as its first action (R6A-1).
//
// Deviation from a literal reading of architecture doc 6.3 step 4
// ("Reconcile"): step 6a does not process PolicyBundle/TrustUpdate (D2),
// so there is nothing for the agent side of reconcile to wait on; this
// function fires EventInSync immediately after EventHelloAck on every
// successful connect, entering STEADY as soon as the handshake
// completes rather than modeling a separate wait for a controller
// decision this step has no way to observe. See docs/reports/step-06a.md
// for this deviation recorded against the architecture doc.
func RunSession(ctx context.Context, cfg SessionConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	cfg.Liveness.Register(sessionLivenessComponent, sessionLivenessMaxInterval)
	// e3StalledComponent is always "" outside a testca build
	// (e3hooks.go): this check compiles away to "if false" there, so
	// Touch always runs in production. step-06a-e3-prompt.md S6.
	touch := func() {
		if e3StalledComponent() == sessionLivenessComponent {
			return
		}
		cfg.Liveness.Touch(sessionLivenessComponent)
	}

	for {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // ctx cancellation is RunSession's clean-stop signal, not a failure to report upward.
		}

		stream, closeStream, err := connectWithDegradedWatch(ctx, cfg, touch)
		if err != nil {
			// Connector only returns an error when ctx is done; same
			// clean-stop convention as the ctx.Err() check above.
			return nil //nolint:nilerr
		}

		if cfg.ControlLoop.SM.Current() == StateDegraded {
			if ferr := cfg.ControlLoop.SM.Fire(EventConditionsClear); ferr != nil {
				cfg.Auditor.Record(AuditEvent{Step: "session_state_transition_failed", Detail: "DEGRADED -> CONNECTING", Err: ferr})
			}
		}
		if ferr := cfg.ControlLoop.SM.Fire(EventHelloAck); ferr != nil {
			cfg.Auditor.Record(AuditEvent{Step: "session_state_transition_failed", Detail: "CONNECTING -> SYNCING", Err: ferr})
		}
		if ferr := cfg.ControlLoop.SM.Fire(EventInSync); ferr != nil {
			cfg.Auditor.Record(AuditEvent{Step: "session_state_transition_failed", Detail: "SYNCING -> STEADY", Err: ferr})
		}
		cfg.Auditor.Record(AuditEvent{Step: "session_connected", Detail: "Hello/HelloAck complete"})

		reconnect, runErr := runStreamLoop(ctx, cfg, stream, touch)
		_ = closeStream()
		if runErr != nil {
			cfg.Auditor.Record(AuditEvent{Step: "session_stream_closed", Err: runErr})
		}

		if cfg.ControlLoop.SM.Current() != StateRevoked {
			if ferr := cfg.ControlLoop.SM.Fire(EventStreamLost); ferr != nil {
				cfg.Auditor.Record(AuditEvent{Step: "session_state_transition_failed", Detail: "-> CONNECTING (stream lost)", Err: ferr})
			}
		}
		if !reconnect {
			return nil
		}
	}
}

// connectWithDegradedWatch calls cfg.Connector.Connect, which blocks
// (with its own internal backoff) until it succeeds or ctx is done.
// While waiting, if limits.ControlConnectDegradedTimeout elapses since
// this call started, it fires EventConnectTimeout exactly once
// (architecture doc 8.4 DEGRADED: "No controller for > 5 min") without
// canceling the in-flight connect attempt -- Connect keeps running in
// its own goroutine and this function keeps waiting for it. Only this
// function's own goroutine (the caller's) ever calls cfg.ControlLoop.SM.
// Fire or cfg.Liveness.Touch, so there is no data race with the
// Connect goroutine, which only calls touch (a plain function value).
func connectWithDegradedWatch(ctx context.Context, cfg SessionConfig, touch func()) (ControlStream, func() error, error) {
	type result struct {
		stream ControlStream
		closer func() error
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		stream, closer, err := cfg.Connector.Connect(ctx, cfg.Hello, touch)
		resultCh <- result{stream, closer, err}
	}()

	degradedTimeout := limits.ControlConnectDegradedTimeout
	if o := e3DegradedTimeoutOverride(); o > 0 {
		// Always 0 outside a testca build (e3hooks.go); step-06a-e3-
		// prompt.md S5 explicitly permits shortening this threshold
		// only through a testca-tagged constant override.
		degradedTimeout = o
	}
	degradedTimer := time.NewTimer(degradedTimeout)
	defer degradedTimer.Stop()
	touchTicker := time.NewTicker(sessionLivenessTouchInterval)
	defer touchTicker.Stop()

	for {
		select {
		case r := <-resultCh:
			return r.stream, r.closer, r.err
		case <-degradedTimer.C:
			if ferr := cfg.ControlLoop.SM.Fire(EventConnectTimeout); ferr == nil {
				cfg.Auditor.Record(AuditEvent{Step: "session_degraded", Detail: "no controller stream for over 5 minutes"})
			}
			// EventConnectTimeout is only valid once per CONNECTING
			// episode (the transitions table has no self-loop for it);
			// a second firing after it already succeeded is a no-op
			// ErrInvalidTransition, deliberately not audited again --
			// this select arm is otherwise unreachable a second time
			// since degradedTimer is a one-shot timer.
		case <-touchTicker.C:
			touch()
		}
	}
}

// runStreamLoop drives one open stream: dispatches inbound
// ControllerMessages through cfg.ControlLoop, sends a Heartbeat every
// cfg.heartbeatInterval(), and checks certificate expiry on every
// heartbeat tick (D2). It returns once the stream ends, reporting
// whether the caller should reconnect (Outcome.Reconnect, or true for an
// ordinary stream-level failure) and the error that ended it, if any.
func runStreamLoop(ctx context.Context, cfg SessionConfig, stream ControlStream, touch func()) (reconnect bool, err error) {
	seqTracker := &SeqTracker{seen: true, last: 1} // Hello's HelloAck (seq 1) was already consumed by Connector/SendHello.
	out := NewOutboundSeqAfterHello()

	msgCh := make(chan *controlv1.ControllerMessage)
	errCh := make(chan error, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				errCh <- rerr
				return
			}
			select {
			case msgCh <- msg:
			case <-stop:
				return
			}
		}
	}()

	heartbeatTicker := time.NewTicker(cfg.heartbeatInterval())
	defer heartbeatTicker.Stop()
	touchTicker := time.NewTicker(sessionLivenessTouchInterval)
	defer touchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return false, ctx.Err()

		case rerr := <-errCh:
			return true, rerr

		case msg := <-msgCh:
			touch()
			outcome, herr := cfg.ControlLoop.HandleControllerMessage(ctx, seqTracker, out, msg)
			if outcome.Reply != nil {
				if serr := stream.Send(outcome.Reply); serr != nil {
					return true, serr
				}
			}
			if outcome.Close {
				_ = stream.CloseSend()
				return outcome.Reconnect, herr
			}

		case <-heartbeatTicker.C:
			touch()
			hb, herr := cfg.ControlLoop.BuildHeartbeat(ctx, out)
			if herr != nil {
				cfg.Auditor.Record(AuditEvent{Step: "heartbeat_build_failed", Err: herr})
				continue
			}
			if serr := stream.Send(hb); serr != nil {
				return true, serr
			}
			cfg.ControlLoop.CheckCertExpiry(cfg.Clock())

		case <-touchTicker.C:
			touch()
		}
	}
}
