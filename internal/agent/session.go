package agent

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"

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
	// Revocations persists the REVOKED marker when Terminate{REVOKED}
	// arrives (ADR 0035; production: *store.Store). Required: a nil
	// recorder would silently lose the revocation across a restart.
	Revocations RevocationRecorder
	// HeartbeatInterval overrides limits.DefaultHeartbeatInterval (15s)
	// if positive; tests use a short interval so they do not block for
	// 15 real seconds.
	HeartbeatInterval time.Duration
	// Outbox holds ApplyResults and Alerts produced off the stream loop
	// (docs/prompts/step-06b.md B2/E1); the stream loop drains it after
	// every HelloAck and whenever it is notified. Optional: nil means
	// this session has no apply worker or alerter.
	Outbox *Outbox
	// Link records connection state for the health window's
	// reachability check (B4) and serializes connect/loss transitions
	// with the apply worker's (see Link). Optional: nil means RunSession
	// fires those transitions without coordination (no apply worker).
	Link *Link

	// touchInterval overrides sessionLivenessTouchInterval for the park
	// loop if positive, and parkTick, if non-nil, runs on every park-loop
	// tick before the liveness touch. Both are unexported: only this
	// package's tests set them (a short interval, and a hook that blocks
	// to prove a hung park loop goes stale). Zero values are production.
	touchInterval time.Duration
	parkTick      func()
}

func (c SessionConfig) parkTouchInterval() time.Duration {
	if c.touchInterval > 0 {
		return c.touchInterval
	}
	return sessionLivenessTouchInterval
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
	case c.Revocations == nil:
		return fmt.Errorf("agent: RunSession: Revocations must not be nil")
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
// RunSession returns nil when ctx is canceled. On Terminate{REVOKED}
// (or if cfg.ControlLoop's StateMachine is already REVOKED when it is
// called) it parks (see park) instead of returning: no further
// connection, liveness still reported. Architecture doc 8.4's
// REVOKED -> UNENROLLED transition is an explicit operator
// re-enrollment action this step does not drive. It registers itself with cfg.Liveness under
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
		if cfg.ControlLoop.SM.Current() == StateRevoked {
			return park(ctx, cfg, touch)
		}

		stream, closeStream, err := connectWithDegradedWatch(ctx, cfg, touch)
		if err != nil {
			// Connector only returns an error when ctx is done; same
			// clean-stop convention as the ctx.Err() check above.
			return nil //nolint:nilerr
		}

		linkUp(cfg, func() { fireConnected(cfg) })
		cfg.Auditor.Record(AuditEvent{Step: "session_connected", Detail: "Hello/HelloAck complete"})

		reconnect, runErr := runStreamLoop(ctx, cfg, stream, touch)
		_ = closeStream()
		if runErr != nil {
			cfg.Auditor.Record(AuditEvent{Step: "session_stream_closed", Err: runErr})
		}

		linkDown(cfg, func() { fireStreamLost(cfg) })
		if cfg.ControlLoop.SM.Current() == StateRevoked {
			persistRevocation(cfg)
			continue // the next iteration's check parks
		}
		if !reconnect {
			return nil
		}
	}
}

// applyOwnsState reports whether the apply worker currently owns the
// state machine (APPLYING or ROLLBACK). Connection transitions are left
// to the worker in those states; it settles them when the apply ends
// (see Link).
func applyOwnsState(s State) bool { return s == StateApplying || s == StateRollback }

func linkUp(cfg SessionConfig, fire func()) {
	if cfg.Link != nil {
		cfg.Link.Up(fire)
		return
	}
	fire()
}

func linkDown(cfg SessionConfig, fire func()) {
	if cfg.Link != nil {
		cfg.Link.Down(fire)
		return
	}
	fire()
}

// fireConnected fires the connect-time transitions: DEGRADED ->
// CONNECTING if needed, then HelloAck and InSync (see RunSession's doc
// comment for why InSync follows at once). If an apply is in progress
// (the stream dropped and came back while APPLYING), nothing is fired:
// the worker returns the agent to STEADY when it settles.
func fireConnected(cfg SessionConfig) {
	sm := cfg.ControlLoop.SM
	if applyOwnsState(sm.Current()) {
		cfg.Auditor.Record(AuditEvent{Step: "session_connected_during_apply", Detail: "state left to the apply worker"})
		return
	}
	if sm.Current() == StateDegraded {
		if ferr := sm.Fire(EventConditionsClear); ferr != nil {
			cfg.Auditor.Record(AuditEvent{Step: "session_state_transition_failed", Detail: "DEGRADED -> CONNECTING", Err: ferr})
		}
	}
	if ferr := sm.Fire(EventHelloAck); ferr != nil {
		cfg.Auditor.Record(AuditEvent{Step: "session_state_transition_failed", Detail: "CONNECTING -> SYNCING", Err: ferr})
	}
	if ferr := sm.Fire(EventInSync); ferr != nil {
		cfg.Auditor.Record(AuditEvent{Step: "session_state_transition_failed", Detail: "SYNCING -> STEADY", Err: ferr})
	}
}

// fireStreamLost fires StreamLost unless the agent is REVOKED or an
// apply owns the state machine.
func fireStreamLost(cfg SessionConfig) {
	sm := cfg.ControlLoop.SM
	if cur := sm.Current(); cur == StateRevoked || applyOwnsState(cur) {
		return
	}
	if ferr := sm.Fire(EventStreamLost); ferr != nil {
		cfg.Auditor.Record(AuditEvent{Step: "session_state_transition_failed", Detail: "-> CONNECTING (stream lost)", Err: ferr})
	}
}

// persistRevocation records the REVOKED marker (ADR 0035) before
// RunSession parks. A failure is audited, not fatal: this process parks
// and never dials either way, and the next start would reconnect only
// if the marker is missing, which the audit record makes visible.
func persistRevocation(cfg SessionConfig) {
	reason := truncateUTF8(cfg.ControlLoop.RevokedReason(), limits.MaxRevokedReasonBytes)
	if err := cfg.Revocations.MarkRevoked(cfg.Clock(), reason); err != nil {
		cfg.Auditor.Record(AuditEvent{Step: "revocation_persist_failed", Detail: "REVOKED marker not persisted; a restart would reconnect", Err: err})
		return
	}
	cfg.Auditor.Record(AuditEvent{Step: "revocation_persisted", Detail: reason})
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// park implements docs/reviews/step-06a-e3-decisions.md D1. Once
// REVOKED, RunSession neither returns nor touches the network: it idles
// until ctx is done (shutdown; operator re-enrollment, ADR 0023, also
// ends the process's session), touching liveness on every tick. It stays
// registered, so the watchdog keeps being fed while it idles and is
// withheld if this loop itself ever hangs. E3 run 45858158620 (S4)
// showed the old behavior: RunSession returned, session_runner went
// stale, systemd's watchdog killed relayd, and the new process
// reconnected.
func park(ctx context.Context, cfg SessionConfig, touch func()) error {
	cfg.Auditor.Record(AuditEvent{Step: "session_parked", Detail: "REVOKED: no controller connection until shutdown or operator re-enrollment"})
	ticker := time.NewTicker(cfg.parkTouchInterval())
	defer ticker.Stop()
	touch()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if cfg.parkTick != nil {
				cfg.parkTick()
			}
			touch()
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

	var outboxNotify <-chan struct{}
	if cfg.Outbox != nil {
		outboxNotify = cfg.Outbox.Notify()
		// Anything queued while disconnected goes out right after
		// HelloAck (E1).
		if serr := drainOutbox(cfg, stream, out); serr != nil {
			return true, serr
		}
	}

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
			if cfg.Link != nil {
				cfg.Link.Acked()
			}
			cfg.ControlLoop.CheckCertExpiry(cfg.Clock())

		case <-outboxNotify:
			touch()
			if serr := drainOutbox(cfg, stream, out); serr != nil {
				return true, serr
			}

		case <-touchTicker.C:
			touch()
		}
	}
}

// drainOutbox sends every queued Outbox message on stream, assigning each
// the next outbound seq. A message is removed only after the transport
// accepted it, so one whose Send failed is retried on the next stream.
func drainOutbox(cfg SessionConfig, stream ControlStream, out *OutboundSeq) error {
	for {
		msg := cfg.Outbox.Peek()
		if msg == nil {
			return nil
		}
		msg.Seq = out.Next()
		if err := stream.Send(msg); err != nil {
			return err
		}
		cfg.Outbox.Pop(msg)
		if cfg.Link != nil {
			cfg.Link.Acked()
		}
	}
}
