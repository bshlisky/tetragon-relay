package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
)

// ErrProtocolError is returned by (*ControlLoop).HandleControllerMessage
// when msg violates the closed message set or the inbound seq rule
// (ADR 0032); the caller must close the stream (architecture doc 6.5).
var ErrProtocolError = errors.New("agent: protocol error")

// SeqTracker enforces ADR 0032's pinned seq rule on one direction of one
// stream: the first message has seq = 1; every later message is exactly
// the previous plus 1.
type SeqTracker struct {
	last uint64
	seen bool
}

// Check validates seq against the tracked sequence and advances it on
// success. It never resets itself on failure: a stream that failed this
// check must be closed and reconnected (a fresh SeqTracker for the new
// stream), never repaired in place.
func (t *SeqTracker) Check(seq uint64) error {
	if !t.seen {
		if seq != 1 {
			return fmt.Errorf("%w: first message seq = %d, want 1", ErrProtocolError, seq)
		}
		t.seen = true
		t.last = seq
		return nil
	}
	want := t.last + 1
	if seq != want {
		return fmt.Errorf("%w: message seq = %d, want %d", ErrProtocolError, seq, want)
	}
	t.last = seq
	return nil
}

// OutboundSeq generates the agent's own outgoing seq values, starting at
// 1 (ADR 0032), for messages the control loop sends outside of Hello
// (which internal/controlclient.SendHello already sends at seq 1 itself).
type OutboundSeq struct {
	next uint64
}

// NewOutboundSeqAfterHello returns an OutboundSeq whose first Next() call
// returns 2: Hello was already sent at seq 1 by SendHello before the
// control loop starts.
func NewOutboundSeqAfterHello() *OutboundSeq {
	return &OutboundSeq{next: 2}
}

// Next returns the next seq value and advances.
func (s *OutboundSeq) Next() uint64 {
	v := s.next
	s.next++
	return v
}

// StateSnapshot is everything Heartbeat and StateReport report about the
// agent's current view of the world (architecture doc 6.2/6.4). Telemetry
// fields are not part of this snapshot: they stay zero until step 7
// (docs/prompts/step-06a.md D2).
type StateSnapshot struct {
	// Epochs is scope -> current epoch (control.proto Hello/Heartbeat/
	// StateReport's epochs field).
	Epochs map[string]uint64
	// LoadedDigest is architecture doc 6.4's digest, computed from
	// Tetragon's own ListTracingPolicies response.
	LoadedDigest []byte
	// LKGBundleDigest is the current LKG bundle's digest, if any.
	LKGBundleDigest []byte
	// Health is Tetragon's health plus agent process liveness.
	Health *controlv1.TetragonHealth
	// Policies is every currently loaded policy, for StateReport only
	// (Heartbeat does not carry this field in the proto).
	Policies []*controlv1.LoadedPolicy
}

// SnapshotProvider builds a StateSnapshot on demand (for a Heartbeat tick
// or a StateRequest), from the agent's actual Tetragon connection and
// store -- never cached, so a request always reflects current kernel
// reality (architecture doc 6.4).
type SnapshotProvider interface {
	Snapshot(ctx context.Context) (StateSnapshot, error)
}

// IdentityRotator is the subset of identity.CertManager's rotation
// surface the control loop needs: RotateIdentity triggers Rotate;
// ExpiringSoon drives the DEGRADED-on-expiring-certificate rule (D2).
// Defined as an interface so the control loop can be tested without a
// real TPM-backed CertManager.
type IdentityRotator interface {
	Rotate(ctx context.Context) error
	ExpiringSoon(now time.Time) bool
}

// ControlLoop holds every dependency (*ControlLoop).HandleControllerMessage
// and BuildHeartbeat need. None of the fields may be nil (this package's
// fail-closed convention for required collaborators); NewControlLoop
// enforces that.
type ControlLoop struct {
	SM       *StateMachine
	Auditor  Auditor
	Clock    func() time.Time
	Snapshot SnapshotProvider
	Rotator  IdentityRotator
	// Jobs receives PolicyBundle envelopes for the apply worker
	// (docs/prompts/step-06b.md B2). Optional: when nil (a control loop
	// built without bundle processing, e.g. in tests), a PolicyBundle is
	// answered with APPLY_FAILED and nothing else happens.
	Jobs JobSink

	mu            sync.Mutex
	revokedReason string
}

// RevokedReason returns the reason recorded with the most recent
// Terminate{REVOKED} ("REVOKED: <detail>"), or "" if none was received.
// RunSession persists it with the REVOKED marker (ADR 0035).
func (cl *ControlLoop) RevokedReason() string {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.revokedReason
}

// JobSink is where the control loop hands work it must not do on the
// stream loop's goroutine (*ApplyWorker implements it). SubmitBundle must
// return without blocking.
type JobSink interface {
	SubmitBundle(envelope []byte)
	SubmitTrustUpdate(signedRoots [][]byte)
}

// NewControlLoop constructs a ControlLoop, rejecting any nil dependency.
func NewControlLoop(sm *StateMachine, auditor Auditor, clock func() time.Time, snapshot SnapshotProvider, rotator IdentityRotator) (*ControlLoop, error) {
	switch {
	case sm == nil:
		return nil, fmt.Errorf("agent: NewControlLoop: state machine must not be nil")
	case auditor == nil:
		return nil, fmt.Errorf("agent: NewControlLoop: auditor must not be nil")
	case clock == nil:
		return nil, fmt.Errorf("agent: NewControlLoop: clock must not be nil")
	case snapshot == nil:
		return nil, fmt.Errorf("agent: NewControlLoop: snapshot provider must not be nil")
	case rotator == nil:
		return nil, fmt.Errorf("agent: NewControlLoop: rotator must not be nil")
	}
	return &ControlLoop{SM: sm, Auditor: auditor, Clock: clock, Snapshot: snapshot, Rotator: rotator}, nil
}

// Outcome is what HandleControllerMessage's caller (the network loop,
// RunSession) must do next.
type Outcome struct {
	// Reply is the AgentMessage to send in response, or nil if nothing
	// is sent for this inbound message.
	Reply *controlv1.AgentMessage
	// Close is true when the stream must be closed (a protocol error,
	// or any Terminate reason).
	Close bool
	// Reconnect is true when the caller should reconnect with the
	// existing full-jitter backoff (architecture doc 6.3 step 6) after
	// closing; false means stop reconnecting entirely (Terminate{REVOKED}).
	Reconnect bool
}

// HandleControllerMessage implements docs/prompts/step-06a.md D2's
// inbound message handling for every message in control.proto's closed
// ControllerMessage oneof, after ADR 0032's seq check. It never executes
// anything outside that closed set (architecture doc P7): the type switch
// below has no default case that does anything but refuse.
func (cl *ControlLoop) HandleControllerMessage(ctx context.Context, seqTracker *SeqTracker, out *OutboundSeq, msg *controlv1.ControllerMessage) (Outcome, error) {
	if err := seqTracker.Check(msg.GetSeq()); err != nil {
		return Outcome{Close: true, Reconnect: true}, err
	}

	switch body := msg.GetBody().(type) {
	case *controlv1.ControllerMessage_HelloAck:
		// SendHello already consumed the stream's one legitimate
		// HelloAck before the control loop starts (architecture doc
		// 6.3 step 3); a second one is a protocol violation.
		return Outcome{Close: true, Reconnect: true}, fmt.Errorf("%w: unexpected second HelloAck", ErrProtocolError)

	case *controlv1.ControllerMessage_StateRequest:
		report := cl.buildStateReport(ctx, body.StateRequest.GetNonce())
		return Outcome{Reply: cl.wrap(out, &controlv1.AgentMessage{Body: &controlv1.AgentMessage_StateReport{StateReport: report}})}, nil

	case *controlv1.ControllerMessage_RotateIdentity:
		reason := body.RotateIdentity.GetReason()
		if cl.SM.Current() == StateTampered {
			// ADR 0038: tampered mode connects with the identity as it is.
			cl.Auditor.Record(AuditEvent{Step: "rotate_identity_refused", Detail: "tampered mode: identity is not rotated; " + reason})
			return Outcome{}, nil
		}
		cl.Auditor.Record(AuditEvent{Step: "rotate_identity_requested", Detail: reason})
		if err := cl.Rotator.Rotate(ctx); err != nil {
			cl.Auditor.Record(AuditEvent{Step: "rotate_identity_failed", Detail: reason, Err: err})
		}
		return Outcome{}, nil

	case *controlv1.ControllerMessage_Terminate:
		reason := body.Terminate.GetReason()
		cl.Auditor.Record(AuditEvent{Step: "terminate_received", Detail: fmt.Sprintf("reason=%s detail=%s", reason, body.Terminate.GetDetail())})
		if reason == controlv1.Terminate_REVOKED {
			cl.mu.Lock()
			cl.revokedReason = "REVOKED: " + body.Terminate.GetDetail()
			cl.mu.Unlock()
			_ = cl.SM.Fire(EventTerminateRevoked)
			return Outcome{Close: true, Reconnect: false}, nil
		}
		// Every other reason (DUPLICATE_SESSION, PROTOCOL_ERROR,
		// SHUTDOWN, REASON_UNSPECIFIED): close and reconnect with the
		// existing backoff, same as any other stream loss.
		return Outcome{Close: true, Reconnect: true}, nil

	case *controlv1.ControllerMessage_Bundle:
		// docs/prompts/step-06b.md B2: never block the stream loop.
		// The raw envelope bytes go to the apply worker's pending slot
		// unmodified (never re-encoded); the worker sends the
		// ApplyResult through the Outbox when it is done.
		if cl.Jobs == nil {
			result := &controlv1.ApplyResult{
				BundleDigest: bundleDigest(body.Bundle.GetEnvelope()),
				Status:       controlv1.ApplyResult_APPLY_FAILED,
				Detail:       "relayd has no apply worker configured",
			}
			return Outcome{Reply: cl.wrap(out, applyResultMessage(result))}, nil
		}
		cl.Jobs.SubmitBundle(body.Bundle.GetEnvelope())
		return Outcome{}, nil

	case *controlv1.ControllerMessage_TrustUpdate:
		// docs/prompts/step-06b.md C1/C2: processed on the apply
		// worker, between bundle applies; no reply (failures are
		// audited and alerted by the worker).
		if cl.Jobs != nil {
			cl.Jobs.SubmitTrustUpdate(body.TrustUpdate.GetSignedRoots())
			return Outcome{}, nil
		}
		alert := &controlv1.Alert{
			Kind:     controlv1.Alert_TRUST_UPDATE_REJECTED,
			Detail:   "relayd has no apply worker configured; TrustUpdate not processed",
			UnixTime: cl.Clock().Unix(),
		}
		return Outcome{Reply: cl.wrap(out, &controlv1.AgentMessage{Body: &controlv1.AgentMessage_Alert{Alert: alert}})}, nil

	default:
		// control.proto's oneof is closed by design (control.proto:46:
		// "No exec, file write, shell, config-set, or debug messages
		// exist by design"); an unknown wire type here means either a
		// future proto field this build predates, or a non-conforming
		// peer. Either way, closing the stream is the only safe action.
		return Outcome{Close: true, Reconnect: true}, fmt.Errorf("%w: unknown message type %T", ErrProtocolError, body)
	}
}

// wrap assigns the next outbound seq (ADR 0032) to msg (already built
// with its Body set by the caller) and returns it. msg.Seq is always
// overwritten, never trusted from the caller, so there is exactly one
// place outbound seq values are ever chosen.
func (cl *ControlLoop) wrap(out *OutboundSeq, msg *controlv1.AgentMessage) *controlv1.AgentMessage {
	msg.Seq = out.Next()
	return msg
}

// buildStateReport implements the StateRequest/StateReport exchange: a
// snapshot-failure (e.g. Tetragon unreachable) still returns a
// StateReport (echoing the request's nonce, architecture doc 6.2), just
// with every other field left at its zero value, rather than failing the
// whole control loop over a transient local read.
func (cl *ControlLoop) buildStateReport(ctx context.Context, nonce []byte) *controlv1.StateReport {
	snap, err := cl.Snapshot.Snapshot(ctx)
	if err != nil {
		cl.Auditor.Record(AuditEvent{Step: "state_report_snapshot_failed", Err: err})
		return &controlv1.StateReport{Nonce: nonce}
	}
	return &controlv1.StateReport{
		Nonce:           nonce,
		Epochs:          snap.Epochs,
		LoadedDigest:    snap.LoadedDigest,
		LkgBundleDigest: snap.LKGBundleDigest,
		Policies:        snap.Policies,
		Health:          snap.Health,
	}
}

// BuildHeartbeat implements the periodic (15 s, architecture doc 6.3 step
// 5) Heartbeat the caller's ticker loop sends via out. Telemetry fields
// stay zero (step 7 scope).
func (cl *ControlLoop) BuildHeartbeat(ctx context.Context, out *OutboundSeq) (*controlv1.AgentMessage, error) {
	snap, err := cl.Snapshot.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent: build heartbeat snapshot: %w", err)
	}
	hb := &controlv1.Heartbeat{
		Epochs:       snap.Epochs,
		LoadedDigest: snap.LoadedDigest,
		Health:       snap.Health,
	}
	return cl.wrap(out, &controlv1.AgentMessage{Body: &controlv1.AgentMessage_Heartbeat{Heartbeat: hb}}), nil
}

// CheckCertExpiry implements D2's "expiring certificate (under 15 minutes
// left) puts the agent in DEGRADED" rule (EventDegradedCondition; see
// state.go's doc comment on that event for why it extends architecture
// doc 8.4's base diagram). A no-op if the certificate is not expiring
// soon, or if the current state has no EventDegradedCondition edge
// (UNENROLLED/ENROLLING/CONNECTING/DEGRADED/REVOKED: either there is no
// certificate in use yet, DEGRADED is already the state, or REVOKED
// supersedes it).
func (cl *ControlLoop) CheckCertExpiry(now time.Time) {
	if !cl.Rotator.ExpiringSoon(now) {
		return
	}
	if _, ok := transitions[cl.SM.Current()][EventDegradedCondition]; !ok {
		return
	}
	if err := cl.SM.Fire(EventDegradedCondition); err != nil {
		cl.Auditor.Record(AuditEvent{Step: "cert_expiry_check", Detail: "failed to enter DEGRADED", Err: err})
	}
}
