package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
)

func TestSeqTracker(t *testing.T) {
	var tr SeqTracker
	if err := tr.Check(1); err != nil {
		t.Fatalf("first Check(1): %v", err)
	}
	if err := tr.Check(2); err != nil {
		t.Fatalf("second Check(2): %v", err)
	}
	if err := tr.Check(4); !errors.Is(err, ErrProtocolError) {
		t.Fatalf("Check(4) after 2: error = %v, want ErrProtocolError", err)
	}
}

func TestSeqTracker_FirstMustBeOne(t *testing.T) {
	var tr SeqTracker
	if err := tr.Check(0); !errors.Is(err, ErrProtocolError) {
		t.Fatalf("Check(0) first: error = %v, want ErrProtocolError", err)
	}
	var tr2 SeqTracker
	if err := tr2.Check(2); !errors.Is(err, ErrProtocolError) {
		t.Fatalf("Check(2) first: error = %v, want ErrProtocolError", err)
	}
}

func TestOutboundSeq_StartsAtTwo(t *testing.T) {
	out := NewOutboundSeqAfterHello()
	if got := out.Next(); got != 2 {
		t.Fatalf("first Next() = %d, want 2 (seq 1 is Hello)", got)
	}
	if got := out.Next(); got != 3 {
		t.Fatalf("second Next() = %d, want 3", got)
	}
}

// fakeSnapshotProvider is a controllable SnapshotProvider for tests.
type fakeSnapshotProvider struct {
	snap StateSnapshot
	err  error
}

func (f *fakeSnapshotProvider) Snapshot(context.Context) (StateSnapshot, error) {
	return f.snap, f.err
}

// fakeRotator is a controllable IdentityRotator for tests.
type fakeRotator struct {
	expiringSoon bool
	rotateErr    error
	rotateCalls  int
}

func (f *fakeRotator) Rotate(context.Context) error {
	f.rotateCalls++
	return f.rotateErr
}

func (f *fakeRotator) ExpiringSoon(time.Time) bool { return f.expiringSoon }

func testControlLoop(t *testing.T) (*ControlLoop, *FakeAuditor, *fakeSnapshotProvider, *fakeRotator) {
	t.Helper()
	sm, err := NewStateMachine(&FakeAuditor{})
	if err != nil {
		t.Fatalf("NewStateMachine: %v", err)
	}
	auditor := &FakeAuditor{}
	snap := &fakeSnapshotProvider{}
	rot := &fakeRotator{}
	cl, err := NewControlLoop(sm, auditor, func() time.Time { return time.Unix(1000, 0) }, snap, rot)
	if err != nil {
		t.Fatalf("NewControlLoop: %v", err)
	}
	return cl, auditor, snap, rot
}

func TestNewControlLoop_RejectsNilDeps(t *testing.T) {
	sm, _ := NewStateMachine(&FakeAuditor{})
	auditor := &FakeAuditor{}
	clock := time.Now
	snap := &fakeSnapshotProvider{}
	rot := &fakeRotator{}

	cases := []struct {
		name string
		fn   func() error
	}{
		{"nil state machine", func() error { _, err := NewControlLoop(nil, auditor, clock, snap, rot); return err }},
		{"nil auditor", func() error { _, err := NewControlLoop(sm, nil, clock, snap, rot); return err }},
		{"nil clock", func() error { _, err := NewControlLoop(sm, auditor, nil, snap, rot); return err }},
		{"nil snapshot", func() error { _, err := NewControlLoop(sm, auditor, clock, nil, rot); return err }},
		{"nil rotator", func() error { _, err := NewControlLoop(sm, auditor, clock, snap, nil); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

func TestHandleControllerMessage_SeqViolationClosesAndReconnects(t *testing.T) {
	cl, _, _, _ := testControlLoop(t)
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	msg := &controlv1.ControllerMessage{Seq: 5, Body: &controlv1.ControllerMessage_StateRequest{StateRequest: &controlv1.StateRequest{}}}
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if !errors.Is(err, ErrProtocolError) {
		t.Fatalf("error = %v, want ErrProtocolError", err)
	}
	if !outcome.Close || !outcome.Reconnect {
		t.Fatalf("outcome = %+v, want Close=true Reconnect=true", outcome)
	}
}

func TestHandleControllerMessage_SecondHelloAckIsProtocolError(t *testing.T) {
	cl, _, _, _ := testControlLoop(t)
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_HelloAck{HelloAck: &controlv1.HelloAck{Nonce: make([]byte, 32)}}}
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if !errors.Is(err, ErrProtocolError) {
		t.Fatalf("error = %v, want ErrProtocolError", err)
	}
	if !outcome.Close || !outcome.Reconnect {
		t.Fatalf("outcome = %+v, want Close=true Reconnect=true", outcome)
	}
}

func TestHandleControllerMessage_StateRequest(t *testing.T) {
	cl, _, snap, _ := testControlLoop(t)
	snap.snap = StateSnapshot{
		Epochs:       map[string]uint64{"prod-db": 7},
		LoadedDigest: []byte{1, 2, 3},
		Health:       &controlv1.TetragonHealth{Serving: true},
	}
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	nonce := []byte("0123456789012345678901234567890")
	msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_StateRequest{StateRequest: &controlv1.StateRequest{Nonce: nonce}}}
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if err != nil {
		t.Fatalf("HandleControllerMessage: %v", err)
	}
	if outcome.Close || outcome.Reconnect {
		t.Fatalf("outcome = %+v, want no close/reconnect", outcome)
	}
	report := outcome.Reply.GetStateReport()
	if report == nil {
		t.Fatalf("Reply = %v, want a StateReport", outcome.Reply)
	}
	if string(report.GetNonce()) != string(nonce) {
		t.Fatalf("StateReport nonce not echoed")
	}
	if report.GetEpochs()["prod-db"] != 7 {
		t.Fatalf("StateReport epochs = %v", report.GetEpochs())
	}
	if outcome.Reply.GetSeq() != 2 {
		t.Fatalf("Reply seq = %d, want 2 (first after Hello's 1)", outcome.Reply.GetSeq())
	}
}

func TestHandleControllerMessage_StateRequest_SnapshotFailureStillReplies(t *testing.T) {
	cl, auditor, snap, _ := testControlLoop(t)
	snap.err = errors.New("tetragon unreachable")
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	nonce := []byte("0123456789012345678901234567890")
	msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_StateRequest{StateRequest: &controlv1.StateRequest{Nonce: nonce}}}
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if err != nil {
		t.Fatalf("HandleControllerMessage: %v", err)
	}
	report := outcome.Reply.GetStateReport()
	if report == nil || string(report.GetNonce()) != string(nonce) {
		t.Fatalf("expected a StateReport echoing the nonce even on snapshot failure, got %v", outcome.Reply)
	}
	foundAudit := false
	for _, e := range auditor.Events {
		if e.Step == "state_report_snapshot_failed" {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatalf("expected a state_report_snapshot_failed audit record")
	}
}

func TestHandleControllerMessage_RotateIdentity(t *testing.T) {
	cl, auditor, _, rot := testControlLoop(t)
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_RotateIdentity{RotateIdentity: &controlv1.RotateIdentity{Reason: "scheduled"}}}
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if err != nil {
		t.Fatalf("HandleControllerMessage: %v", err)
	}
	if outcome.Reply != nil || outcome.Close {
		t.Fatalf("outcome = %+v, want no reply, no close", outcome)
	}
	if rot.rotateCalls != 1 {
		t.Fatalf("Rotate called %d times, want 1", rot.rotateCalls)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "rotate_identity_requested" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a rotate_identity_requested audit record")
	}
}

func TestHandleControllerMessage_RotateIdentity_FailureAudited(t *testing.T) {
	cl, auditor, _, rot := testControlLoop(t)
	rot.rotateErr = errors.New("tpm busy")
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_RotateIdentity{RotateIdentity: &controlv1.RotateIdentity{}}}
	if _, err := cl.HandleControllerMessage(context.Background(), seq, out, msg); err != nil {
		t.Fatalf("HandleControllerMessage: %v", err)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "rotate_identity_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a rotate_identity_failed audit record")
	}
}

func TestHandleControllerMessage_TerminateRevoked(t *testing.T) {
	cl, _, _, _ := testControlLoop(t)
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_Terminate{Terminate: &controlv1.Terminate{Reason: controlv1.Terminate_REVOKED, Detail: "operator revoked"}}}
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if err != nil {
		t.Fatalf("HandleControllerMessage: %v", err)
	}
	if !outcome.Close || outcome.Reconnect {
		t.Fatalf("outcome = %+v, want Close=true Reconnect=false", outcome)
	}
	if cl.SM.Current() != StateRevoked {
		t.Fatalf("state = %v, want StateRevoked", cl.SM.Current())
	}
}

func TestHandleControllerMessage_TerminateOtherReasonsReconnect(t *testing.T) {
	reasons := []controlv1.Terminate_Reason{
		controlv1.Terminate_REASON_UNSPECIFIED,
		controlv1.Terminate_DUPLICATE_SESSION,
		controlv1.Terminate_PROTOCOL_ERROR,
		controlv1.Terminate_SHUTDOWN,
	}
	for _, reason := range reasons {
		t.Run(reason.String(), func(t *testing.T) {
			cl, _, _, _ := testControlLoop(t)
			seq := &SeqTracker{}
			out := NewOutboundSeqAfterHello()
			msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_Terminate{Terminate: &controlv1.Terminate{Reason: reason}}}
			outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
			if err != nil {
				t.Fatalf("HandleControllerMessage: %v", err)
			}
			if !outcome.Close || !outcome.Reconnect {
				t.Fatalf("outcome = %+v, want Close=true Reconnect=true", outcome)
			}
			if cl.SM.Current() == StateRevoked {
				t.Fatalf("state machine entered REVOKED for reason %s", reason)
			}
		})
	}
}

func TestHandleControllerMessage_PolicyBundle_NotYetProcessed(t *testing.T) {
	cl, _, _, _ := testControlLoop(t)
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_Bundle{Bundle: &controlv1.PolicyBundle{Envelope: []byte("not parsed")}}}
	before := cl.SM.Current()
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if err != nil {
		t.Fatalf("HandleControllerMessage: %v", err)
	}
	result := outcome.Reply.GetApplyResult()
	if result == nil {
		t.Fatalf("Reply = %v, want an ApplyResult", outcome.Reply)
	}
	if result.GetStatus() != controlv1.ApplyResult_APPLY_FAILED {
		t.Fatalf("ApplyResult.Status = %v, want APPLY_FAILED", result.GetStatus())
	}
	if cl.SM.Current() != before {
		t.Fatalf("state changed from %v to %v; PolicyBundle must not touch state in step 6a", before, cl.SM.Current())
	}
}

func TestHandleControllerMessage_TrustUpdate_NotYetProcessed(t *testing.T) {
	cl, _, _, _ := testControlLoop(t)
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	msg := &controlv1.ControllerMessage{Seq: 1, Body: &controlv1.ControllerMessage_TrustUpdate{TrustUpdate: &controlv1.TrustUpdate{SignedRoots: [][]byte{[]byte("x")}}}}
	before := cl.SM.Current()
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if err != nil {
		t.Fatalf("HandleControllerMessage: %v", err)
	}
	alert := outcome.Reply.GetAlert()
	if alert == nil {
		t.Fatalf("Reply = %v, want an Alert", outcome.Reply)
	}
	if cl.SM.Current() != before {
		t.Fatalf("state changed from %v to %v; TrustUpdate must not touch state in step 6a", before, cl.SM.Current())
	}
}

func TestHandleControllerMessage_UnknownBodyIsProtocolError(t *testing.T) {
	cl, _, _, _ := testControlLoop(t)
	seq := &SeqTracker{}
	out := NewOutboundSeqAfterHello()
	msg := &controlv1.ControllerMessage{Seq: 1} // no body set at all: GetBody() returns nil
	outcome, err := cl.HandleControllerMessage(context.Background(), seq, out, msg)
	if !errors.Is(err, ErrProtocolError) {
		t.Fatalf("error = %v, want ErrProtocolError", err)
	}
	if !outcome.Close || !outcome.Reconnect {
		t.Fatalf("outcome = %+v, want Close=true Reconnect=true", outcome)
	}
}

func TestBuildHeartbeat(t *testing.T) {
	cl, _, snap, _ := testControlLoop(t)
	snap.snap = StateSnapshot{Epochs: map[string]uint64{"prod-db": 3}, LoadedDigest: []byte{9}}
	out := NewOutboundSeqAfterHello()
	msg, err := cl.BuildHeartbeat(context.Background(), out)
	if err != nil {
		t.Fatalf("BuildHeartbeat: %v", err)
	}
	hb := msg.GetHeartbeat()
	if hb == nil {
		t.Fatalf("expected a Heartbeat body")
	}
	if hb.GetEpochs()["prod-db"] != 3 {
		t.Fatalf("Heartbeat epochs = %v", hb.GetEpochs())
	}
	if hb.GetTelemetryLastSeq() != 0 || hb.GetTelemetryBacklog() != 0 {
		t.Fatalf("telemetry fields must be zero with no pipeline")
	}
	if msg.GetSeq() != 2 {
		t.Fatalf("Heartbeat seq = %d, want 2", msg.GetSeq())
	}
}

func TestBuildHeartbeat_SnapshotFailure(t *testing.T) {
	cl, _, snap, _ := testControlLoop(t)
	snap.err = errors.New("tetragon unreachable")
	out := NewOutboundSeqAfterHello()
	if _, err := cl.BuildHeartbeat(context.Background(), out); err == nil {
		t.Fatalf("expected an error when the snapshot fails")
	}
}

func TestCheckCertExpiry_FiresWhenApplicable(t *testing.T) {
	cl, _, _, rot := testControlLoop(t)
	rot.expiringSoon = true
	// Fire into STEADY first (a state with an EventDegradedCondition edge).
	mustFire(t, cl.SM, EventJoinTokenValid)
	mustFire(t, cl.SM, EventSVIDIssued)
	mustFire(t, cl.SM, EventHelloAck)
	mustFire(t, cl.SM, EventInSync)
	if cl.SM.Current() != StateSteady {
		t.Fatalf("setup: state = %v, want StateSteady", cl.SM.Current())
	}
	cl.CheckCertExpiry(time.Unix(2000, 0))
	if cl.SM.Current() != StateDegraded {
		t.Fatalf("state = %v, want StateDegraded", cl.SM.Current())
	}
}

func TestCheckCertExpiry_NoOpWhenNotExpiring(t *testing.T) {
	cl, _, _, rot := testControlLoop(t)
	rot.expiringSoon = false
	mustFire(t, cl.SM, EventJoinTokenValid)
	mustFire(t, cl.SM, EventSVIDIssued)
	mustFire(t, cl.SM, EventHelloAck)
	mustFire(t, cl.SM, EventInSync)
	cl.CheckCertExpiry(time.Unix(2000, 0))
	if cl.SM.Current() != StateSteady {
		t.Fatalf("state = %v, want unchanged StateSteady", cl.SM.Current())
	}
}

func TestCheckCertExpiry_NoOpWhenNoEdgeFromCurrentState(t *testing.T) {
	cl, _, _, rot := testControlLoop(t)
	rot.expiringSoon = true
	// StateUnenrolled has no EventDegradedCondition edge.
	cl.CheckCertExpiry(time.Unix(2000, 0))
	if cl.SM.Current() != StateUnenrolled {
		t.Fatalf("state = %v, want unchanged StateUnenrolled", cl.SM.Current())
	}
}

func mustFire(t *testing.T, sm *StateMachine, event Event) {
	t.Helper()
	if err := sm.Fire(event); err != nil {
		t.Fatalf("Fire(%s) from %s: %v", event, sm.Current(), err)
	}
}

type fixedTelemetry struct{}

func (fixedTelemetry) HeartbeatStats() (uint64, uint32) { return 42, 7 }

func TestBuildHeartbeat_TelemetryFields(t *testing.T) {
	cl, _, snap, _ := testControlLoop(t)
	snap.snap = StateSnapshot{Epochs: map[string]uint64{"prod-db": 3}}
	cl.Telemetry = fixedTelemetry{}
	msg, err := cl.BuildHeartbeat(context.Background(), NewOutboundSeqAfterHello())
	if err != nil {
		t.Fatal(err)
	}
	if hb := msg.GetHeartbeat(); hb.GetTelemetryLastSeq() != 42 || hb.GetTelemetryBacklog() != 7 {
		t.Fatalf("heartbeat telemetry = %d, %d", hb.GetTelemetryLastSeq(), hb.GetTelemetryBacklog())
	}
}

type ratedTelemetry struct{ fixedTelemetry }

func (ratedTelemetry) EventsPerSecond() uint32 { return 1234 }

// step-07b-decisions.md D2: telemetry_events_per_s, when the pipeline
// reports it.
func TestBuildHeartbeat_TelemetryRate(t *testing.T) {
	cl, _, snap, _ := testControlLoop(t)
	snap.snap = StateSnapshot{Epochs: map[string]uint64{"prod-db": 3}}
	for _, tc := range []struct {
		tel  TelemetryStats
		want uint32
	}{{fixedTelemetry{}, 0}, {ratedTelemetry{}, 1234}} {
		cl.Telemetry = tc.tel
		msg, err := cl.BuildHeartbeat(context.Background(), NewOutboundSeqAfterHello())
		if err != nil {
			t.Fatal(err)
		}
		if got := msg.GetHeartbeat().GetTelemetryEventsPerS(); got != tc.want {
			t.Fatalf("telemetry_events_per_s = %d, want %d", got, tc.want)
		}
	}
}
