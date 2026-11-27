package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

func TestStateMachine_TamperedHasNoExitButRevoked(t *testing.T) {
	aud := &FakeAuditor{}
	sm, _ := NewStateMachine(aud)
	for _, e := range []Event{EventJoinTokenValid, EventSVIDIssued, EventStoreTampered} {
		if err := sm.Fire(e); err != nil {
			t.Fatalf("%s: %v", e, err)
		}
	}
	if sm.Current() != StateTampered || sm.Current().String() != "TAMPERED" || EventStoreTampered.String() != "store_tampered" {
		t.Fatalf("state = %s", sm.Current())
	}
	for e := EventJoinTokenValid; e <= EventStoreTampered; e++ {
		if e == EventTerminateRevoked {
			continue
		}
		if err := sm.Fire(e); err == nil {
			t.Fatalf("TAMPERED accepted %s", e)
		}
	}
	if err := sm.Fire(EventTerminateRevoked); err != nil || sm.Current() != StateRevoked {
		t.Fatalf("Terminate{REVOKED} from TAMPERED: %v, state %s", err, sm.Current())
	}
	// EventStoreTampered is valid only from CONNECTING.
	sm2, _ := NewStateMachine(aud)
	if err := sm2.Fire(EventStoreTampered); err == nil {
		t.Fatal("UNENROLLED -> TAMPERED accepted")
	}
}

func newTamperedJobs(t *testing.T) (*TamperedJobs, *Outbox, *FakeAuditor) {
	t.Helper()
	aud := &FakeAuditor{}
	o := testOutbox()
	al, err := NewAlerter(o, aud, func() time.Time { return time.Unix(100, 0) })
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewTamperedJobs(o, al, aud)
	if err != nil {
		t.Fatal(err)
	}
	return j, o, aud
}

func TestTamperedJobs_RejectEverything(t *testing.T) {
	j, o, aud := newTamperedJobs(t)
	j.SubmitBundle([]byte("not even an envelope"))
	r := o.Peek().GetApplyResult()
	if r.GetStatus() != controlv1.ApplyResult_REJECTED_TAMPERED || r.GetEpoch() != 0 || string(r.GetBundleDigest()) != string(bundleDigest([]byte("not even an envelope"))) {
		t.Fatalf("result = %v", r)
	}
	o.Pop(o.Peek())
	j.SubmitTrustUpdate([][]byte{[]byte("root")})
	a := o.Peek().GetAlert()
	if a.GetKind() != controlv1.Alert_TRUST_UPDATE_REJECTED || !strings.Contains(a.GetDetail(), "TAMPERED") {
		t.Fatalf("alert = %v", a)
	}
	var steps []string
	for _, e := range aud.Events {
		steps = append(steps, e.Step)
	}
	if got := strings.Join(steps, ","); !strings.Contains(got, "bundle_rejected") || !strings.Contains(got, "trust_update_rejected") {
		t.Fatalf("audit steps = %s", got)
	}
	if _, err := NewTamperedJobs(nil, nil, nil); err == nil {
		t.Fatal("nil dependencies accepted")
	}
}

func TestTamperedSnapshotProvider_EmptyEpochs(t *testing.T) {
	p := &TamperedSnapshotProvider{Client: &fakeSnapshotClient{statuses: []tetra.TracingPolicyStatus{{Name: "p1", Enabled: true}}}}
	snap, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Epochs == nil || len(snap.Epochs) != 0 {
		t.Fatalf("epochs = %v, want an empty (non-nil) map", snap.Epochs)
	}
	if len(snap.LoadedDigest) != 32 || len(snap.Policies) != 1 || snap.LKGBundleDigest != nil || !snap.Health.GetServing() {
		t.Fatalf("snapshot = %+v", snap)
	}
	if _, err := (&TamperedSnapshotProvider{Client: &fakeSnapshotClient{err: errors.New("down")}}).Snapshot(context.Background()); err == nil {
		t.Fatal("Tetragon error not returned")
	}
	if _, err := (&TamperedSnapshotProvider{}).Snapshot(context.Background()); err == nil {
		t.Fatal("nil client accepted")
	}
}

func TestBestEffortRevocations(t *testing.T) {
	if err := (&BestEffortRevocations{}).MarkRevoked(time.Unix(1, 0), "x"); err == nil {
		t.Fatal("nil Mark accepted")
	}
	var got string
	b := &BestEffortRevocations{Mark: func(_ time.Time, r string) error { got = r; return nil }}
	if err := b.MarkRevoked(time.Unix(1, 0), "REVOKED: y"); err != nil || got != "REVOKED: y" {
		t.Fatalf("MarkRevoked: %v %q", err, got)
	}
}

// R6B-5 end to end through RunSession: TAMPER first after HelloAck, then
// heartbeats with an empty epochs map; a bundle gets REJECTED_TAMPERED; a
// RotateIdentity is refused; no connection transition leaves TAMPERED;
// Terminate{REVOKED} persists the marker best-effort and parks.
func TestRunSession_TamperedMode(t *testing.T) {
	aud := &syncAuditor{}
	sm, _ := NewStateMachine(aud)
	for _, e := range []Event{EventJoinTokenValid, EventSVIDIssued, EventStoreTampered} {
		if err := sm.Fire(e); err != nil {
			t.Fatal(err)
		}
	}
	clock := func() time.Time { return time.Unix(1000, 0) }
	rot := &fakeRotator{}
	snap := &TamperedSnapshotProvider{Client: &fakeSnapshotClient{}}
	cl, err := NewControlLoop(sm, aud, clock, snap, rot)
	if err != nil {
		t.Fatal(err)
	}
	outbox := testOutbox()
	alerter, _ := NewAlerter(outbox, aud, clock)
	jobs, _ := NewTamperedJobs(outbox, alerter, aud)
	cl.Jobs = jobs
	reg, _ := NewLivenessRegistry(clock)
	link, _ := NewLink(clock, time.Hour)
	revs := &fakeRevocations{err: errors.New("store TAMPERED")}

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
			Clock:             clock,
			Auditor:           aud,
			Liveness:          reg,
			Revocations:       &BestEffortRevocations{Mark: revs.MarkRevoked},
			HeartbeatInterval: 20 * time.Millisecond,
			Outbox:            outbox,
			Link:              link,
			OnConnected:       TamperedConnected(alerter, errors.New("index HMAC mismatch")),
		})
	}()

	waitSent := func(pred func([]*controlv1.AgentMessage) bool) []*controlv1.AgentMessage {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if m := stream.sentMessages(); pred(m) {
				return m
			}
			time.Sleep(2 * time.Millisecond)
		}
		t.Fatalf("timed out; sent = %v", stream.sentMessages())
		return nil
	}
	sent := waitSent(func(m []*controlv1.AgentMessage) bool { return len(m) >= 2 })
	if a := sent[0].GetAlert(); a.GetKind() != controlv1.Alert_TAMPER || !strings.Contains(a.GetDetail(), "index HMAC mismatch") {
		t.Fatalf("first message after HelloAck = %v, want Alert{TAMPER}", sent[0])
	}
	hb := sent[1].GetHeartbeat()
	if hb == nil || len(hb.GetEpochs()) != 0 || len(hb.GetLoadedDigest()) != 32 {
		t.Fatalf("second message = %v, want a heartbeat with empty epochs and a loaded digest", sent[1])
	}
	if sm.Current() != StateTampered {
		t.Fatalf("state after connect = %s, want TAMPERED", sm.Current())
	}

	stream.in <- &controlv1.ControllerMessage{Seq: 2, Body: &controlv1.ControllerMessage_Bundle{Bundle: &controlv1.PolicyBundle{Envelope: []byte("{}")}}}
	sent = waitSent(func(m []*controlv1.AgentMessage) bool {
		for _, x := range m {
			if x.GetApplyResult() != nil {
				return true
			}
		}
		return false
	})
	for _, x := range sent {
		if r := x.GetApplyResult(); r != nil && r.GetStatus() != controlv1.ApplyResult_REJECTED_TAMPERED {
			t.Fatalf("bundle result = %v", r)
		}
	}
	stream.in <- &controlv1.ControllerMessage{Seq: 3, Body: &controlv1.ControllerMessage_RotateIdentity{RotateIdentity: &controlv1.RotateIdentity{Reason: "r"}}}
	stream.in <- &controlv1.ControllerMessage{Seq: 4, Body: &controlv1.ControllerMessage_Terminate{Terminate: &controlv1.Terminate{Reason: controlv1.Terminate_REVOKED, Detail: "gone"}}}
	deadline := time.Now().Add(3 * time.Second)
	for sm.Current() != StateRevoked && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if sm.Current() != StateRevoked {
		t.Fatalf("state = %s, want REVOKED", sm.Current())
	}
	deadline = time.Now().Add(3 * time.Second)
	for !aud.HasStep("session_parked") && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunSession: %v", err)
	}
	if rot.rotateCalls != 0 {
		t.Fatal("tampered mode rotated the identity")
	}
	for _, want := range []string{"rotate_identity_refused", "revocation_persist_failed", "session_parked"} {
		if !aud.HasStep(want) {
			t.Fatalf("no %s audit record; steps = %v", want, aud.steps)
		}
	}
	if aud.HasStep("session_state_transition_failed") {
		t.Fatal("a connection transition was attempted from TAMPERED")
	}
}
