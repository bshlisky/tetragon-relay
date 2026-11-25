package testcontroller

import (
	"context"
	"errors"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
)

const scriptTestHostUUID = "66666666-6666-6666-6666-666666666666"

func scriptTestStream(t *testing.T, inbound ...*controlv1.AgentMessage) *fakeConnectStream {
	t.Helper()
	leaf := testCert(t, "spiffe://mgmt.example.internal/host/"+scriptTestHostUUID)
	return &fakeConnectStream{ctx: authorizedContext(leaf), inbound: inbound}
}

func connectWithHello(t *testing.T, s *Server, stream *fakeConnectStream) error {
	t.Helper()
	stream.inbound = append([]*controlv1.AgentMessage{{
		Seq:  firstSeq,
		Body: &controlv1.AgentMessage_Hello{Hello: &controlv1.Hello{HostUuid: scriptTestHostUUID}},
	}}, stream.inbound...)
	return s.Connect(stream)
}

func TestServer_NilScript_ReturnsAfterHelloAck(t *testing.T) {
	s := NewServer(Config{TrustDomain: "mgmt.example.internal"})
	stream := scriptTestStream(t)
	if err := connectWithHello(t, s, stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("sent %d messages, want exactly 1 (HelloAck)", len(stream.sent))
	}
}

func TestServer_Script_ReceivesHeartbeat(t *testing.T) {
	var gotSeq uint64
	s := NewServer(Config{TrustDomain: "mgmt.example.internal", Script: func(_ context.Context, stream ScriptStream, hostUUID string) error {
		if hostUUID != scriptTestHostUUID {
			t.Errorf("script hostUUID = %q, want %q", hostUUID, scriptTestHostUUID)
		}
		msg, err := WaitForAgentMessage(stream, time.Second)
		if err != nil {
			return err
		}
		gotSeq = msg.GetSeq()
		if _, ok := msg.GetBody().(*controlv1.AgentMessage_Heartbeat); !ok {
			t.Errorf("message body = %T, want Heartbeat", msg.GetBody())
		}
		return nil
	}})
	stream := scriptTestStream(t, &controlv1.AgentMessage{Seq: 2, Body: &controlv1.AgentMessage_Heartbeat{Heartbeat: &controlv1.Heartbeat{}}})
	if err := connectWithHello(t, s, stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if gotSeq != 2 {
		t.Fatalf("heartbeat seq = %d, want 2", gotSeq)
	}
}

func TestServer_Script_NoMoreMessagesIsNotATimeout(t *testing.T) {
	s := NewServer(Config{TrustDomain: "mgmt.example.internal", Script: func(_ context.Context, stream ScriptStream, _ string) error {
		_, err := WaitForAgentMessage(stream, time.Second)
		return err
	}})
	// fakeConnectStream.Recv returns io.EOF once its scripted inbound
	// queue is exhausted (not a real block): WaitForAgentMessage must
	// propagate that promptly, not wait out its own timeout and return
	// ErrScriptTimeout instead.
	stream := scriptTestStream(t)
	err := connectWithHello(t, s, stream)
	if err == nil || errors.Is(err, ErrScriptTimeout) {
		t.Fatalf("Connect error = %v, want the stream's own io.EOF, not ErrScriptTimeout", err)
	}
}

func TestWaitForAgentMessage_TimesOutOnARealBlock(t *testing.T) {
	blocked := &blockingStream{}
	_, err := WaitForAgentMessage(blocked, 10*time.Millisecond)
	if !errors.Is(err, ErrScriptTimeout) {
		t.Fatalf("error = %v, want ErrScriptTimeout", err)
	}
}

// blockingStream's Recv never returns, so WaitForAgentMessage's own
// timeout path (as opposed to the stream itself returning an error
// quickly, like fakeConnectStream's io.EOF above) is exercised for real.
type blockingStream struct{}

func (blockingStream) Send(*controlv1.ControllerMessage) error { return nil }
func (blockingStream) Recv() (*controlv1.AgentMessage, error) {
	select {} // never returns
}

func TestServer_Script_StateRequestRoundTrip(t *testing.T) {
	var gotReport *controlv1.StateReport
	s := NewServer(Config{TrustDomain: "mgmt.example.internal", Script: func(_ context.Context, stream ScriptStream, _ string) error {
		seq := NewNextSeqAfterHelloAck()
		if err := SendStateRequest(stream, seq, []byte("nonce-123")); err != nil {
			return err
		}
		msg, err := WaitForAgentMessage(stream, time.Second)
		if err != nil {
			return err
		}
		gotReport = msg.GetStateReport()
		return nil
	}})
	stream := scriptTestStream(t, &controlv1.AgentMessage{
		Seq: 2, Body: &controlv1.AgentMessage_StateReport{StateReport: &controlv1.StateReport{Nonce: []byte("nonce-123")}},
	})
	if err := connectWithHello(t, s, stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if gotReport == nil || string(gotReport.GetNonce()) != "nonce-123" {
		t.Fatalf("StateReport = %v, want nonce echoed back", gotReport)
	}
	if sent := stream.sent[1]; sent.GetSeq() != 2 || sent.GetStateRequest() == nil {
		t.Fatalf("sent StateRequest = %v, want seq 2", sent)
	}
}

func TestServer_Script_RotateIdentity(t *testing.T) {
	s := NewServer(Config{TrustDomain: "mgmt.example.internal", Script: func(_ context.Context, stream ScriptStream, _ string) error {
		seq := NewNextSeqAfterHelloAck()
		return SendRotateIdentity(stream, seq, "scheduled rotation")
	}})
	stream := scriptTestStream(t)
	if err := connectWithHello(t, s, stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	sent := stream.sent[1]
	rot := sent.GetRotateIdentity()
	if rot == nil || rot.GetReason() != "scheduled rotation" {
		t.Fatalf("sent RotateIdentity = %v, want reason set", sent)
	}
}

func TestServer_Script_EveryTerminateReason(t *testing.T) {
	reasons := []controlv1.Terminate_Reason{
		controlv1.Terminate_REASON_UNSPECIFIED,
		controlv1.Terminate_DUPLICATE_SESSION,
		controlv1.Terminate_PROTOCOL_ERROR,
		controlv1.Terminate_REVOKED,
		controlv1.Terminate_SHUTDOWN,
	}
	for _, reason := range reasons {
		t.Run(reason.String(), func(t *testing.T) {
			s := NewServer(Config{TrustDomain: "mgmt.example.internal", Script: func(_ context.Context, stream ScriptStream, _ string) error {
				seq := NewNextSeqAfterHelloAck()
				return SendTerminate(stream, seq, reason, "test: "+reason.String())
			}})
			stream := scriptTestStream(t)
			if err := connectWithHello(t, s, stream); err != nil {
				t.Fatalf("Connect: %v", err)
			}
			term := stream.sent[1].GetTerminate()
			if term == nil || term.GetReason() != reason {
				t.Fatalf("sent Terminate = %v, want reason %s", stream.sent[1], reason)
			}
		})
	}
}

func TestServer_Script_OutOfOrderSeq(t *testing.T) {
	s := NewServer(Config{TrustDomain: "mgmt.example.internal", Script: func(_ context.Context, stream ScriptStream, _ string) error {
		// seq 5 instead of the expected 2: a conforming agent's
		// SeqTracker.Check rejects this and closes the stream.
		return SendAtSeq(stream, 5, &controlv1.ControllerMessage{
			Body: &controlv1.ControllerMessage_RotateIdentity{RotateIdentity: &controlv1.RotateIdentity{}},
		})
	}})
	stream := scriptTestStream(t)
	if err := connectWithHello(t, s, stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if sent := stream.sent[1]; sent.GetSeq() != 5 {
		t.Fatalf("sent seq = %d, want 5 (deliberately out of order)", sent.GetSeq())
	}
}

func TestServer_Script_OversizedTerminate(t *testing.T) {
	const oversize = 2 << 20 // 2 MiB, over architecture doc 6.1's 1 MiB frame cap
	s := NewServer(Config{TrustDomain: "mgmt.example.internal", Script: func(_ context.Context, stream ScriptStream, _ string) error {
		seq := NewNextSeqAfterHelloAck()
		return SendOversizedTerminate(stream, seq, oversize)
	}})
	stream := scriptTestStream(t)
	if err := connectWithHello(t, s, stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if got := len(stream.sent[1].GetTerminate().GetDetail()); got != oversize {
		t.Fatalf("sent Terminate.Detail length = %d, want %d", got, oversize)
	}
}

func TestServer_Script_UnknownMessageType(t *testing.T) {
	s := NewServer(Config{TrustDomain: "mgmt.example.internal", Script: func(_ context.Context, stream ScriptStream, _ string) error {
		seq := NewNextSeqAfterHelloAck()
		return SendUnknownMessageType(stream, seq)
	}})
	stream := scriptTestStream(t)
	if err := connectWithHello(t, s, stream); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if sent := stream.sent[1]; sent.GetBody() != nil {
		t.Fatalf("sent message body = %T, want nil (no oneof case set)", sent.GetBody())
	}
}

func TestDoNothingScript(t *testing.T) {
	if err := DoNothingScript(context.Background(), nil, ""); err != nil {
		t.Fatalf("DoNothingScript returned %v, want nil", err)
	}
}

func TestNextSeq(t *testing.T) {
	seq := NewNextSeqAfterHelloAck()
	if got := seq.Next(); got != 2 {
		t.Fatalf("first Next() = %d, want 2", got)
	}
	if got := seq.Next(); got != 3 {
		t.Fatalf("second Next() = %d, want 3", got)
	}
}
