package testcontroller

import (
	"context"
	"fmt"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
)

// NextSeq is a Script's own per-stream outbound seq counter (ADR 0032:
// seq starts at 1 per direction; Connect's HelloAck already used seq 1,
// so a fresh Script's first message is seq 2).
type NextSeq struct{ next uint64 }

// NewNextSeqAfterHelloAck returns a NextSeq whose first Next() call
// returns 2.
func NewNextSeqAfterHelloAck() *NextSeq { return &NextSeq{next: 2} }

// Next returns the next seq value and advances. Override skips this
// counter entirely and returns v without advancing next -- used to
// deliberately send an out-of-order seq (docs/prompts/step-06a.md E2).
func (s *NextSeq) Next() uint64 {
	v := s.next
	s.next++
	return v
}

// Override returns v without consulting or advancing the counter, for
// Part E2's out-of-order-seq scenario.
func (s *NextSeq) Override(v uint64) uint64 { return v }

// ErrScriptTimeout is returned by WaitForAgentMessage when the agent
// does not send anything within the given timeout.
var ErrScriptTimeout = fmt.Errorf("testcontroller: script: timed out waiting for an AgentMessage")

// WaitForAgentMessage reads the next AgentMessage from stream, or
// returns ErrScriptTimeout if Recv itself does not return within
// timeout. Recv runs in its own goroutine so a timeout never leaves the
// caller blocked on it; the goroutine is abandoned (not joined) on
// timeout, matching every other place in this repository that reads
// from a blocking stream under a deadline (e.g. internal/agent's own
// control-loop driver).
func WaitForAgentMessage(stream ScriptStream, timeout time.Duration) (*controlv1.AgentMessage, error) {
	type result struct {
		msg *controlv1.AgentMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, err := stream.Recv()
		ch <- result{msg, err}
	}()
	select {
	case r := <-ch:
		return r.msg, r.err
	case <-time.After(timeout):
		return nil, ErrScriptTimeout
	}
}

// SendStateRequest sends a StateRequest with nonce (Part D2: the agent
// must echo it in its StateReport).
func SendStateRequest(stream ScriptStream, seq *NextSeq, nonce []byte) error {
	return stream.Send(&controlv1.ControllerMessage{
		Seq:  seq.Next(),
		Body: &controlv1.ControllerMessage_StateRequest{StateRequest: &controlv1.StateRequest{Nonce: nonce}},
	})
}

// SendRotateIdentity sends a RotateIdentity request.
func SendRotateIdentity(stream ScriptStream, seq *NextSeq, reason string) error {
	return stream.Send(&controlv1.ControllerMessage{
		Seq:  seq.Next(),
		Body: &controlv1.ControllerMessage_RotateIdentity{RotateIdentity: &controlv1.RotateIdentity{Reason: reason}},
	})
}

// SendTerminate sends a Terminate with reason and detail. The caller is
// expected to stop driving the stream afterward (a real agent closes
// its side on every Terminate reason, per internal/agent.ControlLoop.
// HandleControllerMessage).
func SendTerminate(stream ScriptStream, seq *NextSeq, reason controlv1.Terminate_Reason, detail string) error {
	return stream.Send(&controlv1.ControllerMessage{
		Seq:  seq.Next(),
		Body: &controlv1.ControllerMessage_Terminate{Terminate: &controlv1.Terminate{Reason: reason, Detail: detail}},
	})
}

// SendAtSeq sends msg with Seq forced to seq, ignoring any NextSeq
// counter (Part E2's out-of-order-seq scenario: a conforming agent must
// close the stream with a protocol error, ADR 0032; internal/agent.
// SeqTracker.Check).
func SendAtSeq(stream ScriptStream, seq uint64, msg *controlv1.ControllerMessage) error {
	msg.Seq = seq
	return stream.Send(msg)
}

// SendOversizedTerminate sends a Terminate whose Detail field alone
// exceeds limits.MaxControlMessageBytes once serialized (Part E2's
// oversize-message scenario): architecture doc 6.1's 1 MiB frame cap is
// already enforced by internal/controlclient's own grpc.
// MaxCallRecvMsgSize dial option (defense in depth at the transport
// layer, not application code this package or internal/agent needs to
// duplicate), so a conforming agent's stream read fails outright rather
// than ever reaching HandleControllerMessage's own dispatch.
func SendOversizedTerminate(stream ScriptStream, seq *NextSeq, oversizeBytes int) error {
	detail := make([]byte, oversizeBytes)
	for i := range detail {
		detail[i] = 'A'
	}
	return stream.Send(&controlv1.ControllerMessage{
		Seq:  seq.Next(),
		Body: &controlv1.ControllerMessage_Terminate{Terminate: &controlv1.Terminate{Detail: string(detail)}},
	})
}

// SendUnknownMessageType sends a ControllerMessage with no oneof case
// set at all (Part E2's unknown-message-type scenario): protobuf leaves
// an unrecognized/unset oneof as a nil Body on the receiving end, which
// internal/agent.ControlLoop.HandleControllerMessage's type switch has
// no case for -- its default arm closes the stream with ErrProtocolError,
// exactly as architecture doc P7/control.proto's closed message set
// requires ("the agent never executes anything not in the closed
// message set").
func SendUnknownMessageType(stream ScriptStream, seq *NextSeq) error {
	return stream.Send(&controlv1.ControllerMessage{Seq: seq.Next()})
}

// DoNothingScript is a Script that returns immediately after Hello/
// HelloAck -- Config's zero value already behaves this way (nil
// Script); this exists only so a caller that wants to be explicit about
// "no script" in a table of scripts can name one.
func DoNothingScript(context.Context, ScriptStream, string) error { return nil }
