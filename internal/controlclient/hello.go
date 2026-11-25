package controlclient

import (
	"errors"
	"fmt"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
)

// HelloFields is every field of control.Hello this step can fill
// (docs/prompts/step-05b.md C3), pre-computed by the caller from
// internal/hostprobe, internal/apply, internal/store, internal/tetra and
// internal/identity -- none of which this package imports, keeping it
// "transport only" (C: "package internal/controlclient, transport only").
// See docs/reports/step-05b.md section 11 for each field's exact source.
type HelloFields struct {
	HostUUID     string
	AgentVersion string
	// AgentBuildDigest is the sha256 of the running binary
	// (/proc/self/exe), hex-encoded (control.proto Hello.agent_build_digest
	// is a string field, not bytes).
	AgentBuildDigest string
	TetragonVersion  string
	KernelRelease    string
	BootID           string
	// Epochs is scope -> current epoch (control.proto Hello.epochs).
	Epochs           map[string]uint64
	LoadedDigest     []byte
	LKGBundleDigest  []byte
	TrustRootDigest  []byte
	TrustRootVersion uint64
	ConfigDigest     []byte
	// PCRQuote is intentionally left nil/unset by every caller in this
	// step: remote attestation (architecture doc 6.3 step 3; the PCR
	// quote over HelloAck's nonce) is a later step.
}

// toProto builds the control.Hello message HelloFields describes.
func (f HelloFields) toProto() *controlv1.Hello {
	return &controlv1.Hello{
		HostUuid:         f.HostUUID,
		AgentVersion:     f.AgentVersion,
		AgentBuildDigest: f.AgentBuildDigest,
		TetragonVersion:  f.TetragonVersion,
		KernelRelease:    f.KernelRelease,
		BootId:           f.BootID,
		Epochs:           f.Epochs,
		LoadedDigest:     f.LoadedDigest,
		LkgBundleDigest:  f.LKGBundleDigest,
		TrustRootDigest:  f.TrustRootDigest,
		TrustRootVersion: f.TrustRootVersion,
		ConfigDigest:     f.ConfigDigest,
	}
}

// ErrUnexpectedMessage is returned by SendHello when the controller's
// first message on the stream is not a HelloAck.
var ErrUnexpectedMessage = errors.New("controlclient: expected HelloAck as the first message")

// HelloAckNonceSize is architecture doc 6.3 step 3's required HelloAck
// nonce length.
const HelloAckNonceSize = 32

// ErrBadNonceSize is returned by SendHello when HelloAck's nonce is not
// exactly HelloAckNonceSize bytes.
var ErrBadNonceSize = errors.New("controlclient: HelloAck nonce is not 32 bytes")

// agentMessageStream is the subset of AgentControl_ConnectClient SendHello
// needs, so it can be unit-tested against a fake without a real gRPC
// connection.
type agentMessageStream interface {
	Send(*controlv1.AgentMessage) error
	Recv() (*controlv1.ControllerMessage, error)
}

// SendHello sends fields as AgentMessage{seq: seq, hello: ...} on stream
// and waits for the controller's HelloAck (architecture doc 6.3 step 3).
// It implements only the Hello/HelloAck exchange; the full message loop
// is step 6.
func SendHello(stream agentMessageStream, seq uint64, fields HelloFields) (*controlv1.HelloAck, error) {
	msg := &controlv1.AgentMessage{
		Seq:  seq,
		Body: &controlv1.AgentMessage_Hello{Hello: fields.toProto()},
	}
	if err := stream.Send(msg); err != nil {
		return nil, fmt.Errorf("controlclient: send Hello: %w", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("controlclient: receive HelloAck: %w", err)
	}
	ack, ok := resp.GetBody().(*controlv1.ControllerMessage_HelloAck)
	if !ok {
		return nil, fmt.Errorf("%w: got %T", ErrUnexpectedMessage, resp.GetBody())
	}
	if len(ack.HelloAck.GetNonce()) != HelloAckNonceSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrBadNonceSize, len(ack.HelloAck.GetNonce()))
	}
	return ack.HelloAck, nil
}
