package controlclient

import (
	"errors"
	"testing"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
)

type fakeStream struct {
	sent    []*controlv1.AgentMessage
	sendErr error
	recv    *controlv1.ControllerMessage
	recvErr error
}

func (f *fakeStream) Send(m *controlv1.AgentMessage) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeStream) Recv() (*controlv1.ControllerMessage, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	return f.recv, nil
}

func validHelloFields() HelloFields {
	return HelloFields{
		HostUUID:         "11111111-1111-1111-1111-111111111111",
		AgentVersion:     "0.1.0",
		AgentBuildDigest: "deadbeef",
		TetragonVersion:  "v1.8.0",
		KernelRelease:    "5.14.0",
		BootID:           "boot-id",
		Epochs:           map[string]uint64{"prod-db": 5},
		LoadedDigest:     []byte("loaded"),
		LKGBundleDigest:  []byte("lkg"),
		TrustRootDigest:  []byte("root"),
		TrustRootVersion: 3,
		ConfigDigest:     []byte("config"),
	}
}

func TestSendHello_Success(t *testing.T) {
	nonce := make([]byte, HelloAckNonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	stream := &fakeStream{
		recv: &controlv1.ControllerMessage{
			Seq:  1,
			Body: &controlv1.ControllerMessage_HelloAck{HelloAck: &controlv1.HelloAck{Nonce: nonce, HeartbeatIntervalSeconds: 15}},
		},
	}
	ack, err := SendHello(stream, 1, validHelloFields())
	if err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	if len(ack.GetNonce()) != HelloAckNonceSize {
		t.Fatalf("HelloAck nonce length = %d, want %d", len(ack.GetNonce()), HelloAckNonceSize)
	}
	if ack.GetHeartbeatIntervalSeconds() != 15 {
		t.Fatalf("HeartbeatIntervalSeconds = %d, want 15", ack.GetHeartbeatIntervalSeconds())
	}
	if len(stream.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(stream.sent))
	}
	hello := stream.sent[0].GetHello()
	if hello == nil {
		t.Fatalf("sent message has no Hello body")
	}
	if hello.GetHostUuid() != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("Hello.HostUuid = %q", hello.GetHostUuid())
	}
	if hello.GetEpochs()["prod-db"] != 5 {
		t.Fatalf("Hello.Epochs[prod-db] = %d, want 5", hello.GetEpochs()["prod-db"])
	}
}

func TestSendHello_SendFailureSurfaces(t *testing.T) {
	wantErr := errors.New("send failed")
	stream := &fakeStream{sendErr: wantErr}
	if _, err := SendHello(stream, 1, validHelloFields()); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wrapping %v", err, wantErr)
	}
}

func TestSendHello_RecvFailureSurfaces(t *testing.T) {
	wantErr := errors.New("recv failed")
	stream := &fakeStream{recvErr: wantErr}
	if _, err := SendHello(stream, 1, validHelloFields()); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wrapping %v", err, wantErr)
	}
}

func TestSendHello_UnexpectedMessageTypeIsError(t *testing.T) {
	stream := &fakeStream{
		recv: &controlv1.ControllerMessage{
			Seq:  1,
			Body: &controlv1.ControllerMessage_Terminate{Terminate: &controlv1.Terminate{Reason: controlv1.Terminate_PROTOCOL_ERROR}},
		},
	}
	if _, err := SendHello(stream, 1, validHelloFields()); !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatalf("err = %v, want ErrUnexpectedMessage", err)
	}
}

func TestSendHello_BadNonceSizeIsError(t *testing.T) {
	stream := &fakeStream{
		recv: &controlv1.ControllerMessage{
			Seq:  1,
			Body: &controlv1.ControllerMessage_HelloAck{HelloAck: &controlv1.HelloAck{Nonce: []byte("too-short")}},
		},
	}
	if _, err := SendHello(stream, 1, validHelloFields()); !errors.Is(err, ErrBadNonceSize) {
		t.Fatalf("err = %v, want ErrBadNonceSize", err)
	}
}
