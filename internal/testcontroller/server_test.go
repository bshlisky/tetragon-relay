package testcontroller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/url"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// fakeConnectStream implements controlv1.AgentControl_ConnectServer
// (grpc.BidiStreamingServer[AgentMessage, ControllerMessage]) without a
// real gRPC connection, so Connect's seq-enforcement (docs/decisions/
// 0032-seq-numbering-starts-at-one.md) can be unit-tested directly.
type fakeConnectStream struct {
	ctx     context.Context
	inbound []*controlv1.AgentMessage
	idx     int
	sent    []*controlv1.ControllerMessage
}

func (f *fakeConnectStream) Recv() (*controlv1.AgentMessage, error) {
	if f.idx >= len(f.inbound) {
		return nil, io.EOF
	}
	m := f.inbound[f.idx]
	f.idx++
	return m, nil
}

func (f *fakeConnectStream) Send(m *controlv1.ControllerMessage) error {
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeConnectStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeConnectStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeConnectStream) SetTrailer(metadata.MD)       {}
func (f *fakeConnectStream) Context() context.Context     { return f.ctx }
func (f *fakeConnectStream) SendMsg(any) error            { return nil }
func (f *fakeConnectStream) RecvMsg(any) error            { return nil }

// authorizedContext builds a context carrying leaf as the stream's peer
// TLS certificate, as authorize expects to find it.
func authorizedContext(leaf *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}},
	})
}

func testCertAndKey(t *testing.T, uri string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var uris []*url.URL
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("url.Parse: %v", err)
		}
		uris = []*url.URL{u}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

func testCert(t *testing.T, uri string) *x509.Certificate {
	t.Helper()
	cert, _ := testCertAndKey(t, uri)
	return cert
}

func TestParseHostURISAN(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		wantUUID    string
		wantOK      bool
		trustDomain string
	}{
		{"valid", "spiffe://mgmt.example.internal/host/abc-123", "abc-123", true, "mgmt.example.internal"},
		{"wrong trust domain", "spiffe://other.internal/host/abc-123", "", false, "mgmt.example.internal"},
		{"not a host SPIFFE ID", "spiffe://mgmt.example.internal/mgmt/controller", "", false, "mgmt.example.internal"},
		{"no URI SAN", "", "", false, "mgmt.example.internal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := testCert(t, tc.uri)
			gotUUID, gotOK := parseHostURISAN(cert, tc.trustDomain)
			if gotOK != tc.wantOK || gotUUID != tc.wantUUID {
				t.Fatalf("parseHostURISAN = (%q, %v), want (%q, %v)", gotUUID, gotOK, tc.wantUUID, tc.wantOK)
			}
		})
	}
}

func TestConnect_FirstSeqMustBeOne(t *testing.T) {
	leaf := testCert(t, "spiffe://mgmt.example.internal/host/11111111-1111-1111-1111-111111111111")
	s := NewServer(Config{TrustDomain: "mgmt.example.internal"})

	tests := []struct {
		name    string
		seq     uint64
		wantErr bool
	}{
		{"seq 1 is accepted", 1, false},
		{"seq 0 is rejected", 0, true},
		{"seq 2 is rejected", 2, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stream := &fakeConnectStream{
				ctx: authorizedContext(leaf),
				inbound: []*controlv1.AgentMessage{{
					Seq:  tc.seq,
					Body: &controlv1.AgentMessage_Hello{Hello: &controlv1.Hello{HostUuid: "11111111-1111-1111-1111-111111111111"}},
				}},
			}
			err := s.Connect(stream)
			if tc.wantErr {
				if err == nil || !errors.Is(err, ErrBadInitialSeq) {
					t.Fatalf("Connect error = %v, want ErrBadInitialSeq", err)
				}
				if len(stream.sent) != 1 {
					t.Fatalf("sent %d messages, want exactly 1 Terminate", len(stream.sent))
				}
				term := stream.sent[0].GetTerminate()
				if term == nil || term.GetReason() != controlv1.Terminate_PROTOCOL_ERROR {
					t.Fatalf("sent message = %v, want Terminate{PROTOCOL_ERROR}", stream.sent[0])
				}
				if stream.sent[0].GetSeq() != firstSeq {
					t.Fatalf("Terminate seq = %d, want %d", stream.sent[0].GetSeq(), firstSeq)
				}
				return
			}
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}
			if len(stream.sent) != 1 {
				t.Fatalf("sent %d messages, want exactly 1 HelloAck", len(stream.sent))
			}
			if stream.sent[0].GetHelloAck() == nil {
				t.Fatalf("sent message = %v, want HelloAck", stream.sent[0])
			}
			if stream.sent[0].GetSeq() != firstSeq {
				t.Fatalf("HelloAck seq = %d, want %d", stream.sent[0].GetSeq(), firstSeq)
			}
		})
	}
}

func TestServerTLSConfig_Shape(t *testing.T) {
	serverCert, serverKey := testCertAndKey(t, "spiffe://mgmt.example.internal/mgmt/controller")
	cfg := Config{
		ServerCertificate: tls.Certificate{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey, Leaf: serverCert},
		ClientCABundle:    []*x509.Certificate{serverCert},
	}
	tlsCfg := ServerTLSConfig(cfg)
	if tlsCfg.MinVersion != 0x0304 || tlsCfg.MaxVersion != 0x0304 {
		t.Fatalf("MinVersion/MaxVersion = %#x/%#x, want TLS 1.3 only", tlsCfg.MinVersion, tlsCfg.MaxVersion)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("Certificates length = %d, want 1", len(tlsCfg.Certificates))
	}
}
