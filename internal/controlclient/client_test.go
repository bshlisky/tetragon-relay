package controlclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// startTestGRPCServer starts a real gRPC server over TLS (server cert
// carrying serverSPIFFEID as its URI SAN, self-signed -- NoClientCert so
// this test exercises Dial's transport/connectivity mechanics without
// needing a client certificate chain; mutual authentication's security
// properties are covered by TestVerifyConnection_* above and by the full
// TPM-backed integration test, docs/prompts/step-05b.md E3). Returns the
// listener address and a cleanup func.
func startTestGRPCServer(t *testing.T, serverSPIFFEID string) (addr string, serverCert *x509.Certificate) {
	t.Helper()
	cert, key := testCertAndKey(t, serverSPIFFEID)
	tlsCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLSCfg)))
	controlv1.RegisterAgentControlServer(srv, &controlv1.UnimplementedAgentControlServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})
	return lis.Addr().String(), cert
}

func TestDial_Success(t *testing.T) {
	serverSPIFFE := "spiffe://mgmt.example.internal/mgmt/controller"
	addr, serverCert := startTestGRPCServer(t, serverSPIFFE)

	cfg := Config{
		Endpoints:          []string{addr},
		ControllerSPIFFEID: serverSPIFFE,
		ControllerCABundle: []*x509.Certificate{serverCert}, // self-signed: the cert is its own root
		ClientCertificate:  testClientCert(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := AgentControlClient(conn)
	if client == nil {
		t.Fatalf("AgentControlClient returned nil")
	}
}

func TestDial_InvalidConfigIsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Dial(ctx, Config{}); err == nil {
		t.Fatalf("Dial with an empty config unexpectedly succeeded")
	}
}

func TestDial_WrongSPIFFEIDNeverBecomesReady(t *testing.T) {
	addr, serverCert := startTestGRPCServer(t, "spiffe://mgmt.example.internal/mgmt/controller")

	cfg := Config{
		Endpoints:          []string{addr},
		ControllerSPIFFEID: "spiffe://mgmt.example.internal/mgmt/collector", // wrong on purpose
		ControllerCABundle: []*x509.Certificate{serverCert},
		ClientCertificate:  testClientCert(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := Dial(ctx, cfg); err == nil {
		t.Fatalf("Dial with a mismatched controller SPIFFE ID unexpectedly succeeded")
	}
}

func TestDial_UnreachableEndpointRetriesUntilCanceled(t *testing.T) {
	ca, _ := testCertAndKey(t, "")
	cfg := Config{
		Endpoints:          []string{"127.0.0.1:1"}, // nothing listens here
		ControllerSPIFFEID: "spiffe://mgmt.example.internal/mgmt/controller",
		ControllerCABundle: []*x509.Certificate{ca},
		ClientCertificate:  testClientCert(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := Dial(ctx, cfg); err == nil {
		t.Fatalf("Dial to an unreachable endpoint unexpectedly succeeded")
	}
}
