package testcontroller

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Config is everything the test server needs to run (architecture doc
// 6.1's TLS profile, 6.3's client checks).
type Config struct {
	// TrustDomain is the SPIFFE trust domain agent certificates' URI
	// SANs are checked against ("spiffe://<TrustDomain>/host/<uuid>").
	TrustDomain string
	// ServerCertificate is this test controller's own mTLS identity
	// (architecture doc 6.1/6.2: SPIFFE ID "spiffe://<td>/mgmt/controller").
	ServerCertificate tls.Certificate
	// ClientCABundle verifies agent certificates' chains.
	ClientCABundle []*x509.Certificate
	// Denylist is the set of host UUIDs architecture doc 6.3 step 2's
	// "checked on every stream open" denylist refuses (Terminate{REVOKED}).
	Denylist map[string]bool
	// Inventory is the set of host UUIDs this test server considers
	// registered (architecture doc 6.3 step 2: "host-uuid exists in
	// inventory"); a host UUID absent from this set is refused. Nil
	// means "every host UUID is inventoried" (useful for simple tests
	// that only exercise the other checks).
	Inventory map[string]bool
	// HeartbeatIntervalSeconds is reported in HelloAck.
	HeartbeatIntervalSeconds uint32
}

// ServerTLSConfig builds the *tls.Config for Config: TLS 1.3 only,
// mutual authentication required (RequireAndVerifyClientCert), chain
// verified against ClientCABundle.
func ServerTLSConfig(cfg Config) *tls.Config {
	pool := x509.NewCertPool()
	for _, c := range cfg.ClientCABundle {
		pool.AddCert(c)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cfg.ServerCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
}

// Server implements controlv1.AgentControlServer: the TLS/client-check
// and Hello/HelloAck subset docs/prompts/step-05b.md E2 asks for.
type Server struct {
	controlv1.UnimplementedAgentControlServer
	cfg Config
}

// NewServer constructs a Server from cfg.
func NewServer(cfg Config) *Server { return &Server{cfg: cfg} }

// Credentials returns the gRPC transport credentials for cfg's TLS
// profile, for use with grpc.Creds when constructing the server.
func (s *Server) Credentials() credentials.TransportCredentials {
	return credentials.NewTLS(ServerTLSConfig(s.cfg))
}

var (
	// ErrNoPeerCertificate is returned when the stream's peer presented
	// no TLS certificate at all (should be unreachable given
	// RequireAndVerifyClientCert, but checked explicitly rather than
	// assumed).
	ErrNoPeerCertificate = errors.New("testcontroller: no peer certificate")
	// ErrBadHostURISAN is returned when the peer certificate's URI SAN
	// does not match "spiffe://<trust-domain>/host/<uuid>".
	ErrBadHostURISAN = errors.New("testcontroller: peer certificate URI SAN is not a valid host SPIFFE ID for this trust domain")
)

// Connect implements controlv1.AgentControlServer (architecture doc 6.2's
// Connect RPC; 6.3 steps 1-3: authorize, then Hello/HelloAck). The full
// message loop (reconcile, heartbeats, bundle push) is step 6 -- this test
// server returns after the Hello/HelloAck exchange.
func (s *Server) Connect(stream controlv1.AgentControl_ConnectServer) error {
	hostUUID, err := s.authorize(stream.Context())
	if err != nil {
		_ = stream.Send(&controlv1.ControllerMessage{
			Body: &controlv1.ControllerMessage_Terminate{Terminate: &controlv1.Terminate{
				Reason: terminateReasonFor(err), Detail: err.Error(),
			}},
		})
		return err
	}

	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("testcontroller: receive Hello: %w", err)
	}
	hello := msg.GetHello()
	if hello == nil {
		return fmt.Errorf("testcontroller: expected Hello as the first message, got %T", msg.GetBody())
	}
	if hello.GetHostUuid() != hostUUID {
		return fmt.Errorf("testcontroller: Hello.host_uuid %q does not match the certificate's host UUID %q", hello.GetHostUuid(), hostUUID)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("testcontroller: generate nonce: %w", err)
	}
	return stream.Send(&controlv1.ControllerMessage{
		Body: &controlv1.ControllerMessage_HelloAck{HelloAck: &controlv1.HelloAck{
			Nonce: nonce, HeartbeatIntervalSeconds: s.cfg.HeartbeatIntervalSeconds,
		}},
	})
}

// ErrDenylisted and ErrNotInInventory are the two 6.3-step-2 authorization
// failures this test server implements.
var (
	ErrDenylisted     = errors.New("testcontroller: host UUID is on the denylist")
	ErrNotInInventory = errors.New("testcontroller: host UUID is not in inventory")
)

func terminateReasonFor(err error) controlv1.Terminate_Reason {
	switch {
	case errors.Is(err, ErrDenylisted):
		return controlv1.Terminate_REVOKED
	default:
		return controlv1.Terminate_PROTOCOL_ERROR
	}
}

// authorize implements architecture doc 6.3 step 2's checks this test
// server covers: the peer certificate's chain was already verified by TLS
// itself (RequireAndVerifyClientCert); here, the URI SAN is parsed into a
// host UUID, checked against the denylist, then against inventory.
func (s *Server) authorize(ctx context.Context) (hostUUID string, err error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", ErrNoPeerCertificate
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", ErrNoPeerCertificate
	}
	leaf := tlsInfo.State.PeerCertificates[0]
	hostUUID, ok = parseHostURISAN(leaf, s.cfg.TrustDomain)
	if !ok {
		return "", ErrBadHostURISAN
	}
	if s.cfg.Denylist[hostUUID] {
		return "", ErrDenylisted
	}
	if s.cfg.Inventory != nil && !s.cfg.Inventory[hostUUID] {
		return "", ErrNotInInventory
	}
	return hostUUID, nil
}

func parseHostURISAN(cert *x509.Certificate, trustDomain string) (hostUUID string, ok bool) {
	if len(cert.URIs) != 1 {
		return "", false
	}
	prefix := fmt.Sprintf("spiffe://%s/host/", trustDomain)
	s := cert.URIs[0].String()
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		return "", false
	}
	return s[len(prefix):], true
}
