package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/testcontroller"
	"google.golang.org/grpc"
)

// This file exercises RealConnector against a real TLS/gRPC server
// (internal/testcontroller, no build tag) over a real loopback
// connection -- RealConnector's own glue (controlclient.Dial, the
// Connect RPC and SendHello) cannot be exercised through a fake, unlike
// everything else in this package's session tests. It builds its own
// minimal ECDSA P-384 CA and leaf certificates directly (rather than
// internal/identity.TestCA, which is gated behind the testca build tag
// and so not available to this package's ordinary, untagged test run),
// since RealConnector's own contract has nothing to do with identity
// enrollment itself -- only with dialing and completing Hello/HelloAck
// once a certificate already exists.

const connectorTestTrustDomain = "connector-test.example.internal"

type connectorTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newConnectorTestCA(t *testing.T) *connectorTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "connector test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &connectorTestCA{cert: cert, key: key}
}

func (ca *connectorTestCA) issue(t *testing.T, spiffeID string, eku x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("parse spiffe id: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: spiffeID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// startConnectorTestServer starts a real internal/testcontroller server
// on a loopback TCP listener and returns its address.
func startConnectorTestServer(t *testing.T, cfg testcontroller.Config) string {
	t.Helper()
	srv := testcontroller.NewServer(cfg)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(srv.Credentials()))
	controlv1.RegisterAgentControlServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop(); _ = lis.Close() })
	return lis.Addr().String()
}

func TestRealConnector_ConnectSucceeds(t *testing.T) {
	ca := newConnectorTestCA(t)
	controllerSPIFFE := "spiffe://" + connectorTestTrustDomain + "/mgmt/controller"
	serverCert := ca.issue(t, controllerSPIFFE, x509.ExtKeyUsageServerAuth)
	hostUUID := "11111111-1111-1111-1111-111111111111"
	clientCert := ca.issue(t, "spiffe://"+connectorTestTrustDomain+"/host/"+hostUUID, x509.ExtKeyUsageClientAuth)

	addr := startConnectorTestServer(t, testcontroller.Config{
		TrustDomain: connectorTestTrustDomain, ServerCertificate: serverCert,
		ClientCABundle: []*x509.Certificate{ca.cert}, HeartbeatIntervalSeconds: 15,
	})

	connector := &RealConnector{
		Config: func() controlclient.Config {
			return controlclient.Config{
				Endpoints: []string{addr}, ControllerSPIFFEID: controllerSPIFFE,
				ControllerCABundle: []*x509.Certificate{ca.cert}, ClientCertificate: clientCert, Clock: time.Now,
			}
		},
		Rand: func() float64 { return 0 },
	}

	touches := 0
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, closeFn, err := connector.Connect(ctx, func() controlclient.HelloFields {
		return controlclient.HelloFields{HostUUID: hostUUID, AgentVersion: "test"}
	}, func() { touches++ })
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = closeFn() }()
	if stream == nil {
		t.Fatal("Connect returned a nil stream on success")
	}
}

func TestRealConnector_RetriesHelloRejectionWithBackoff(t *testing.T) {
	ca := newConnectorTestCA(t)
	controllerSPIFFE := "spiffe://" + connectorTestTrustDomain + "/mgmt/controller"
	serverCert := ca.issue(t, controllerSPIFFE, x509.ExtKeyUsageServerAuth)
	hostUUID := "22222222-2222-2222-2222-222222222222"
	clientCert := ca.issue(t, "spiffe://"+connectorTestTrustDomain+"/host/"+hostUUID, x509.ExtKeyUsageClientAuth)

	// Inventory excludes hostUUID: every Connect attempt is refused
	// with Terminate before Hello/HelloAck completes (architecture doc
	// 6.3 step 2), so RealConnector must retry with backoff rather
	// than returning the first failure.
	addr := startConnectorTestServer(t, testcontroller.Config{
		TrustDomain: connectorTestTrustDomain, ServerCertificate: serverCert,
		ClientCABundle: []*x509.Certificate{ca.cert},
		Inventory:      map[string]bool{"99999999-9999-9999-9999-999999999999": true},
	})

	connector := &RealConnector{
		Config: func() controlclient.Config {
			return controlclient.Config{
				Endpoints: []string{addr}, ControllerSPIFFEID: controllerSPIFFE,
				ControllerCABundle: []*x509.Certificate{ca.cert}, ClientCertificate: clientCert, Clock: time.Now,
			}
		},
		Rand: func() float64 { return 1 - 1e-9 }, // near-maximal jitter: DialBackoff(0, ~1) is close to its 1s base, long enough to observe a touch
	}

	// Test seam (connector.go's own doc comment): shrink the touch
	// interval well below the backoff delay above, so this test
	// observes at least one touch without waiting anywhere near 5 real
	// seconds per attempt.
	restore := sessionLivenessTouchInterval
	sessionLivenessTouchInterval = 20 * time.Millisecond
	defer func() { sessionLivenessTouchInterval = restore }()

	var touches int
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err := connector.Connect(ctx, func() controlclient.HelloFields {
		return controlclient.HelloFields{HostUUID: hostUUID}
	}, func() { touches++ })
	if err == nil {
		t.Fatal("Connect unexpectedly succeeded against a host UUID not in inventory")
	}
	if touches == 0 {
		t.Fatal("touch was never called; the retry/backoff path (sleepWithTouch) was not exercised")
	}
}

// TestRealConnector_StuckAttemptTimesOutAndRetries is R6A-4's own test
// (step-06a-e3-prompt.md): the first endpoint is a raw TCP listener that
// accepts every connection and then never speaks (no TLS handshake, no
// bytes at all) -- a Connector that, before R6A-4, would block forever
// inside controlclient.Dial's WaitForStateChange. It asserts the first
// attempt fails and backs off within a bounded window around
// limits.ControlConnectAttemptTimeout (never instantly, never anywhere
// close to hanging forever), and that the second attempt (a real
// endpoint c.Config switches to after the first call) succeeds.
func TestRealConnector_StuckAttemptTimesOutAndRetries(t *testing.T) {
	blackHole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen (black hole): %v", err)
	}
	var acceptedMu sync.Mutex
	var accepted []net.Conn
	t.Cleanup(func() {
		_ = blackHole.Close()
		acceptedMu.Lock()
		defer acceptedMu.Unlock()
		for _, c := range accepted {
			_ = c.Close()
		}
	})
	go func() {
		for {
			conn, aerr := blackHole.Accept()
			if aerr != nil {
				return
			}
			// Accept and hold the connection open; never read, write
			// or close it. Simulates a network path that completes the
			// TCP handshake but never progresses TLS.
			acceptedMu.Lock()
			accepted = append(accepted, conn)
			acceptedMu.Unlock()
		}
	}()

	ca := newConnectorTestCA(t)
	controllerSPIFFE := "spiffe://" + connectorTestTrustDomain + "/mgmt/controller"
	serverCert := ca.issue(t, controllerSPIFFE, x509.ExtKeyUsageServerAuth)
	hostUUID := "33333333-3333-3333-3333-333333333333"
	clientCert := ca.issue(t, "spiffe://"+connectorTestTrustDomain+"/host/"+hostUUID, x509.ExtKeyUsageClientAuth)

	realAddr := startConnectorTestServer(t, testcontroller.Config{
		TrustDomain: connectorTestTrustDomain, ServerCertificate: serverCert,
		ClientCABundle: []*x509.Certificate{ca.cert}, HeartbeatIntervalSeconds: 15,
		// A Script that blocks until the stream's context is done (rather
		// than nil/DoNothingScript, both of which return immediately and
		// so close the stream right after HelloAck): this test needs the
		// stream to stay open past limits.ControlConnectAttemptTimeout so
		// it can confirm the deadline was disarmed on success, not just
		// that Connect itself returned.
		Script: func(ctx context.Context, _ testcontroller.ScriptStream, _ string) error {
			<-ctx.Done()
			return nil
		},
	})

	var configCalls int32
	connector := &RealConnector{
		Config: func() controlclient.Config {
			ep := realAddr
			if atomic.AddInt32(&configCalls, 1) == 1 {
				ep = blackHole.Addr().String()
			}
			return controlclient.Config{
				Endpoints: []string{ep}, ControllerSPIFFEID: controllerSPIFFE,
				ControllerCABundle: []*x509.Certificate{ca.cert}, ClientCertificate: clientCert, Clock: time.Now,
			}
		},
		Rand: func() float64 { return 0 },
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), limits.ControlConnectAttemptTimeout*3)
	defer cancel()
	stream, closeFn, err := connector.Connect(ctx, func() controlclient.HelloFields {
		return controlclient.HelloFields{HostUUID: hostUUID, AgentVersion: "test"}
	}, func() {})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Connect: %v (elapsed %v)", err, elapsed)
	}
	defer func() { _ = closeFn() }()
	if stream == nil {
		t.Fatal("Connect returned a nil stream on success")
	}
	if atomic.LoadInt32(&configCalls) < 2 {
		t.Fatalf("Config called %d times, want >= 2 (the black-holed first attempt must have failed and retried)", configCalls)
	}
	if elapsed < limits.ControlConnectAttemptTimeout {
		t.Fatalf("Connect returned after only %v; the first (black-holed) attempt should have taken at least limits.ControlConnectAttemptTimeout (%v)", elapsed, limits.ControlConnectAttemptTimeout)
	}
	if elapsed > limits.ControlConnectAttemptTimeout*3 {
		t.Fatalf("Connect took %v; a stuck attempt should fail and move on well before the test's own overall ctx timeout", elapsed)
	}

	// Confirm the deadline that bounded the first, failed attempt did
	// not leak onto this successful attempt's own, now-live stream: wait
	// past another full limits.ControlConnectAttemptTimeout window and
	// prove the stream is still usable.
	time.Sleep(limits.ControlConnectAttemptTimeout + time.Second)
	if serr := stream.Send(&controlv1.AgentMessage{
		Seq:  2,
		Body: &controlv1.AgentMessage_Heartbeat{Heartbeat: &controlv1.Heartbeat{}},
	}); serr != nil {
		t.Fatalf("stream.Send after the attempt deadline elapsed: %v (the deadline leaked onto the established stream)", serr)
	}
}
