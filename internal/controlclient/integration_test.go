//go:build testca

package controlclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/identity"
	"github.com/bshlisky/tetragon-relay/internal/testcontroller"
	"github.com/bshlisky/tetragon-relay/internal/tpm"
	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
	"google.golang.org/grpc"
)

// This file is docs/prompts/step-05b.md E3: enroll via the test CA with a
// TPM-held key (real swtpm, not a mock -- the same real-TPM testing
// discipline internal/tpm's own suite uses), connect to the test
// controller (internal/testcontroller, the same server cmd/testcontroller
// wraps), and complete Hello/HelloAck -- plus the four required negative
// cases. Requires swtpm on PATH; skipped (not failed) otherwise, matching
// internal/tpm's own convention.

const trustDomain = "mgmt.example.internal"

func startSWTPMForIntegrationTest(t *testing.T) transport.TPM {
	t.Helper()
	swtpmPath, err := exec.LookPath("swtpm")
	if err != nil {
		t.Skip("swtpm not found on PATH; skipping step-05b E3 integration test")
	}
	stateDir := t.TempDir()
	cmdPort := mustFreePort(t)
	ctrlPort := mustFreePort(t)
	cmd := exec.Command(swtpmPath, "socket",
		"--tpmstate", "dir="+stateDir,
		"--ctrl", "type=tcp,port="+strconv.Itoa(ctrlPort),
		"--server", "type=tcp,port="+strconv.Itoa(cmdPort),
		"--tpm2", "--flags", "not-need-init",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	cmdAddr := "localhost:" + strconv.Itoa(cmdPort)
	ctrlAddr := "localhost:" + strconv.Itoa(ctrlPort)
	var tt *tcp.TPM
	deadline := time.Now().Add(10 * time.Second)
	for {
		tt, err = tcp.Open(tcp.Config{CommandAddress: cmdAddr, PlatformAddress: ctrlAddr})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect to swtpm: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Cleanup(func() { _ = tt.Close() })
	_ = tt.PowerOn()
	su := tpm2.Startup{StartupType: tpm2.TPMSUClear}
	if _, err := su.Execute(tt); err != nil {
		t.Fatalf("TPM2_Startup: %v", err)
	}
	return tt
}

func mustFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// issueControllerCert issues the test controller's own server certificate
// from ca (reusing the same test CA as the agent's enrollment trust
// bundle is a test-only simplification; architecture doc section 5 keeps
// these as separate trust domains in production).
func issueControllerCert(t *testing.T, ca *identity.TestCA, spiffeID string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "controller"}, URIs: []*url.URL{u}, SignatureAlgorithm: x509.ECDSAWithSHA384}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	// Server (EKU serverAuth), not Enroll's client-only path: see
	// TestCA.IssueServerCertificate's doc comment.
	chain, err := ca.IssueServerCertificate(csrDER, time.Now().Add(-time.Minute), time.Now().Add(4*time.Hour))
	if err != nil {
		t.Fatalf("issue controller cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{chain[0].Raw}, PrivateKey: key, Leaf: chain[0]}
}

// enrollAgent builds a TPM-backed identity for hostUUID via ca and returns
// the resulting tls.Certificate (chain + TPM signer).
func enrollAgent(t *testing.T, tp transport.TPM, ca *identity.TestCA, hostUUID string) tls.Certificate {
	t.Helper()
	if _, err := tpm.ProvisionSRK(tp, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	signer, err := tpm.NewOrLoadHostSigner(tp, t.TempDir()+"/host-signer.json")
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner: %v", err)
	}
	token, err := ca.IssueJoinToken()
	if err != nil {
		t.Fatalf("IssueJoinToken: %v", err)
	}
	cfg := identity.Config{
		TrustDomain: trustDomain, HostUUID: hostUUID,
		EnrollmentTrustBundle: []*x509.Certificate{ca.CACertificate()},
		MaxCertTTL:            4 * time.Hour, ClockSkew: time.Minute, StoreDir: t.TempDir(),
	}
	cm, err := identity.NewCertManager(cfg, signer, identity.NewTestEnroller(ca, token))
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	chain, err := cm.Enroll(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	der := make([][]byte, len(chain))
	for i, c := range chain {
		der[i] = c.Raw
	}
	return tls.Certificate{Certificate: der, PrivateKey: signer, Leaf: chain[0]}
}

// startTestController starts internal/testcontroller (the same server
// cmd/testcontroller wraps) over a real TCP listener and returns its
// address.
func startTestController(t *testing.T, cfg testcontroller.Config) string {
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

func TestIntegration_EnrollConnectHelloAck(t *testing.T) {
	tp := startSWTPMForIntegrationTest(t)
	ca, err := identity.NewTestCA(4 * time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	controllerSPIFFE := "spiffe://" + trustDomain + "/mgmt/controller"
	controllerCert := issueControllerCert(t, ca, controllerSPIFFE)
	agentCert := enrollAgent(t, tp, ca, "11111111-1111-1111-1111-111111111111")

	addr := startTestController(t, testcontroller.Config{
		TrustDomain: trustDomain, ServerCertificate: controllerCert,
		ClientCABundle: []*x509.Certificate{ca.CACertificate()}, HeartbeatIntervalSeconds: 15,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := controlclient.Dial(ctx, controlclient.Config{
		Endpoints: []string{addr}, ControllerSPIFFEID: controllerSPIFFE,
		ControllerCABundle: []*x509.Certificate{ca.CACertificate()}, ClientCertificate: agentCert,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	stream, err := controlclient.AgentControlClient(conn).Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	ack, err := controlclient.SendHello(stream, 1, controlclient.HelloFields{
		HostUUID: "11111111-1111-1111-1111-111111111111", AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	if ack.GetHeartbeatIntervalSeconds() != 15 {
		t.Fatalf("HeartbeatIntervalSeconds = %d, want 15", ack.GetHeartbeatIntervalSeconds())
	}
	t.Logf("E3 PASS: enrolled via test CA with a TPM-held key, connected, completed Hello/HelloAck")
}

func TestIntegration_ServerWrongSPIFFEID_ClientRefuses(t *testing.T) {
	tp := startSWTPMForIntegrationTest(t)
	ca, err := identity.NewTestCA(4 * time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	actualControllerSPIFFE := "spiffe://" + trustDomain + "/mgmt/controller"
	controllerCert := issueControllerCert(t, ca, actualControllerSPIFFE)
	agentCert := enrollAgent(t, tp, ca, "22222222-2222-2222-2222-222222222222")
	addr := startTestController(t, testcontroller.Config{
		TrustDomain: trustDomain, ServerCertificate: controllerCert,
		ClientCABundle: []*x509.Certificate{ca.CACertificate()},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	wrongSPIFFE := "spiffe://" + trustDomain + "/mgmt/collector" // NOT what the server actually presents
	_, err = controlclient.Dial(ctx, controlclient.Config{
		Endpoints: []string{addr}, ControllerSPIFFEID: wrongSPIFFE,
		ControllerCABundle: []*x509.Certificate{ca.CACertificate()}, ClientCertificate: agentCert,
	})
	if err == nil {
		t.Fatalf("Dial unexpectedly succeeded despite the server presenting a different SPIFFE ID")
	}
	t.Logf("observed error: %v", err)
}

func TestIntegration_ClientCertForOtherHostUUID_ServerRefuses(t *testing.T) {
	tp := startSWTPMForIntegrationTest(t)
	ca, err := identity.NewTestCA(4 * time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	controllerSPIFFE := "spiffe://" + trustDomain + "/mgmt/controller"
	controllerCert := issueControllerCert(t, ca, controllerSPIFFE)
	// The agent's certificate is valid and chains correctly, but for a
	// host UUID the server's inventory does not recognize.
	agentCert := enrollAgent(t, tp, ca, "33333333-3333-3333-3333-333333333333")
	addr := startTestController(t, testcontroller.Config{
		TrustDomain: trustDomain, ServerCertificate: controllerCert,
		ClientCABundle: []*x509.Certificate{ca.CACertificate()},
		Inventory:      map[string]bool{"99999999-9999-9999-9999-999999999999": true}, // does not include the agent's UUID
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := controlclient.Dial(ctx, controlclient.Config{
		Endpoints: []string{addr}, ControllerSPIFFEID: controllerSPIFFE,
		ControllerCABundle: []*x509.Certificate{ca.CACertificate()}, ClientCertificate: agentCert,
	})
	if err != nil {
		t.Fatalf("Dial: %v (TLS layer should still succeed; the server refuses at the application layer)", err)
	}
	defer func() { _ = conn.Close() }()
	stream, err := controlclient.AgentControlClient(conn).Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_, err = controlclient.SendHello(stream, 1, controlclient.HelloFields{HostUUID: "33333333-3333-3333-3333-333333333333"})
	if err == nil {
		t.Fatalf("SendHello unexpectedly succeeded despite the host UUID not being in the server's inventory")
	}
	t.Logf("observed error: %v", err)
}

func TestIntegration_ServerTLS12Refused(t *testing.T) {
	tp := startSWTPMForIntegrationTest(t)
	ca, err := identity.NewTestCA(4 * time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	controllerSPIFFE := "spiffe://" + trustDomain + "/mgmt/controller"
	controllerCert := issueControllerCert(t, ca, controllerSPIFFE)
	agentCert := enrollAgent(t, tp, ca, "44444444-4444-4444-4444-444444444444")

	// A raw TLS 1.2-only listener standing in for a misconfigured/legacy
	// controller: the client's TLS 1.3-only config must refuse it.
	pool := x509.NewCertPool()
	pool.AddCert(ca.CACertificate())
	tls12Cfg := &tls.Config{
		Certificates: []tls.Certificate{controllerCert},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", tls12Cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = lis.Close() }()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = controlclient.Dial(ctx, controlclient.Config{
		Endpoints: []string{lis.Addr().String()}, ControllerSPIFFEID: controllerSPIFFE,
		ControllerCABundle: []*x509.Certificate{ca.CACertificate()}, ClientCertificate: agentCert,
	})
	if err == nil {
		t.Fatalf("Dial unexpectedly succeeded against a TLS 1.2-only server")
	}
	t.Logf("observed error: %v", err)
}

func TestIntegration_ExpiredClientCertificateRefused(t *testing.T) {
	ca, err := identity.NewTestCA(4 * time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	controllerSPIFFE := "spiffe://" + trustDomain + "/mgmt/controller"
	controllerCert := issueControllerCert(t, ca, controllerSPIFFE)

	// Build an expired client certificate directly (not through
	// CertManager, which would itself reject it -- this test exercises
	// the SERVER's own TLS-level expiry check, which an already-expired
	// certificate must fail regardless of client-side validation).
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	u, err := url.Parse("spiffe://" + trustDomain + "/host/55555555-5555-5555-5555-555555555555")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "expired-host"}, URIs: []*url.URL{u}, SignatureAlgorithm: x509.ECDSAWithSHA384}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	expiredChain, err := ca.IssueWithValidity(csrDER, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("IssueWithValidity: %v", err)
	}
	expiredClientCert := tls.Certificate{Certificate: [][]byte{expiredChain[0].Raw, ca.CACertificate().Raw}, PrivateKey: key, Leaf: expiredChain[0]}

	addr := startTestController(t, testcontroller.Config{
		TrustDomain: trustDomain, ServerCertificate: controllerCert,
		ClientCABundle: []*x509.Certificate{ca.CACertificate()},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = controlclient.Dial(ctx, controlclient.Config{
		Endpoints: []string{addr}, ControllerSPIFFEID: controllerSPIFFE,
		ControllerCABundle: []*x509.Certificate{ca.CACertificate()}, ClientCertificate: expiredClientCert,
	})
	if err == nil {
		t.Fatalf("Dial unexpectedly succeeded with an expired client certificate")
	}
	t.Logf("observed error: %v", err)
}
