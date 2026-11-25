package controlclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

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
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		// IsCA/KeyUsageCertSign: these self-signed test certs double as
		// their own trust anchor in Dial tests (ControllerCABundle =
		// [serverCert]), and crypto/x509's chain verification requires
		// any cert used as a parent/root to be a CA (ErrNotCA otherwise)
		// even when the leaf and the root are the same certificate.
		IsCA:        true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        uris,
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

func testClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, key := testCertAndKey(t, "")
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

func testConfig(t *testing.T, controllerSPIFFEID string, caBundle []*x509.Certificate) Config {
	t.Helper()
	return Config{
		Endpoints:          []string{"10.0.0.1:8443"},
		ControllerSPIFFEID: controllerSPIFFEID,
		ControllerCABundle: caBundle,
		ClientCertificate:  testClientCert(t),
	}
}

func TestBuildTLSConfig_BasicShape(t *testing.T) {
	ca, _ := testCertAndKey(t, "")
	cfg := testConfig(t, "spiffe://mgmt.example.internal/mgmt/controller", []*x509.Certificate{ca})

	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 || tlsCfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion/MaxVersion = %#x/%#x, want TLS 1.3 only", tlsCfg.MinVersion, tlsCfg.MaxVersion)
	}
	if !tlsCfg.SessionTicketsDisabled {
		t.Fatalf("SessionTicketsDisabled = false, want true")
	}
	if tlsCfg.ClientSessionCache != nil {
		t.Fatalf("ClientSessionCache is non-nil, want nil (no resumption)")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("Certificates length = %d, want 1", len(tlsCfg.Certificates))
	}
	if tlsCfg.VerifyConnection == nil {
		t.Fatalf("VerifyConnection is nil")
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify = false, want true (VerifyConnection performs its own chain + SPIFFE ID verification; see BuildTLSConfig's doc comment)")
	}
	wantGroups := DefaultGroups
	if len(tlsCfg.CurvePreferences) != len(wantGroups) {
		t.Fatalf("CurvePreferences = %v, want %v", tlsCfg.CurvePreferences, wantGroups)
	}
	for i := range wantGroups {
		if tlsCfg.CurvePreferences[i] != wantGroups[i] {
			t.Fatalf("CurvePreferences[%d] = %v, want %v", i, tlsCfg.CurvePreferences[i], wantGroups[i])
		}
	}
}

func TestBuildTLSConfig_CustomGroups(t *testing.T) {
	ca, _ := testCertAndKey(t, "")
	cfg := testConfig(t, "spiffe://mgmt.example.internal/mgmt/controller", []*x509.Certificate{ca})
	cfg.Groups = []tls.CurveID{tls.X25519}

	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if len(tlsCfg.CurvePreferences) != 1 || tlsCfg.CurvePreferences[0] != tls.X25519 {
		t.Fatalf("CurvePreferences = %v, want [X25519]", tlsCfg.CurvePreferences)
	}
}

func TestBuildTLSConfig_InvalidConfigIsError(t *testing.T) {
	if _, err := BuildTLSConfig(Config{}); err == nil {
		t.Fatalf("BuildTLSConfig with an empty config unexpectedly succeeded")
	}
}

func TestVerifyConnection_AcceptsExpectedPeer(t *testing.T) {
	wantSPIFFE := "spiffe://mgmt.example.internal/mgmt/controller"
	// Self-signed: the presented certificate is also the trust anchor
	// (same pattern TestDial_Success uses), so the chain actually
	// verifies against cfg.ControllerCABundle.
	serverCert, _ := testCertAndKey(t, wantSPIFFE)
	cfg := testConfig(t, wantSPIFFE, []*x509.Certificate{serverCert})
	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	cs := tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_256_GCM_SHA384,
		PeerCertificates: []*x509.Certificate{serverCert},
	}
	if err := tlsCfg.VerifyConnection(cs); err != nil {
		t.Fatalf("VerifyConnection rejected a valid peer: %v", err)
	}
}

func TestVerifyConnection_Rejections(t *testing.T) {
	ca, _ := testCertAndKey(t, "")
	wantSPIFFE := "spiffe://mgmt.example.internal/mgmt/controller"
	cfg := testConfig(t, wantSPIFFE, []*x509.Certificate{ca})
	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	validServerCert, _ := testCertAndKey(t, wantSPIFFE)
	wrongServerCert, _ := testCertAndKey(t, "spiffe://mgmt.example.internal/mgmt/collector")
	noSANServerCert, _ := testCertAndKey(t, "")

	tests := []struct {
		name string
		cs   tls.ConnectionState
	}{
		{"wrong cipher suite", tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_CHACHA20_POLY1305_SHA256, PeerCertificates: []*x509.Certificate{validServerCert}}},
		{"wrong TLS version", tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: tls.TLS_AES_256_GCM_SHA384, PeerCertificates: []*x509.Certificate{validServerCert}}},
		{"no peer certificates", tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_256_GCM_SHA384}},
		{"wrong SPIFFE ID", tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_256_GCM_SHA384, PeerCertificates: []*x509.Certificate{wrongServerCert}}},
		{"no URI SAN at all", tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_256_GCM_SHA384, PeerCertificates: []*x509.Certificate{noSANServerCert}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tlsCfg.VerifyConnection(tc.cs); err == nil {
				t.Fatalf("VerifyConnection accepted a connection that should have been rejected")
			}
		})
	}
}
