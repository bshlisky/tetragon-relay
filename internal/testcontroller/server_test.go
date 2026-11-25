package testcontroller

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
