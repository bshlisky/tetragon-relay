package spiffetls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

func mkCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, uris ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "x"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
		tmpl.ExtKeyUsage = nil
	}
	for _, u := range uris {
		pu, _ := url.Parse(u)
		tmpl.URIs = append(tmpl.URIs, pu)
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func TestVerifyConnection(t *testing.T) {
	const id = "spiffe://td/mgmt/collector"
	ca, caKey := mkCert(t, nil, nil, true)
	other, _ := mkCert(t, nil, nil, true)
	leaf, _ := mkCert(t, ca, caKey, false, id)
	wrongID, _ := mkCert(t, ca, caKey, false, "spiffe://td/mgmt/controller")
	twoIDs, _ := mkCert(t, ca, caKey, false, id, "spiffe://td/x")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	ok := tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_256_GCM_SHA384, PeerCertificates: []*x509.Certificate{leaf}}
	if err := VerifyConnection(ok, roots, id, now); err != nil {
		t.Fatalf("valid: %v", err)
	}
	cases := map[string]tls.ConnectionState{
		"chacha":   {Version: tls.VersionTLS13, CipherSuite: tls.TLS_CHACHA20_POLY1305_SHA256, PeerCertificates: ok.PeerCertificates},
		"tls12":    {Version: tls.VersionTLS12, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: ok.PeerCertificates},
		"no certs": {Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256},
		"wrong id": {Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{wrongID}},
		"two ids":  {Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{twoIDs}},
		"other ca": {Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{other}},
	}
	for name, cs := range cases {
		if err := VerifyConnection(cs, roots, id, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := VerifyConnection(cases["wrong id"], roots, id, now); !errors.Is(err, ErrServerSPIFFEIDMismatch) {
		t.Fatalf("wrong id: %v", err)
	}
	if err := VerifyConnection(ok, roots, id, now.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("expired at the injected clock: %v", err)
	}
}

func TestClientTLSConfig(t *testing.T) {
	ca, caKey := mkCert(t, nil, nil, true)
	leaf, _ := mkCert(t, ca, caKey, false, "spiffe://td/mgmt/collector")
	good := ClientConfig{
		ServerSPIFFEID: "spiffe://td/mgmt/collector", ServerCABundle: []*x509.Certificate{ca},
		ClientCertificate: tls.Certificate{Certificate: [][]byte{leaf.Raw}}, Groups: []tls.CurveID{tls.CurveP384},
		Clock: func() time.Time { return now },
	}
	cfg, err := ClientTLSConfig(good)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 || !cfg.SessionTicketsDisabled || cfg.ClientSessionCache != nil {
		t.Fatalf("config = %+v", cfg)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Fatalf("VerifyConnection: %v", err)
	}
	for name, mut := range map[string]func(*ClientConfig){
		"id":     func(c *ClientConfig) { c.ServerSPIFFEID = "" },
		"ca":     func(c *ClientConfig) { c.ServerCABundle = nil },
		"cert":   func(c *ClientConfig) { c.ClientCertificate = tls.Certificate{} },
		"groups": func(c *ClientConfig) { c.Groups = nil },
		"clock":  func(c *ClientConfig) { c.Clock = nil },
	} {
		c := good
		mut(&c)
		if _, err := ClientTLSConfig(c); err == nil {
			t.Errorf("missing %s accepted", name)
		}
	}
}
