package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		TrustDomain:           "mgmt.example.internal",
		HostUUID:              "11111111-1111-1111-1111-111111111111",
		EnrollmentTrustBundle: []*x509.Certificate{{}}, // non-empty for Validate(); BuildCSR doesn't use it
		MaxCertTTL:            time.Hour,
		ClockSkew:             time.Minute,
		StoreDir:              t.TempDir(),
	}
}

func genKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestBuildCSR_ContentsP384(t *testing.T) {
	cfg := testConfig(t)
	key := genKey(t, elliptic.P384())

	der, err := BuildCSR(key, cfg)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Fatalf("SignatureAlgorithm = %v, want ECDSAWithSHA384", csr.SignatureAlgorithm)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != cfg.HostSPIFFEID() {
		t.Fatalf("URIs = %v, want [%s]", csr.URIs, cfg.HostSPIFFEID())
	}
	if len(csr.DNSNames) != 0 {
		t.Fatalf("DNSNames = %v, want none", csr.DNSNames)
	}
	gotPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !gotPub.Equal(&key.PublicKey) {
		t.Fatalf("CSR public key does not match the signing key")
	}
}

func TestBuildCSR_P256UsesSHA256(t *testing.T) {
	cfg := testConfig(t)
	key := genKey(t, elliptic.P256())

	der, err := BuildCSR(key, cfg)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("SignatureAlgorithm = %v, want ECDSAWithSHA256", csr.SignatureAlgorithm)
	}
}

func TestBuildCSR_UnsupportedCurveIsError(t *testing.T) {
	cfg := testConfig(t)
	key := genKey(t, elliptic.P224())
	if _, err := BuildCSR(key, cfg); err == nil {
		t.Fatalf("BuildCSR with an unsupported curve unexpectedly succeeded")
	}
}

func TestBuildCSR_InvalidConfigIsError(t *testing.T) {
	cfg := testConfig(t)
	cfg.HostUUID = ""
	key := genKey(t, elliptic.P384())
	if _, err := BuildCSR(key, cfg); err == nil {
		t.Fatalf("BuildCSR with an invalid config unexpectedly succeeded")
	}
}
