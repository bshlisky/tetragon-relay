package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

type funcEnroller func(ctx context.Context, csr []byte) ([]*x509.Certificate, error)

func (f funcEnroller) Enroll(ctx context.Context, csr []byte) ([]*x509.Certificate, error) {
	return f(ctx, csr)
}

func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate (CA): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate (CA): %v", err)
	}
	return cert, key
}

type leafOpts struct {
	pub         *ecdsa.PublicKey
	uris        []*url.URL
	dnsNames    []string
	eku         []x509.ExtKeyUsage
	notBefore   time.Time
	notAfter    time.Time
	issuerCert  *x509.Certificate
	issuerKey   *ecdsa.PrivateKey
	serialBytes int64
}

func issueLeaf(t *testing.T, o leafOpts) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(o.serialBytes + 2),
		Subject:      pkix.Name{CommonName: "host"},
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  o.eku,
		URIs:         o.uris,
		DNSNames:     o.dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, o.issuerCert, o.pub, o.issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate (leaf): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate (leaf): %v", err)
	}
	return cert
}

func baseCfg(t *testing.T, ca *x509.Certificate) Config {
	t.Helper()
	return Config{
		TrustDomain:           "mgmt.example.internal",
		HostUUID:              "11111111-1111-1111-1111-111111111111",
		EnrollmentTrustBundle: []*x509.Certificate{ca},
		MaxCertTTL:            4 * time.Hour,
		ClockSkew:             time.Minute,
		StoreDir:              t.TempDir(),
	}
}

func spiffeURI(t *testing.T, cfg Config) *url.URL {
	t.Helper()
	u, err := url.Parse(cfg.HostSPIFFEID())
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	return u
}

func TestCertManager_Enroll_Success(t *testing.T) {
	ca, caKey := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	now := time.Now()

	enroller := funcEnroller(func(_ context.Context, csrDER []byte) ([]*x509.Certificate, error) {
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, err
		}
		leaf := issueLeaf(t, leafOpts{
			pub: csr.PublicKey.(*ecdsa.PublicKey), uris: csr.URIs,
			eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour),
			issuerCert: ca, issuerKey: caKey,
		})
		return []*x509.Certificate{leaf, ca}, nil
	})

	cm, err := NewCertManager(cfg, signer, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	chain, err := cm.Enroll(context.Background(), now)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
	if cm.Chain() == nil {
		t.Fatalf("Chain() is nil after successful Enroll")
	}

	// Persisted chain round-trips.
	loaded, err := LoadChain(cfg.StoreDir)
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(loaded) != 2 || !loaded[0].Equal(chain[0]) {
		t.Fatalf("LoadChain did not round-trip the enrolled chain")
	}
}

func TestCertManager_Enroll_Rejections(t *testing.T) {
	ca, caKey := newTestCA(t)
	otherCA, otherCAKey := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	otherKey := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	now := time.Now()

	validURI := spiffeURI(t, cfg)
	wrongURI, err := url.Parse("spiffe://mgmt.example.internal/host/other-uuid")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		leaf    func() *x509.Certificate
		wantErr error
	}{
		{"wrong key", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &otherKey.PublicKey, uris: []*url.URL{validURI}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour), issuerCert: ca, issuerKey: caKey, serialBytes: 1})
		}, ErrLeafKeyMismatch},
		{"wrong URI SAN", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &signer.PublicKey, uris: []*url.URL{wrongURI}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour), issuerCert: ca, issuerKey: caKey, serialBytes: 2})
		}, ErrURISANMismatch},
		{"missing URI SAN", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &signer.PublicKey, uris: nil, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour), issuerCert: ca, issuerKey: caKey, serialBytes: 3})
		}, ErrURISANMismatch},
		{"extra DNS SAN", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &signer.PublicKey, uris: []*url.URL{validURI}, dnsNames: []string{"evil.example.com"}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour), issuerCert: ca, issuerKey: caKey, serialBytes: 4})
		}, ErrURISANMismatch},
		{"wrong EKU", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &signer.PublicKey, uris: []*url.URL{validURI}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour), issuerCert: ca, issuerKey: caKey, serialBytes: 5})
		}, ErrMissingClientAuthEKU},
		{"expired", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &signer.PublicKey, uris: []*url.URL{validURI}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour), issuerCert: ca, issuerKey: caKey, serialBytes: 6})
		}, ErrExpired},
		{"not yet valid", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &signer.PublicKey, uris: []*url.URL{validURI}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour), issuerCert: ca, issuerKey: caKey, serialBytes: 7})
		}, ErrNotYetValid},
		{"TTL too long", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &signer.PublicKey, uris: []*url.URL{validURI}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notBefore: now.Add(-time.Minute), notAfter: now.Add(24 * time.Hour), issuerCert: ca, issuerKey: caKey, serialBytes: 8})
		}, ErrTTLTooLong},
		{"unknown issuer", func() *x509.Certificate {
			return issueLeaf(t, leafOpts{pub: &signer.PublicKey, uris: []*url.URL{validURI}, eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour), issuerCert: otherCA, issuerKey: otherCAKey, serialBytes: 9})
		}, ErrChainVerificationFailed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := tc.leaf()
			chainResp := []*x509.Certificate{leaf, ca}
			if tc.name == "unknown issuer" {
				chainResp = []*x509.Certificate{leaf, otherCA}
			}
			enroller := funcEnroller(func(_ context.Context, _ []byte) ([]*x509.Certificate, error) {
				return chainResp, nil
			})
			cm, err := NewCertManager(cfg, signer, enroller)
			if err != nil {
				t.Fatalf("NewCertManager: %v", err)
			}
			_, err = cm.Enroll(context.Background(), now)
			if err == nil {
				t.Fatalf("Enroll unexpectedly succeeded")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want wrapping %v", err, tc.wantErr)
			}
			if cm.Chain() != nil {
				t.Fatalf("Chain() is non-nil after a rejected Enroll")
			}
		})
	}
}

func TestCertManager_Enroll_EmptyChainRejected(t *testing.T) {
	ca, _ := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	enroller := funcEnroller(func(context.Context, []byte) ([]*x509.Certificate, error) { return nil, nil })
	cm, err := NewCertManager(cfg, signer, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if _, err := cm.Enroll(context.Background(), time.Now()); !errors.Is(err, ErrEmptyChain) {
		t.Fatalf("err = %v, want ErrEmptyChain", err)
	}
}

func TestCertManager_Rotate_Success(t *testing.T) {
	ca, caKey := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	newSigner := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	now := time.Now()

	issue := func(csrDER []byte) ([]*x509.Certificate, error) {
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, err
		}
		leaf := issueLeaf(t, leafOpts{
			pub: csr.PublicKey.(*ecdsa.PublicKey), uris: csr.URIs,
			eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour),
			issuerCert: ca, issuerKey: caKey,
		})
		return []*x509.Certificate{leaf, ca}, nil
	}
	enroller := funcEnroller(func(_ context.Context, csrDER []byte) ([]*x509.Certificate, error) { return issue(csrDER) })

	cm, err := NewCertManager(cfg, signer, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	originalChain, err := cm.Enroll(context.Background(), now)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	rotatedChain, err := cm.Rotate(context.Background(), now, newSigner)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotatedChain[0].Equal(originalChain[0]) {
		t.Fatalf("Rotate produced the same leaf certificate as before rotation")
	}
	gotPub, ok := cm.Chain()[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !gotPub.Equal(&newSigner.PublicKey) {
		t.Fatalf("active chain's leaf public key does not match the new signer after Rotate")
	}
}

func TestRenewAtAndShouldRenew(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(4 * time.Hour)
	leaf := &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}

	wantRenewAt := notBefore.Add(2 * time.Hour)
	if got := RenewAt(leaf); !got.Equal(wantRenewAt) {
		t.Fatalf("RenewAt = %v, want %v", got, wantRenewAt)
	}
	if ShouldRenew(leaf, wantRenewAt.Add(-time.Second)) {
		t.Fatalf("ShouldRenew = true before the renewal point")
	}
	if !ShouldRenew(leaf, wantRenewAt) {
		t.Fatalf("ShouldRenew = false exactly at the renewal point")
	}
	if !ShouldRenew(leaf, wantRenewAt.Add(time.Second)) {
		t.Fatalf("ShouldRenew = false after the renewal point")
	}
}

func TestExpiringSoon(t *testing.T) {
	notAfter := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotAfter: notAfter}

	if ExpiringSoon(leaf, notAfter.Add(-20*time.Minute)) {
		t.Fatalf("ExpiringSoon = true with 20 minutes left")
	}
	if !ExpiringSoon(leaf, notAfter.Add(-10*time.Minute)) {
		t.Fatalf("ExpiringSoon = false with 10 minutes left")
	}
}
