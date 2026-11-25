package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

type fakeChainHolder struct {
	chain []*x509.Certificate
}

func (f *fakeChainHolder) Chain() []*x509.Certificate { return f.chain }

func testLeafCert(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestRealIdentityRotator_ExpiringSoon_NoChain(t *testing.T) {
	r := &RealIdentityRotator{CertManager: &fakeChainHolder{}}
	if r.ExpiringSoon(time.Now()) {
		t.Fatalf("ExpiringSoon with no chain = true, want false")
	}
}

func TestRealIdentityRotator_ExpiringSoon_WithChain(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"expires in 5 minutes", now.Add(5 * time.Minute), true},
		{"expires in 1 hour", now.Add(time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := testLeafCert(t, now.Add(-time.Hour), tc.notAfter)
			r := &RealIdentityRotator{CertManager: &fakeChainHolder{chain: []*x509.Certificate{leaf}}}
			if got := r.ExpiringSoon(now); got != tc.want {
				t.Fatalf("ExpiringSoon = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRealIdentityRotator_Rotate_NotImplemented(t *testing.T) {
	r := &RealIdentityRotator{CertManager: &fakeChainHolder{}}
	err := r.Rotate(context.Background())
	if err == nil {
		t.Fatalf("expected an error")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error type: %v", err)
	}
}
