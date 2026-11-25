//go:build testca

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestTestCA_EnrollRoundTrip(t *testing.T) {
	ca, err := NewTestCA(time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	token, err := ca.IssueJoinToken()
	if err != nil {
		t.Fatalf("IssueJoinToken: %v", err)
	}
	enroller := NewTestEnroller(ca, token)

	signer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := Config{
		TrustDomain:           "mgmt.example.internal",
		HostUUID:              "11111111-1111-1111-1111-111111111111",
		EnrollmentTrustBundle: []*x509.Certificate{ca.CACertificate()},
		MaxCertTTL:            2 * time.Hour,
		ClockSkew:             time.Minute,
		StoreDir:              t.TempDir(),
	}
	cm, err := NewCertManager(cfg, signer, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	chain, err := cm.Enroll(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf, CA)", len(chain))
	}
}

func TestTestCA_TokenIsSingleUse(t *testing.T) {
	ca, err := NewTestCA(time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	token, err := ca.IssueJoinToken()
	if err != nil {
		t.Fatalf("IssueJoinToken: %v", err)
	}
	enroller := NewTestEnroller(ca, token)
	signer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := Config{
		TrustDomain: "mgmt.example.internal", HostUUID: "abc",
		EnrollmentTrustBundle: []*x509.Certificate{ca.CACertificate()},
		MaxCertTTL:            time.Hour, ClockSkew: time.Minute, StoreDir: t.TempDir(),
	}
	csr, err := BuildCSR(signer, cfg)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	if _, err := enroller.Enroll(context.Background(), csr); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	if _, err := enroller.Enroll(context.Background(), csr); !errors.Is(err, ErrInvalidJoinToken) {
		t.Fatalf("second Enroll with the same token: err = %v, want ErrInvalidJoinToken", err)
	}
}

func TestNewTestCA_NonPositiveTTLIsError(t *testing.T) {
	if _, err := NewTestCA(0); err == nil {
		t.Fatalf("NewTestCA(0) unexpectedly succeeded")
	}
	if _, err := NewTestCA(-time.Second); err == nil {
		t.Fatalf("NewTestCA(negative) unexpectedly succeeded")
	}
}

func TestTestEnroller_MalformedCSRIsError(t *testing.T) {
	ca, err := NewTestCA(time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	token, err := ca.IssueJoinToken()
	if err != nil {
		t.Fatalf("IssueJoinToken: %v", err)
	}
	enroller := NewTestEnroller(ca, token)
	if _, err := enroller.Enroll(context.Background(), []byte("not a CSR")); err == nil {
		t.Fatalf("Enroll with a malformed CSR unexpectedly succeeded")
	}
}

func TestTestEnroller_TamperedCSRSignatureIsError(t *testing.T) {
	ca, err := NewTestCA(time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	token, err := ca.IssueJoinToken()
	if err != nil {
		t.Fatalf("IssueJoinToken: %v", err)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := Config{
		TrustDomain: "mgmt.example.internal", HostUUID: "abc",
		EnrollmentTrustBundle: []*x509.Certificate{ca.CACertificate()},
		MaxCertTTL:            time.Hour, ClockSkew: time.Minute, StoreDir: t.TempDir(),
	}
	csr, err := BuildCSR(signer, cfg)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	// Flip a byte well inside the DER to invalidate the self-signature
	// without producing unparsable ASN.1 (the signature bytes are near
	// the end of a PKCS#10 CSR's DER encoding).
	tampered := append([]byte(nil), csr...)
	tampered[len(tampered)-5] ^= 0xFF

	enroller := NewTestEnroller(ca, token)
	if _, err := enroller.Enroll(context.Background(), tampered); err == nil {
		t.Fatalf("Enroll with a tampered CSR signature unexpectedly succeeded")
	}
}

func TestTestEnroller_CanceledContextIsError(t *testing.T) {
	ca, err := NewTestCA(time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	token, err := ca.IssueJoinToken()
	if err != nil {
		t.Fatalf("IssueJoinToken: %v", err)
	}
	enroller := NewTestEnroller(ca, token)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := enroller.Enroll(ctx, []byte("irrelevant")); err == nil {
		t.Fatalf("Enroll with a canceled context unexpectedly succeeded")
	}
}

func TestTestCA_UnknownTokenIsError(t *testing.T) {
	ca, err := NewTestCA(time.Hour)
	if err != nil {
		t.Fatalf("NewTestCA: %v", err)
	}
	enroller := NewTestEnroller(ca, "never-issued")
	signer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := Config{
		TrustDomain: "mgmt.example.internal", HostUUID: "abc",
		EnrollmentTrustBundle: []*x509.Certificate{ca.CACertificate()},
		MaxCertTTL:            time.Hour, ClockSkew: time.Minute, StoreDir: t.TempDir(),
	}
	csr, err := BuildCSR(signer, cfg)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	if _, err := enroller.Enroll(context.Background(), csr); !errors.Is(err, ErrInvalidJoinToken) {
		t.Fatalf("err = %v, want ErrInvalidJoinToken", err)
	}
}
