//go:build testca

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// TestCA is a small in-process certificate authority for unit and
// integration tests (docs/prompts/step-05b.md B3), built with tag
// "testca" so it is never compiled into a production build (matching
// cmd/bundlesign-test's "testtools" tag precedent). It certifies whatever
// key a CSR proves possession of -- it never generates or sees a private
// key itself, same as any real Enroller must (docs/decisions/0030).
//
// This file calls time.Now() directly (CA certificate and leaf validity
// windows): the project's "no time.Now() in internal/" rule governs
// production logic that must be deterministic and testable
// (internal/identity's own CertManager, certmanager.go, takes every
// decision time as an explicit parameter); this file is test-only
// tooling, gated behind the "testca" build tag and never reachable from a
// production build, the same category internal/tpm's swtpm_test.go and
// internal/agent's tpmwiring_internal_test.go are already in.
type TestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	ttl  time.Duration

	mu     sync.Mutex
	tokens map[string]bool // token -> still valid (true) / consumed (false, then deleted)
}

// NewTestCA generates a fresh self-signed ECDSA P-384 CA certificate and
// returns a TestCA that issues leaf certificates valid for ttl.
func NewTestCA(ttl time.Duration) (*TestCA, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("identity: testca: ttl must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: testca: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tetragon-relay test enrollment CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("identity: testca: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("identity: testca: parse CA certificate: %w", err)
	}
	return &TestCA{cert: cert, key: key, ttl: ttl, tokens: map[string]bool{}}, nil
}

// CACertificate returns the test CA's own certificate, to be placed in
// Config.EnrollmentTrustBundle.
func (ca *TestCA) CACertificate() *x509.Certificate { return ca.cert }

// IssueJoinToken generates a fresh, single-use join token (architecture
// doc 5.2 step 1: "a one-time join token... for hosts without EK
// certificates").
func (ca *TestCA) IssueJoinToken() (string, error) {
	tok, err := randomToken()
	if err != nil {
		return "", err
	}
	ca.mu.Lock()
	ca.tokens[tok] = true
	ca.mu.Unlock()
	return tok, nil
}

var (
	// ErrInvalidJoinToken is returned by TestEnroller.Enroll when the
	// configured token was never issued, or was already consumed by an
	// earlier Enroll call -- it is single-use by design.
	ErrInvalidJoinToken = errors.New("identity: testca: invalid or already-used join token")
	// ErrCSRSignatureInvalid is returned when the CSR's self-signature
	// does not verify: TestCA never certifies a key it cannot prove the
	// caller possesses.
	ErrCSRSignatureInvalid = errors.New("identity: testca: CSR signature does not verify")
)

func (ca *TestCA) consumeToken(token string) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if !ca.tokens[token] {
		return ErrInvalidJoinToken
	}
	delete(ca.tokens, token)
	return nil
}

// testEnroller is the Enroller implementation TestCA hands out, bound to
// one specific one-time join token.
type testEnroller struct {
	ca    *TestCA
	token string
}

// NewTestEnroller returns an Enroller that certifies CSRs against ca,
// authorized by the given one-time join token (architecture doc 5.2 step
// 1). The token is consumed on the first successful Enroll call; a second
// call with the same token fails with ErrInvalidJoinToken.
func NewTestEnroller(ca *TestCA, token string) Enroller {
	return &testEnroller{ca: ca, token: token}
}

func (e *testEnroller) Enroll(ctx context.Context, csrDER []byte) ([]*x509.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := e.ca.consumeToken(e.token); err != nil {
		return nil, err
	}
	now := time.Now()
	return e.ca.issue(csrDER, now.Add(-time.Minute), now.Add(e.ca.ttl), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

// IssueWithValidity is a test-only escape hatch (consumes no join token)
// for tests that need a client (EKU clientAuth) leaf certificate with a
// specific, possibly invalid, validity window -- e.g. an already-expired
// certificate, to prove a SERVER's own TLS-level expiry check refuses it
// (docs/prompts/step-05b.md E3's "an expired client certificate" negative
// case). Production code and NewTestEnroller's normal Enroll path never
// call this; it exists only so integration tests can construct a
// deliberately invalid certificate without needing access to the CA's
// private key.
func (ca *TestCA) IssueWithValidity(csrDER []byte, notBefore, notAfter time.Time) ([]*x509.Certificate, error) {
	return ca.issue(csrDER, notBefore, notAfter, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

// IssueServerCertificate is a test-only helper (consumes no join token)
// for issuing a SERVER (EKU serverAuth) certificate from this same test
// CA -- used by integration tests to stand up a reference controller
// (internal/testcontroller) whose certificate this CA's
// EnrollmentTrustBundle can also verify, without needing a second,
// separate test CA. Architecture doc section 5 keeps the identity PKI and
// policy trust root as separate trust domains in production; using one
// CA for both agent and controller certificates here is a test-only
// simplification, not a production pattern.
func (ca *TestCA) IssueServerCertificate(csrDER []byte, notBefore, notAfter time.Time) ([]*x509.Certificate, error) {
	return ca.issue(csrDER, notBefore, notAfter, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func (ca *TestCA) issue(csrDER []byte, notBefore, notAfter time.Time, ekus []x509.ExtKeyUsage) ([]*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("identity: testca: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCSRSignatureInvalid, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
		URIs:         csr.URIs,
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("identity: testca: create leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("identity: testca: parse leaf certificate: %w", err)
	}
	return []*x509.Certificate{leaf, ca.cert}, nil
}

func randomSerial() (*big.Int, error) {
	maxVal := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, maxVal)
	if err != nil {
		return nil, fmt.Errorf("identity: testca: generate serial: %w", err)
	}
	return serial, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("identity: testca: generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
