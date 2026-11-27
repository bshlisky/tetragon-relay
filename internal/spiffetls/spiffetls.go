// Package spiffetls is ADR 0031's client-side mTLS verification, shared by
// the control channel (internal/controlclient) and the telemetry channel
// (internal/telemetry): TLS 1.3 only, AES-GCM suites only (checked after
// the handshake), full chain verification against a CA bundle, and an
// exact SPIFFE URI SAN pin on the server certificate. It lives in its own
// leaf package so internal/telemetry can use it without importing
// internal/controlclient (ADR 0039 section 8).
package spiffetls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ErrServerSPIFFEIDMismatch is returned (wrapped) by VerifyConnection
// when the server certificate's URI SAN is not exactly the pinned SPIFFE
// ID (architecture doc 6.1: "SPIFFE ID pinning, not hostname").
var ErrServerSPIFFEIDMismatch = errors.New("spiffetls: server certificate's SPIFFE ID does not match the pinned SPIFFE ID")

// allowedCipherSuites is architecture doc 6.1's list. Go's crypto/tls does
// not let a client restrict which TLS 1.3 suites are offered
// (crypto/tls.Config: "TLS 1.3 ciphersuites are not configurable"), so
// this is enforced after the handshake (docs/reports/step-05b.md section 6).
var allowedCipherSuites = map[uint16]bool{
	tls.TLS_AES_256_GCM_SHA384: true,
	tls.TLS_AES_128_GCM_SHA256: true,
}

// ClientConfig is ClientTLSConfig's input. Every field is required.
type ClientConfig struct {
	// ServerSPIFFEID is the exact URI SAN the server must present.
	ServerSPIFFEID string
	// ServerCABundle is the set of roots the server chain must verify to.
	ServerCABundle []*x509.Certificate
	// ClientCertificate is the agent's enrolled chain with its TPM-backed
	// signer.
	ClientCertificate tls.Certificate
	// Groups is the key-exchange group preference list.
	Groups []tls.CurveID
	// Clock is the verification time (step-05b-review.md R5B-1).
	Clock func() time.Time
}

// ClientTLSConfig returns the client *tls.Config of ADR 0031. Server
// authentication is done entirely in VerifyConnection; InsecureSkipVerify
// only disables Go's hostname check, which can never pass against
// certificates with no DNS or IP SANs (architecture doc 5.1) and which
// grpc-go would otherwise re-enable by filling ServerName from the dial
// target. No session tickets are stored or presented; Go's client has no
// 0-RTT.
func ClientTLSConfig(c ClientConfig) (*tls.Config, error) {
	switch {
	case c.ServerSPIFFEID == "":
		return nil, fmt.Errorf("spiffetls: ServerSPIFFEID is required")
	case len(c.ServerCABundle) == 0:
		return nil, fmt.Errorf("spiffetls: ServerCABundle is required")
	case len(c.ClientCertificate.Certificate) == 0:
		return nil, fmt.Errorf("spiffetls: ClientCertificate is required")
	case len(c.Groups) == 0:
		return nil, fmt.Errorf("spiffetls: Groups is required")
	case c.Clock == nil:
		return nil, fmt.Errorf("spiffetls: Clock is required")
	}
	rootPool := x509.NewCertPool()
	for _, cert := range c.ServerCABundle {
		rootPool.AddCert(cert)
	}
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       append([]tls.CurveID(nil), c.Groups...),
		Certificates:           []tls.Certificate{c.ClientCertificate},
		RootCAs:                rootPool,
		InsecureSkipVerify:     true, //nolint:gosec // G402: VerifyConnection performs full chain + SPIFFE ID verification itself (ADR 0031)
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		return VerifyConnection(cs, rootPool, c.ServerSPIFFEID, c.Clock())
	}
	return cfg, nil
}

// VerifyConnection is the post-handshake check: TLS 1.3, an allowed
// suite, a chain to roots with ServerAuth usage at now, and exactly one
// URI SAN equal to spiffeID.
func VerifyConnection(cs tls.ConnectionState, roots *x509.CertPool, spiffeID string, now time.Time) error {
	if !allowedCipherSuites[cs.CipherSuite] {
		return fmt.Errorf("spiffetls: negotiated cipher suite %#04x is not in the allowed set (TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256)", cs.CipherSuite)
	}
	if cs.Version != tls.VersionTLS13 {
		return fmt.Errorf("spiffetls: negotiated TLS version %#04x, want TLS 1.3", cs.Version)
	}
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("spiffetls: no peer certificates presented")
	}
	leaf := cs.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   now,
	}); err != nil {
		return fmt.Errorf("spiffetls: server certificate chain does not verify against the CA bundle: %w", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != spiffeID {
		return fmt.Errorf("%w: got %v, want [%s]", ErrServerSPIFFEIDMismatch, leaf.URIs, spiffeID)
	}
	return nil
}
