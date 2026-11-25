package controlclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// allowedCipherSuites is architecture doc 6.1's cipher suite list:
// TLS_AES_256_GCM_SHA384 and TLS_AES_128_GCM_SHA256 (not
// TLS_CHACHA20_POLY1305_SHA256). Go's crypto/tls does NOT allow
// restricting which TLS 1.3 cipher suites are offered or negotiated via
// Config.CipherSuites ("Note that TLS 1.3 ciphersuites are not
// configurable" -- crypto/tls.Config's own doc comment, confirmed against
// this project's go1.27.4 toolchain): the standard library always offers
// all three. buildTLSConfig therefore enforces this as a POST-handshake
// policy check inside VerifyConnection instead of a pre-handshake
// restriction -- the connection is refused if a forbidden suite was
// negotiated, even though this project cannot prevent it being offered
// in the ClientHello. This is a documented deviation from "configure the
// suite list", not a silent gap; see docs/reports/step-05b.md section 6.
var allowedCipherSuites = map[uint16]bool{
	tls.TLS_AES_256_GCM_SHA384: true,
	tls.TLS_AES_128_GCM_SHA256: true,
}

// BuildTLSConfig builds the *tls.Config for the control channel
// (architecture doc 6.1):
//   - TLS 1.3 only (MinVersion == MaxVersion == tls.VersionTLS13).
//   - Cipher suites restricted to the allowed set via a post-handshake
//     VerifyConnection check (see allowedCipherSuites's doc comment).
//   - Groups from cfg.Groups (default secp384r1, secp256r1).
//   - Client certificate: cfg.ClientCertificate (the enrolled chain,
//     signed through the TPM HostSigner).
//   - Server authentication: InsecureSkipVerify is set, and VerifyConnection
//     performs the ENTIRE check itself (chain verification against
//     cfg.ControllerCABundle, plus an exact URI SAN match against
//     cfg.ControllerSPIFFEID). This project's rule is "use VerifyConnection,
//     not InsecureSkipVerify plus custom code, unless you document why" --
//     the "why" here: Go's crypto/tls (and grpc-go's credentials.NewTLS,
//     confirmed by reading vendor/google.golang.org/grpc/credentials/tls.go)
//     both auto-populate Config.ServerName from the dial target's host
//     whenever it is left empty, so leaving ServerName empty does NOT skip
//     Go's default hostname verification against this connection's actual
//     dial address the way it does for a standalone crypto/tls.Config never
//     passed through grpc. Since this project's certificates carry no DNS or
//     IP SANs at all (architecture doc 5.1: URI SAN only), that default
//     hostname check can never succeed regardless of what ServerName ends up
//     set to, and must be disabled (InsecureSkipVerify) so VerifyConnection's
//     own, correct check (chain + exact SPIFFE URI SAN, the actual identity
//     this project authenticates on) runs instead of a verification that
//     would always fail. This is the same pattern the spiffe/go-spiffe
//     project's tlsconfig package uses for the identical reason.
//   - No session resumption: ClientSessionCache is left nil and
//     SessionTicketsDisabled is set, so no session ticket is ever stored
//     or presented (architecture doc 6.1: "Each connection re-proves TPM
//     key possession").
//   - No 0-RTT: Go's crypto/tls client does not implement TLS 1.3 0-RTT
//     (early data) at all, so this requirement is satisfied by the
//     standard library itself having no knob that could enable it.
func BuildTLSConfig(cfg Config) (*tls.Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	rootPool := x509.NewCertPool()
	for _, c := range cfg.ControllerCABundle {
		rootPool.AddCert(c)
	}

	tlsCfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       cfg.groups(),
		Certificates:           []tls.Certificate{cfg.ClientCertificate},
		RootCAs:                rootPool,
		InsecureSkipVerify:     true, //nolint:gosec // G402: VerifyConnection below performs full chain + SPIFFE ID verification itself; see BuildTLSConfig's doc comment for why Go's default (hostname-based) verification cannot be used here
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
	}
	tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if !allowedCipherSuites[cs.CipherSuite] {
			return fmt.Errorf("controlclient: negotiated cipher suite %#04x is not in the allowed set (TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256)", cs.CipherSuite)
		}
		if cs.Version != tls.VersionTLS13 {
			return fmt.Errorf("controlclient: negotiated TLS version %#04x, want TLS 1.3", cs.Version)
		}
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("controlclient: no peer certificates presented")
		}
		leaf := cs.PeerCertificates[0]
		intermediates := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			// step-05b-review.md R5B-1: use the injected clock, not
			// the zero value (which leaf.Verify treats as time.Now()
			// internally), so certificate-validity edges are
			// deterministic and testable.
			CurrentTime: cfg.Clock(),
		}); err != nil {
			return fmt.Errorf("controlclient: server certificate chain does not verify against the controller CA bundle: %w", err)
		}
		if !hasExactURISAN(leaf, cfg.ControllerSPIFFEID) {
			return fmt.Errorf("%w: got %v, want [%s]", ErrControllerSPIFFEIDMismatch, leaf.URIs, cfg.ControllerSPIFFEID)
		}
		return nil
	}
	return tlsCfg, nil
}

func hasExactURISAN(cert *x509.Certificate, want string) bool {
	return len(cert.URIs) == 1 && cert.URIs[0].String() == want
}
