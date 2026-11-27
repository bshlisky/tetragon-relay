package controlclient

import (
	"crypto/tls"

	"github.com/bshlisky/tetragon-relay/internal/spiffetls"
)

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
	// ADR 0031's verification, shared with the telemetry channel
	// (internal/spiffetls, ADR 0039 section 8).
	return spiffetls.ClientTLSConfig(spiffetls.ClientConfig{
		ServerSPIFFEID:    cfg.ControllerSPIFFEID,
		ServerCABundle:    cfg.ControllerCABundle,
		ClientCertificate: cfg.ClientCertificate,
		Groups:            cfg.groups(),
		Clock:             cfg.Clock,
	})
}
