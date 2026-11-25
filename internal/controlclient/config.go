package controlclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

// Config is everything the mTLS client needs to dial the controller
// (architecture doc 6.1, 6.3 step 1). It carries no secrets of its own:
// ClientCertificate's private key is a crypto.Signer (in production,
// backed by internal/tpm.HostSigner through internal/identity), never raw
// key material this package can see or copy.
type Config struct {
	// Endpoints is the pinned controller IP:port list (architecture doc
	// 6.3 step 1: "agent resolves the controller VIP from local config
	// (not DNS-only)"). DNS is never used to resolve these.
	Endpoints []string

	// ControllerSPIFFEID is the exact SPIFFE ID the server certificate's
	// URI SAN must equal (architecture doc 6.1: "Agent verifies the
	// controller SVID... exactly (SPIFFE ID pinning, not hostname)").
	ControllerSPIFFEID string

	// ControllerCABundle verifies the server certificate's chain. This
	// is a separate trust bundle from internal/identity's enrollment
	// trust bundle and from the policy trust root (architecture doc
	// section 5: multiple separate trust domains).
	ControllerCABundle []*x509.Certificate

	// ClientCertificate is this host's enrolled mTLS identity (the chain
	// internal/identity.CertManager validated, with PrivateKey set to
	// the TPM HostSigner -- never a raw private key, only a
	// crypto.Signer). Rebuilt and a new Config/Client constructed after
	// renewal or rotation (step 6; this package does not watch for
	// identity changes itself).
	ClientCertificate tls.Certificate

	// Groups is the TLS 1.3 key-exchange group preference list
	// (architecture doc 6.1). Defaults to secp384r1, secp256r1
	// (DefaultGroups) if nil -- a config list, not a hardcoded pair, so
	// a future hybrid ML-KEM group can be added without a code change
	// (ADR 0022's not-yet-agile list; PQC itself stays deferred, never
	// enabled by default here).
	Groups []tls.CurveID

	// Clock returns the time BuildTLSConfig's VerifyConnection check
	// uses as x509.VerifyOptions.CurrentTime when verifying the
	// server's certificate chain (step-05b-review.md R5B-1). Required:
	// a nil Clock is a configuration error (Validate), matching this
	// project's "no time.Now in internal/" convention (ADR 0008) --
	// production callers pass time.Now; tests inject a fixed or
	// stepped clock so certificate-validity edges (not yet valid, just
	// expired) are deterministic rather than racing the wall clock.
	Clock func() time.Time
}

var (
	// ErrNoEndpoints is returned by Config.Validate when Endpoints is empty.
	ErrNoEndpoints = errors.New("controlclient: config: no endpoints configured")
	// ErrEmptyControllerSPIFFE is returned by Config.Validate when ControllerSPIFFEID is empty.
	ErrEmptyControllerSPIFFE = errors.New("controlclient: config: controller SPIFFE ID is empty")
	// ErrEmptyControllerBundle is returned by Config.Validate when ControllerCABundle is empty.
	ErrEmptyControllerBundle = errors.New("controlclient: config: controller CA bundle is empty")
	// ErrNoClientCertificate is returned by Config.Validate when ClientCertificate is unset.
	ErrNoClientCertificate = errors.New("controlclient: config: client certificate is not set")
	// ErrNoClock is returned by Config.Validate when Clock is nil
	// (step-05b-review.md R5B-1: the clock used for server certificate
	// verification must be injected, never read from the wall clock
	// implicitly).
	ErrNoClock = errors.New("controlclient: config: clock is not set")
)

// Validate rejects any configuration whose zero value would silently
// disable a security check.
func (c Config) Validate() error {
	if len(c.Endpoints) == 0 {
		return ErrNoEndpoints
	}
	if c.ControllerSPIFFEID == "" {
		return ErrEmptyControllerSPIFFE
	}
	if len(c.ControllerCABundle) == 0 {
		return ErrEmptyControllerBundle
	}
	if len(c.ClientCertificate.Certificate) == 0 || c.ClientCertificate.PrivateKey == nil {
		return ErrNoClientCertificate
	}
	if c.Clock == nil {
		return ErrNoClock
	}
	return nil
}

// DefaultGroups is architecture doc 6.1's TLS 1.3 group preference list:
// secp384r1 then secp256r1. Hybrid ML-KEM groups are deliberately absent
// (ADR 0022: "do NOT enable ML-KEM groups by default").
var DefaultGroups = []tls.CurveID{tls.CurveP384, tls.CurveP256}

func (c Config) groups() []tls.CurveID {
	if len(c.Groups) == 0 {
		return DefaultGroups
	}
	return c.Groups
}
