package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
)

// BuildCSR builds a PKCS#10 certificate signing request for signer's
// public key, with the subject and SANs B2 specifies: a SPIFFE-style URI
// SAN (cfg.HostSPIFFEID()) and no DNS SANs. The CSR is signed by signer
// itself (in production, *tpm.HostSigner); BuildCSR never sees or
// generates a private key.
func BuildCSR(signer crypto.Signer, cfg Config) ([]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	sigAlg, err := signatureAlgorithmFor(signer.Public())
	if err != nil {
		return nil, err
	}
	spiffeURI, err := url.Parse(cfg.HostSPIFFEID())
	if err != nil {
		return nil, fmt.Errorf("identity: build SPIFFE URI: %w", err)
	}
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cfg.HostUUID},
		SignatureAlgorithm: sigAlg,
		URIs:               []*url.URL{spiffeURI},
	}
	der, err := x509.CreateCertificateRequest(nil, template, signer)
	if err != nil {
		return nil, fmt.Errorf("identity: create CSR: %w", err)
	}
	return der, nil
}

// signatureAlgorithmFor picks the x509.SignatureAlgorithm matching pub's
// curve, so the CSR's signature uses the same hash internal/tpm.HostSigner
// expects for Sign (SHA-384 for P-384, SHA-256 for P-256; architecture doc
// 5.1 / docs/decisions/0028-host-signing-key-curve-fallback.md).
func signatureAlgorithmFor(pub crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("identity: unsupported public key type %T (only ECDSA is supported)", pub)
	}
	switch ecdsaPub.Curve {
	case elliptic.P384():
		return x509.ECDSAWithSHA384, nil
	case elliptic.P256():
		return x509.ECDSAWithSHA256, nil
	default:
		return 0, fmt.Errorf("identity: unsupported ECDSA curve %s (only P-384 and P-256 are supported)", ecdsaPub.Curve.Params().Name)
	}
}
