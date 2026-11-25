package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// loadCertPoolPEM reads path (a PEM file of one or more CERTIFICATE
// blocks) and returns the parsed certificates. Used for the controller
// CA bundle and the identity enrollment trust bundle (internal/
// controlclient.Config.ControllerCABundle, internal/identity.
// Config.EnrollmentTrustBundle), both separate trust domains from the
// policy trust root (architecture doc section 5).
func loadCertPoolPEM(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path comes from relay.yaml, already required to be root-owned/mode<=0640 via internal/config.Load
	if err != nil {
		return nil, fmt.Errorf("relayd: read %s: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("relayd: parse certificate in %s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("relayd: %s contains no CERTIFICATE blocks", path)
	}
	return certs, nil
}
