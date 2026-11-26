//go:build testca && testtpm

// Command testenroll is E3's out-of-band identity provisioning tool
// (docs/prompts/step-06a-e3-prompt.md, docs/reports/step-06a.md section
// 9's plan). It is test-only by construction (C1): built only with
// -tags testca,testtpm, never part of production relayd or the RPM, and
// never invoked by relayd itself -- it is run once, by the E3 CI job,
// BEFORE relayd starts, as a separate process with access to the test
// CA's private key relayd itself must never hold (that would make
// relayd its own CA, a different and more confusing test shortcut than
// this project's existing ones).
//
// testenroll:
//  1. Opens the same TPM resource manager device relayd uses
//     (--tpm-device, default /dev/tpmrm0; in E3 a vtpm-proxy-backed
//     swtpm, scripts/e3-run.sh) through tpm.OpenDevice, the opener
//     relayd and relay-probe use. E3 originally ran a second, TCP swtpm
//     for this tool and the identity scenarios; run 45854346976 showed
//     why that cannot work: the store and host-signer blobs S1/S2's
//     production relayd creates are bound to the /dev/tpmrm0 TPM, so a
//     different TPM rejects them with TPM_RC_INTEGRITY.
//  2. Does NOT provision the SRK or the NV counter: the real unit's
//     ExecStartPre=+relay-probe --provision-tpm already did, on the same
//     device, before S1. A missing SRK is an error here, never repaired.
//  3. Calls tpm.NewOrLoadHostSigner at the exact path cmd/relayd's own
//     main() passes (storeDir + "/host-signer.json"), so relayd, started
//     afterward, loads the identical key.
//  4. Builds a fresh identity.TestCA, writes its certificate (the
//     identity enrollment trust bundle AND, in this test-only setup,
//     the policy trust root's own CA -- architecture doc section 5's
//     two separate trust domains collapsed into one CA for tests, the
//     same simplification internal/controlclient's own integration test
//     already documents) to --ca-cert-out.
//  5. Issues a one-time join token and enrolls the host's TPM-held key
//     through identity.NewCertManager(...).Enroll with
//     identity.NewTestEnroller(ca, token) -- the same CertManager.Enroll
//     code path docs/reports/step-05b.md built and tested, writing the
//     resulting chain to --store-dir via persistChain internally.
//  6. Issues the test controller's own server certificate from the same
//     CA (IssueServerCertificate) and writes it (and its private key) to
//     --controller-cert-out / --controller-key-out, for the E3 test
//     controller driver to load.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/identity"
	"github.com/bshlisky/tetragon-relay/internal/tpm"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "testenroll: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	tpmDevice          string
	storeDir           string
	trustDomain        string
	hostUUID           string
	certTTL            time.Duration
	caCertOut          string
	controllerCertOut  string
	controllerKeyOut   string
	controllerSPIFFEID string
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("testenroll", flag.ContinueOnError)
	var c config
	fs.StringVar(&c.tpmDevice, "tpm-device", "/dev/tpmrm0", "TPM resource manager device, the same one relayd opens")
	fs.StringVar(&c.storeDir, "store-dir", "/var/lib/tetragon-relay", "relayd's persist directory (same value cmd/relayd's main.go uses); the host signer blob and identity chain are written here")
	fs.StringVar(&c.trustDomain, "trust-domain", "", "identity.trust_domain (must match relay.yaml)")
	fs.StringVar(&c.hostUUID, "host-uuid", "", "host.uuid (must match relay.yaml)")
	fs.DurationVar(&c.certTTL, "cert-ttl", 4*time.Hour, "validity of every certificate this tool issues (host and controller)")
	fs.StringVar(&c.caCertOut, "ca-cert-out", "", "path to write the test CA's certificate (PEM); becomes relay.yaml's identity.trust_bundle")
	fs.StringVar(&c.controllerCertOut, "controller-cert-out", "", "path to write the test controller's server certificate (PEM)")
	fs.StringVar(&c.controllerKeyOut, "controller-key-out", "", "path to write the test controller's server private key (PEM, PKCS8)")
	fs.StringVar(&c.controllerSPIFFEID, "controller-spiffe-id", "", "SPIFFE ID embedded in the controller's server certificate (must match relay.yaml's controller.spiffe_id)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	for name, v := range map[string]string{
		"tpm-device": c.tpmDevice, "trust-domain": c.trustDomain, "host-uuid": c.hostUUID,
		"ca-cert-out": c.caCertOut, "controller-cert-out": c.controllerCertOut,
		"controller-key-out": c.controllerKeyOut, "controller-spiffe-id": c.controllerSPIFFEID,
	} {
		if v == "" {
			return config{}, fmt.Errorf("--%s is required", name)
		}
	}
	return c, nil
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	tp, err := tpm.OpenDevice(cfg.tpmDevice)
	if err != nil {
		return fmt.Errorf("open TPM device %s: %w", cfg.tpmDevice, err)
	}
	defer func() { _ = tp.Close() }()

	signer, err := tpm.NewOrLoadHostSigner(tp, cfg.storeDir+"/host-signer.json")
	if err != nil {
		return fmt.Errorf("host signer: %w", err)
	}

	ca, err := identity.NewTestCA(cfg.certTTL)
	if err != nil {
		return fmt.Errorf("new test CA: %w", err)
	}
	if err := writePEM(cfg.caCertOut, "CERTIFICATE", ca.CACertificate().Raw, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}

	if err := enrollHost(ca, signer, cfg); err != nil {
		return fmt.Errorf("enroll host identity: %w", err)
	}

	if err := issueControllerCertificate(ca, cfg); err != nil {
		return fmt.Errorf("issue controller certificate: %w", err)
	}

	fmt.Printf("testenroll: host identity (trust domain %q, host %q) and controller certificate; CA written to %s\n",
		cfg.trustDomain, cfg.hostUUID, cfg.caCertOut)
	return nil
}

// enrollHost builds the host's CSR from signer (the TPM-held key) and
// exchanges it with ca through the SAME CertManager.Enroll code path
// cmd/relayd's own main() would eventually use if it had a production
// Enroller (it does not, C2) -- just invoked here, out of process order,
// with the test CA's NewTestEnroller standing in for a real one
// (ADR 0030: an Enroller only ever certifies a key it is proven the
// caller possesses, never generates one). Enroll persists the resulting
// chain to cfg.storeDir internally (identity.persistChain), the exact
// directory cmd/relayd's own identity.Config.StoreDir names, so relayd's
// own CertManager.Load call finds it.
func enrollHost(ca *identity.TestCA, signer crypto.Signer, cfg config) error {
	token, err := ca.IssueJoinToken()
	if err != nil {
		return fmt.Errorf("issue join token: %w", err)
	}
	identityCfg := identity.Config{
		TrustDomain:           cfg.trustDomain,
		HostUUID:              cfg.hostUUID,
		EnrollmentTrustBundle: []*x509.Certificate{ca.CACertificate()},
		MaxCertTTL:            cfg.certTTL,
		ClockSkew:             5 * time.Minute,
		StoreDir:              cfg.storeDir,
	}
	cm, err := identity.NewCertManager(identityCfg, signer, identity.NewTestEnroller(ca, token))
	if err != nil {
		return fmt.Errorf("new cert manager: %w", err)
	}
	if _, err := cm.Enroll(context.Background(), time.Now()); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	return nil
}

func issueControllerCertificate(ca *identity.TestCA, cfg config) error {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate controller key: %w", err)
	}
	u, err := url.Parse(cfg.controllerSPIFFEID)
	if err != nil {
		return fmt.Errorf("parse controller SPIFFE ID %q: %w", cfg.controllerSPIFFEID, err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "controller"}, URIs: []*url.URL{u},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return fmt.Errorf("create controller CSR: %w", err)
	}
	now := time.Now()
	chain, err := ca.IssueServerCertificate(csrDER, now.Add(-time.Minute), now.Add(cfg.certTTL))
	if err != nil {
		return fmt.Errorf("issue controller server certificate: %w", err)
	}
	if err := writePEM(cfg.controllerCertOut, "CERTIFICATE", chain[0].Raw, 0o644); err != nil {
		return fmt.Errorf("write controller certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal controller private key: %w", err)
	}
	return writePEM(cfg.controllerKeyOut, "PRIVATE KEY", keyDER, 0o600)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	return os.WriteFile(path, b, mode) //nolint:gosec // G306: mode is an explicit parameter (0o644 for public certs, 0o600 for the controller's private key); path is an operator-supplied flag for this one-shot, root-run CI tool
}
