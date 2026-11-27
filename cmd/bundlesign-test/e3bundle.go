//go:build testtools

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// policyFlag collects repeated --policy name=path values.
type policyFlag []string

func (p *policyFlag) String() string     { return strings.Join(*p, ",") }
func (p *policyFlag) Set(v string) error { *p = append(*p, v); return nil }

// runE3Bundle implements "bundlesign-test e3-bundle": sign one policy
// bundle under an E3 targets key (cmd/e3root --keys-out), for E3's
// stream-delivery scenarios (docs/prompts/step-06b.md F2). Test-only,
// like the rest of this command (testtools tag).
func runE3Bundle(args []string) error {
	fs := flag.NewFlagSet("e3-bundle", flag.ContinueOnError)
	keyPath := fs.String("key", "", "targets private key (PKCS#8 PEM) to sign with")
	out := fs.String("out", "", "path to write the signed envelope")
	scope := fs.String("scope", "", "bundle scope")
	epoch := fs.Uint64("epoch", 0, "bundle epoch")
	mode := fs.String("mode", "monitor", "monitor | enforce")
	hostUUID := fs.String("host-uuid", "", "target host UUID")
	validity := fs.Duration("validity", 24*time.Hour, "expires - now")
	var policies policyFlag
	fs.Var(&policies, "policy", "name=path of a TracingPolicy YAML file (repeatable; version 1)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *out == "" || *scope == "" || *epoch == 0 || *hostUUID == "" || len(policies) == 0 {
		return fmt.Errorf("--key, --out, --scope, --epoch, --host-uuid and at least one --policy are required")
	}
	key, err := readPKCS8ECDSA(*keyPath)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(der)
	signer := &testKey{id: "sha256:" + hex.EncodeToString(sum[:]), ecdsaPriv: key, keyType: "ecdsa-p384", publicB64: base64.StdEncoding.EncodeToString(der)}

	var pp []policyPayload
	for _, p := range policies {
		name, path, ok := strings.Cut(p, "=")
		if !ok || name == "" || path == "" {
			return fmt.Errorf("--policy %q: want name=path", p)
		}
		yaml, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied flag for this test-only tool
		if err != nil {
			return err
		}
		pp = append(pp, newPolicy(name, 1, string(yaml), ""))
	}
	now := time.Now()
	payload, err := buildBundlePayload(bundleSpec{
		bundleID:           fmt.Sprintf("e3-%s-%d", *scope, *epoch),
		epoch:              *epoch,
		scope:              *scope,
		hostUUIDs:          []string{*hostUUID},
		notBefore:          now.Add(-5 * time.Minute),
		expires:            now.Add(*validity),
		// E3 tests delivery, not verify's version gate (covered by
		// internal/verify's tests and vectors): a low minimum keeps a
		// pre-release suffix in the CI tarball's GetVersion (which
		// sorts below 1.8.0) from failing every scenario.
		tetragonMinVersion: "1.0.0",
		mode:               *mode,
		policies:           pp,
	})
	if err != nil {
		return err
	}
	env, err := signEnvelope(bundlePayloadType, payload, signer)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, env, 0o644); err != nil { //nolint:gosec // G306: a signed bundle is public data
		return err
	}
	fmt.Printf("bundlesign-test: wrote %s bundle scope=%s epoch=%d (%d policies) to %s\n", *mode, *scope, *epoch, len(pp), *out)
	return nil
}

func readPKCS8ECDSA(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied flag for this test-only tool
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return ec, nil
}
