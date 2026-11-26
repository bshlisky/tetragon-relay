//go:build e3

// Command e3root generates a throwaway, self-signed, valid trust-root
// metadata envelope (architecture doc section 7.6's wire format) for the
// E3 CI job's RPM-shipped-initial-root bootstrap
// (/etc/tetragon-relay/trust/root.json, cmd/relayd/main.go's
// trustRootPath constant): internal/agent.Startup's establishTrustRoot
// refuses to start a brand-new (first-boot) store at all without one
// (ErrNoTrustRoot).
//
// This root is never used to sign or verify a policy bundle in E3 (step
// 6a does not process PolicyBundle/TrustUpdate at all, D2's own scope);
// it exists purely so relayd's startup sequence has something to adopt
// and persist. The three private keys this tool generates (root,
// targets, log) are discarded the moment this process exits -- nothing
// downstream needs them again.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

// These mirror internal/trust's own unexported wire types exactly
// (internal/trust/types.go, internal/dsse/envelope.go) -- duplicated
// here (not imported, since they are unexported) rather than adding an
// internal/trust export solely for this one-shot CI tool to consume.
type wireKeyEntry struct {
	KeyType      string `json:"keytype"`
	PublicKeyDER string `json:"public_key_der_b64"`
}
type wireRole struct {
	KeyIDs          []string `json:"keyids"`
	Threshold       int      `json:"threshold"`
	RequireKeyTypes []string `json:"require_keytypes"`
}
type wireRoles struct {
	Root    wireRole `json:"root"`
	Targets wireRole `json:"targets"`
	Log     wireRole `json:"log"`
}
type wireRootPayload struct {
	Schema          string                  `json:"schema"`
	Version         uint64                  `json:"version"`
	Expires         time.Time               `json:"expires"`
	Keys            map[string]wireKeyEntry `json:"keys"`
	Roles           wireRoles               `json:"roles"`
	RequireLogProof bool                    `json:"require_log_proof"`
}
type wireSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}
type wireEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []wireSignature `json:"signatures"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "e3root: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("e3root", flag.ContinueOnError)
	out := fs.String("out", "", "path to write the signed root metadata envelope")
	validity := fs.Duration("validity", 365*24*time.Hour, "root metadata validity (expires - now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}

	rootKey, rootKeyID, rootDER, err := genKey()
	if err != nil {
		return fmt.Errorf("generate root key: %w", err)
	}
	_, targetsKeyID, targetsDER, err := genKey()
	if err != nil {
		return fmt.Errorf("generate targets key: %w", err)
	}
	_, logKeyID, logDER, err := genKey()
	if err != nil {
		return fmt.Errorf("generate log key: %w", err)
	}

	now := time.Now()
	payload := wireRootPayload{
		Schema:  trust.RootSchema,
		Version: 1,
		Expires: now.Add(*validity),
		Keys: map[string]wireKeyEntry{
			string(rootKeyID):    {KeyType: string(trust.KeyTypeECDSAP384), PublicKeyDER: base64.StdEncoding.EncodeToString(rootDER)},
			string(targetsKeyID): {KeyType: string(trust.KeyTypeECDSAP384), PublicKeyDER: base64.StdEncoding.EncodeToString(targetsDER)},
			string(logKeyID):     {KeyType: string(trust.KeyTypeECDSAP384), PublicKeyDER: base64.StdEncoding.EncodeToString(logDER)},
		},
		Roles: wireRoles{
			Root:    wireRole{KeyIDs: []string{string(rootKeyID)}, Threshold: 1, RequireKeyTypes: []string{string(trust.KeyTypeECDSAP384)}},
			Targets: wireRole{KeyIDs: []string{string(targetsKeyID)}, Threshold: 1, RequireKeyTypes: []string{string(trust.KeyTypeECDSAP384)}},
			Log:     wireRole{KeyIDs: []string{string(logKeyID)}, Threshold: 1, RequireKeyTypes: []string{string(trust.KeyTypeECDSAP384)}},
		},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal root payload: %w", err)
	}

	pae := dsse.PAE(trust.RootPayloadType, payloadBytes)
	sig, err := signPAE(rootKey, pae)
	if err != nil {
		return fmt.Errorf("sign root payload: %w", err)
	}
	env := wireEnvelope{
		PayloadType: trust.RootPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures:  []wireSignature{{KeyID: string(rootKeyID), Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	// Round-trip through trust.LoadInitialRoot itself before writing
	// anything to disk: this tool must never hand relayd a root its own
	// startup sequence would then reject, which would turn an E3 setup
	// bug into a confusing relayd-side failure instead of a clear one
	// here.
	if _, err := trust.LoadInitialRoot(envBytes); err != nil {
		return fmt.Errorf("generated root metadata does not parse via trust.LoadInitialRoot (e3root bug): %w", err)
	}

	if err := os.WriteFile(*out, envBytes, 0o644); err != nil { //nolint:gosec // G306: 0644 matches the RPM-shipped root.json's own readable-by-anyone convention (architecture doc 8.5); --out is an operator-supplied flag for this one-shot CI tool
		return fmt.Errorf("write %s: %w", *out, err)
	}
	fmt.Printf("e3root: wrote a throwaway self-signed root metadata envelope (version 1) to %s\n", *out)
	return nil
}

func genKey() (key *ecdsa.PrivateKey, keyID trust.KeyID, der []byte, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, "", nil, err
	}
	der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", nil, err
	}
	keyID, err = trust.DeriveKeyID(&key.PublicKey)
	if err != nil {
		return nil, "", nil, err
	}
	return key, keyID, der, nil
}

func signPAE(key *ecdsa.PrivateKey, pae []byte) ([]byte, error) {
	digest := sha512.Sum384(pae)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}
