//go:build e3

// Command e3root generates the E3 CI job's throwaway trust root: a valid,
// self-signed root metadata envelope (architecture doc section 7.6's wire
// format) for the RPM-shipped initial root (/etc/tetragon-relay/trust/
// root.json, cmd/relayd's trustRootPath), which internal/agent.Startup
// needs to start a first-boot store at all.
//
// Step 6b (docs/prompts/step-06b.md F2) delivers real bundles and trust
// updates over the stream, so with --keys-out the root and targets
// private keys are kept (PKCS#8 PEM, 0600, in a runner-owned directory
// relayd never reads): cmd/bundlesign-test e3-bundle signs bundles with
// targets.key, and a later e3root run with --version N --prev-keys signs
// root N under the previous root key and its own new root key, the
// old-and-new threshold (*trust.Root).Update requires (S10). Every key
// is ECDSA P-384, threshold 1 per role, require_keytypes ecdsa-p384.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	version := fs.Uint64("version", 1, "root metadata version")
	keysOut := fs.String("keys-out", "", "directory to write root.key and targets.key (PKCS#8 PEM, 0600); empty discards them")
	prevKeys := fs.String("prev-keys", "", "directory holding the previous version's root.key; required when --version > 1")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	if *version == 0 || (*version > 1) != (*prevKeys != "") {
		return fmt.Errorf("--prev-keys is required exactly when --version > 1")
	}

	rootKey, rootKeyID, rootDER, err := genKey()
	if err != nil {
		return fmt.Errorf("generate root key: %w", err)
	}
	targetsKey, targetsKeyID, targetsDER, err := genKey()
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
		Version: *version,
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
	type signer struct {
		key *ecdsa.PrivateKey
		id  trust.KeyID
	}
	signers := []signer{{rootKey, rootKeyID}}
	if *version > 1 {
		prev, err := readKey(filepath.Join(*prevKeys, "root.key"))
		if err != nil {
			return fmt.Errorf("read previous root key: %w", err)
		}
		prevID, err := trust.DeriveKeyID(&prev.PublicKey)
		if err != nil {
			return err
		}
		signers = append([]signer{{prev, prevID}}, signers...)
	}
	sigs := make([]wireSignature, 0, len(signers))
	for _, sg := range signers {
		sig, err := signPAE(sg.key, pae)
		if err != nil {
			return fmt.Errorf("sign root payload: %w", err)
		}
		sigs = append(sigs, wireSignature{KeyID: string(sg.id), Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	env := wireEnvelope{
		PayloadType: trust.RootPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures:  sigs,
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	if _, err := trust.LoadInitialRoot(envBytes); err != nil {
		return fmt.Errorf("generated root metadata does not parse via trust.LoadInitialRoot (e3root bug): %w", err)
	}

	if err := os.WriteFile(*out, envBytes, 0o644); err != nil { //nolint:gosec // G306: 0644 matches the RPM-shipped root.json's own readable-by-anyone convention (architecture doc 8.5); --out is an operator-supplied flag for this one-shot CI tool
		return fmt.Errorf("write %s: %w", *out, err)
	}
	if *keysOut != "" {
		if err := os.MkdirAll(*keysOut, 0o700); err != nil {
			return err
		}
		if err := writeKey(filepath.Join(*keysOut, "root.key"), rootKey); err != nil {
			return err
		}
		if err := writeKey(filepath.Join(*keysOut, "targets.key"), targetsKey); err != nil {
			return err
		}
	}
	fmt.Printf("e3root: wrote root metadata version %d (%d signature(s)) to %s\n", *version, len(sigs), *out)
	return nil
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied flag for this one-shot CI tool
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
