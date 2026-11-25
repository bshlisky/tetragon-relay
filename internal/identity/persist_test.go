package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadChain_MissingFileIsErrNoPersistedChain(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadChain(dir); !errors.Is(err, ErrNoPersistedChain) {
		t.Fatalf("LoadChain on a missing file: err = %v, want ErrNoPersistedChain", err)
	}
}

func TestLoadChain_CorruptFileIsError(t *testing.T) {
	dir := t.TempDir()
	if err := writeFileAtomic(filepath.Join(dir, chainFileName), []byte("not pem"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if _, err := LoadChain(dir); err == nil {
		t.Fatalf("LoadChain on a corrupt (no PEM blocks) file unexpectedly succeeded")
	}
}

func TestLoadChain_WrongPEMBlockTypeIsError(t *testing.T) {
	dir := t.TempDir()
	block := "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n"
	if err := writeFileAtomic(filepath.Join(dir, chainFileName), []byte(block), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if _, err := LoadChain(dir); err == nil {
		t.Fatalf("LoadChain on a wrong PEM block type unexpectedly succeeded")
	}
}

func TestPersistChainAndLoadChain_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if err := persistChain(dir, []*x509.Certificate{cert, cert}); err != nil {
		t.Fatalf("persistChain: %v", err)
	}
	loaded, err := LoadChain(dir)
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(loaded) != 2 || !loaded[0].Equal(cert) || !loaded[1].Equal(cert) {
		t.Fatalf("LoadChain did not round-trip persistChain's output")
	}
}

func TestCertManager_Load(t *testing.T) {
	ca, caKey := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)

	leaf := issueLeaf(t, leafOpts{
		pub: &signer.PublicKey, uris: []*url.URL{spiffeURI(t, cfg)},
		eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		notBefore: time.Now().Add(-time.Minute), notAfter: time.Now().Add(time.Hour),
		issuerCert: ca, issuerKey: caKey,
	})
	if err := persistChain(cfg.StoreDir, []*x509.Certificate{leaf, ca}); err != nil {
		t.Fatalf("persistChain: %v", err)
	}

	cm, err := NewCertManager(cfg, signer, funcEnroller(func(context.Context, []byte) ([]*x509.Certificate, error) { return nil, nil }))
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if cm.Chain() != nil {
		t.Fatalf("Chain() is non-nil before Load")
	}
	if err := cm.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cm.Chain() == nil || !cm.Chain()[0].Equal(leaf) {
		t.Fatalf("Load did not populate the active chain correctly")
	}
}

func TestCertManager_Load_NoPersistedChain(t *testing.T) {
	ca, _ := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	cm, err := NewCertManager(cfg, signer, funcEnroller(func(context.Context, []byte) ([]*x509.Certificate, error) { return nil, nil }))
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if err := cm.Load(); !errors.Is(err, ErrNoPersistedChain) {
		t.Fatalf("Load: err = %v, want ErrNoPersistedChain", err)
	}
}
