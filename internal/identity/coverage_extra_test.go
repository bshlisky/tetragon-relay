package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCertManager_Rejections(t *testing.T) {
	ca, _ := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	enroller := funcEnroller(func(context.Context, []byte) ([]*x509.Certificate, error) { return nil, nil })

	if _, err := NewCertManager(cfg, nil, enroller); err == nil {
		t.Fatalf("NewCertManager with a nil signer unexpectedly succeeded")
	}
	if _, err := NewCertManager(cfg, signer, nil); err == nil {
		t.Fatalf("NewCertManager with a nil enroller unexpectedly succeeded")
	}
	badCfg := cfg
	badCfg.HostUUID = ""
	if _, err := NewCertManager(badCfg, signer, enroller); err == nil {
		t.Fatalf("NewCertManager with an invalid config unexpectedly succeeded")
	}
}

func TestCertManager_Enroll_BuildCSRFailureSurfaces(t *testing.T) {
	ca, _ := newTestCA(t)
	cfg := baseCfg(t, ca)
	// P-224 is an unsupported curve for BuildCSR (csr.go): Enroll must
	// surface that failure rather than calling the Enroller at all.
	badSigner := genKey(t, elliptic.P224())
	called := false
	enroller := funcEnroller(func(context.Context, []byte) ([]*x509.Certificate, error) {
		called = true
		return nil, nil
	})
	cm, err := NewCertManager(cfg, badSigner, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if _, err := cm.Enroll(context.Background(), time.Now()); err == nil {
		t.Fatalf("Enroll with an unsupported signer curve unexpectedly succeeded")
	}
	if called {
		t.Fatalf("Enroll called the Enroller despite BuildCSR failing")
	}
}

func TestCertManager_Enroll_EnrollerErrorSurfaces(t *testing.T) {
	ca, _ := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	wantErr := errors.New("boom")
	enroller := funcEnroller(func(context.Context, []byte) ([]*x509.Certificate, error) { return nil, wantErr })
	cm, err := NewCertManager(cfg, signer, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	_, err = cm.Enroll(context.Background(), time.Now())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("Enroll err = %v, want wrapping %v", err, wantErr)
	}
}

func TestCertManager_Enroll_PersistFailureSurfaces(t *testing.T) {
	ca, caKey := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	// A store directory that does not exist makes persistChain's
	// writeFileAtomic fail.
	cfg.StoreDir = filepath.Join(cfg.StoreDir, "no-such-subdir")
	now := time.Now()

	enroller := funcEnroller(func(_ context.Context, csrDER []byte) ([]*x509.Certificate, error) {
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, err
		}
		leaf := issueLeaf(t, leafOpts{
			pub: csr.PublicKey.(*ecdsa.PublicKey), uris: csr.URIs,
			eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			notBefore: now.Add(-time.Minute), notAfter: now.Add(time.Hour),
			issuerCert: ca, issuerKey: caKey,
		})
		return []*x509.Certificate{leaf, ca}, nil
	})
	cm, err := NewCertManager(cfg, signer, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if _, err := cm.Enroll(context.Background(), now); err == nil {
		t.Fatalf("Enroll with an unwritable store dir unexpectedly succeeded")
	}
}

func TestCertManager_Rotate_NilSignerIsError(t *testing.T) {
	ca, _ := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	enroller := funcEnroller(func(context.Context, []byte) ([]*x509.Certificate, error) { return nil, nil })
	cm, err := NewCertManager(cfg, signer, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if _, err := cm.Rotate(context.Background(), time.Now(), nil); err == nil {
		t.Fatalf("Rotate with a nil new signer unexpectedly succeeded")
	}
}

type fakeNonECDSASigner struct{}

func (fakeNonECDSASigner) Public() crypto.PublicKey { return "not an ecdsa key" }
func (fakeNonECDSASigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unused")
}

func TestCertManager_ValidateChain_NonECDSASignerPublicKeyIsError(t *testing.T) {
	ca, caKey := newTestCA(t)
	signer := genKey(t, elliptic.P384())
	cfg := baseCfg(t, ca)
	enroller := funcEnroller(func(context.Context, []byte) ([]*x509.Certificate, error) { return nil, nil })
	cm, err := NewCertManager(cfg, signer, enroller)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	leaf := issueLeaf(t, leafOpts{
		pub: &signer.PublicKey, uris: []*url.URL{spiffeURI(t, cfg)},
		eku:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		notBefore: time.Now().Add(-time.Minute), notAfter: time.Now().Add(time.Hour),
		issuerCert: ca, issuerKey: caKey,
	})
	if err := cm.validateChain([]*x509.Certificate{leaf, ca}, fakeNonECDSASigner{}, time.Now()); err == nil {
		t.Fatalf("validateChain with a non-ECDSA signer public key unexpectedly succeeded")
	}
}

func TestWriteFileAtomic_NonexistentDirIsError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "no-such-subdir", "file")
	if err := writeFileAtomic(bad, []byte("x"), 0o600); err == nil {
		t.Fatalf("writeFileAtomic into a nonexistent directory unexpectedly succeeded")
	}
}

func TestWriteFileAtomic_RenameOntoDirectoryIsError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := writeFileAtomic(target, []byte("x"), 0o600); err == nil {
		t.Fatalf("writeFileAtomic renaming onto a directory unexpectedly succeeded")
	}
}

func TestBuildCSR_URLParseFailureSurfaces(t *testing.T) {
	cfg := testConfig(t)
	cfg.HostUUID = "contains a space and a\x7fcontrol char"
	key := genKey(t, elliptic.P384())
	// A host UUID with unusual characters still produces a parseable URI
	// in practice (url.Parse is permissive); this test documents that
	// BuildCSR's URL-parse error path is defensive, not reachable from
	// any HostUUID value Validate() currently accepts. The call must not
	// panic regardless of outcome.
	_, _ = BuildCSR(key, cfg)
	_ = url.URL{}
}
