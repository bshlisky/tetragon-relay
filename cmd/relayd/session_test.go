package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestHexEncode(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"\x00":     "00",
		"\xff":     "ff",
		"\xab\xcd": "abcd",
	}
	for in, want := range cases {
		if got := hexEncode([]byte(in)); got != want {
			t.Errorf("hexEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	got := clientCertificate([]*x509.Certificate{cert}, key)
	if len(got.Certificate) != 1 {
		t.Fatalf("Certificate has %d entries, want 1", len(got.Certificate))
	}
	if got.PrivateKey != crypto.Signer(key) {
		t.Fatalf("PrivateKey = %v, want the supplied signer", got.PrivateKey)
	}
	if got.Leaf != cert {
		t.Fatalf("Leaf = %v, want the supplied leaf certificate", got.Leaf)
	}

	if empty := clientCertificate(nil, key); empty.Leaf != nil {
		t.Fatalf("clientCertificate(nil, ...).Leaf = %v, want nil", empty.Leaf)
	}
}

func TestAgentBuildDigest_NoPanic(_ *testing.T) {
	// /proc/self/exe only exists on Linux; this just confirms the
	// best-effort call never panics on any platform.
	_, _ = agentBuildDigest()
}
