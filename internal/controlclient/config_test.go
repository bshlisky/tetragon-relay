package controlclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	ca, _ := testCertAndKey(t, "")
	valid := Config{
		Endpoints:          []string{"10.0.0.1:8443"},
		ControllerSPIFFEID: "spiffe://mgmt.example.internal/mgmt/controller",
		ControllerCABundle: []*x509.Certificate{ca},
		ClientCertificate:  testClientCert(t),
		Clock:              time.Now,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate on a valid config: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(c Config) Config
		wantErr error
	}{
		{"no endpoints", func(c Config) Config { c.Endpoints = nil; return c }, ErrNoEndpoints},
		{"empty controller spiffe id", func(c Config) Config { c.ControllerSPIFFEID = ""; return c }, ErrEmptyControllerSPIFFE},
		{"empty controller bundle", func(c Config) Config { c.ControllerCABundle = nil; return c }, ErrEmptyControllerBundle},
		{"no client certificate", func(c Config) Config { c.ClientCertificate = tls.Certificate{}; return c }, ErrNoClientCertificate},
		{"no clock", func(c Config) Config { c.Clock = nil; return c }, ErrNoClock},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.mutate(valid).Validate(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_GroupsDefault(t *testing.T) {
	cfg := Config{}
	got := cfg.groups()
	if len(got) != len(DefaultGroups) {
		t.Fatalf("groups() = %v, want %v", got, DefaultGroups)
	}
	cfg.Groups = []tls.CurveID{tls.X25519}
	if got := cfg.groups(); len(got) != 1 || got[0] != tls.X25519 {
		t.Fatalf("groups() with explicit Groups = %v, want [X25519]", got)
	}
}
