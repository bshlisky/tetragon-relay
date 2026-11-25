package identity

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	valid := Config{
		TrustDomain:           "mgmt.example.internal",
		HostUUID:              "11111111-1111-1111-1111-111111111111",
		EnrollmentTrustBundle: []*x509.Certificate{{}},
		MaxCertTTL:            time.Hour,
		ClockSkew:             time.Minute,
		StoreDir:              "/var/lib/tetragon-relay",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate on a valid config: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(c Config) Config
		wantErr error
	}{
		{"empty trust domain", func(c Config) Config { c.TrustDomain = ""; return c }, ErrEmptyTrustDomain},
		{"empty host uuid", func(c Config) Config { c.HostUUID = ""; return c }, ErrEmptyHostUUID},
		{"empty enrollment bundle", func(c Config) Config { c.EnrollmentTrustBundle = nil; return c }, ErrEmptyEnrollmentBundle},
		{"zero max cert ttl", func(c Config) Config { c.MaxCertTTL = 0; return c }, ErrNonPositiveMaxCertTTL},
		{"negative max cert ttl", func(c Config) Config { c.MaxCertTTL = -time.Second; return c }, ErrNonPositiveMaxCertTTL},
		{"negative clock skew", func(c Config) Config { c.ClockSkew = -time.Second; return c }, ErrNegativeClockSkew},
		{"empty store dir", func(c Config) Config { c.StoreDir = ""; return c }, ErrEmptyStoreDir},
		{"negative rotation interval", func(c Config) Config { c.RotationInterval = -time.Second; return c }, ErrNonPositiveRotationInt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.mutate(valid).Validate(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_HostSPIFFEID(t *testing.T) {
	cfg := Config{TrustDomain: "mgmt.example.internal", HostUUID: "abc-123"}
	want := "spiffe://mgmt.example.internal/host/abc-123"
	if got := cfg.HostSPIFFEID(); got != want {
		t.Fatalf("HostSPIFFEID = %q, want %q", got, want)
	}
}

func TestConfig_RotationIntervalDefault(t *testing.T) {
	cfg := Config{}
	if got := cfg.rotationInterval(); got != DefaultRotationInterval {
		t.Fatalf("rotationInterval() = %v, want DefaultRotationInterval %v", got, DefaultRotationInterval)
	}
	cfg.RotationInterval = 24 * time.Hour
	if got := cfg.rotationInterval(); got != 24*time.Hour {
		t.Fatalf("rotationInterval() = %v, want 24h", got)
	}
}
