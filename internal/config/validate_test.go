package config

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// validYAML is a minimal, fully valid relay.yaml (every required field
// set, every optional field left at its default) used as the baseline
// every mutation test in this file starts from.
const validYAML = `
host:
  uuid: "9b2f1a30-1111-4b2a-8c3d-0123456789ab"
  allowed_scopes: ["prod-db"]
controller:
  endpoints: ["10.20.0.10:8443"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/controller"
collector:
  endpoints: ["10.20.0.30:4317"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/collector"
identity:
  trust_domain: "mgmt.example.internal"
  trust_bundle: "/etc/tetragon-relay/trust/spire-bundle.pem"
tetragon:
  socket: "unix:///var/run/tetragon/tetragon.sock"
  persist_dir: "/etc/tetragon/tetragon.tp.d/relay"
`

func TestParse_ValidConfig_DefaultsApplied(t *testing.T) {
	cfg, err := parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.HostUUID != "9b2f1a30-1111-4b2a-8c3d-0123456789ab" {
		t.Errorf("HostUUID = %q", cfg.HostUUID)
	}
	if len(cfg.AllowedScopes) != 1 || cfg.AllowedScopes[0] != "prod-db" {
		t.Errorf("AllowedScopes = %v", cfg.AllowedScopes)
	}
	if cfg.HeartbeatInterval != 15*time.Second {
		t.Errorf("HeartbeatInterval default = %v, want 15s", cfg.HeartbeatInterval)
	}
	if cfg.SpoolMaxBytes != 2*(1<<30) {
		t.Errorf("SpoolMaxBytes default = %d", cfg.SpoolMaxBytes)
	}
	if cfg.BatchMaxEvents != 2000 {
		t.Errorf("BatchMaxEvents default = %d", cfg.BatchMaxEvents)
	}
	if cfg.BatchMaxAge != 2*time.Second {
		t.Errorf("BatchMaxAge default = %v", cfg.BatchMaxAge)
	}
	if cfg.IdentityProvider != "spire" {
		t.Errorf("IdentityProvider default = %q, want spire", cfg.IdentityProvider)
	}
	if cfg.KeyRotation != 7*24*time.Hour {
		t.Errorf("KeyRotation default = %v, want 168h", cfg.KeyRotation)
	}
	if cfg.HealthWindow != 60*time.Second {
		t.Errorf("HealthWindow default = %v, want 60s", cfg.HealthWindow)
	}
	if cfg.EnforcementSurgeThreshold != 500 {
		t.Errorf("EnforcementSurgeThreshold default = %d, want 500", cfg.EnforcementSurgeThreshold)
	}
	if len(cfg.ArgvPatterns) != 0 {
		t.Errorf("ArgvPatterns default = %v, want none beyond the built-in set", cfg.ArgvPatterns)
	}
	if len(cfg.EventTypes) != 6 {
		t.Errorf("EventTypes default = %v, want all six", cfg.EventTypes)
	}
	if cfg.AllowSELinuxDisabled {
		t.Errorf("AllowSELinuxDisabled default = true, want false")
	}
	if len(cfg.SecurityRelaxations()) != 0 {
		t.Errorf("SecurityRelaxations on default config = %v, want none", cfg.SecurityRelaxations())
	}
	if len(cfg.Digest()) != 32 {
		t.Errorf("Digest length = %d, want 32", len(cfg.Digest()))
	}
}

func TestParse_Digest_IsSHA256OfExactBytes(t *testing.T) {
	raw := []byte(validYAML)
	cfg, err := parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := sha256Sum(raw)
	if string(cfg.Digest()) != string(want) {
		t.Fatalf("Digest = %x, want %x", cfg.Digest(), want)
	}
	// Digest must be a copy, not an alias into Config's internal state.
	d := cfg.Digest()
	d[0] ^= 0xFF
	if string(cfg.Digest()) != string(want) {
		t.Fatalf("mutating the returned Digest slice changed Config's internal digest")
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func TestSecurityRelaxations(t *testing.T) {
	// A standalone document (not validYAML plus an appended fragment):
	// appending a second "tetragon:"/"redaction:" key would duplicate a
	// top-level key, which internal/yamlharden's hardening pass rejects.
	y := `
host:
  uuid: "9b2f1a30-1111-4b2a-8c3d-0123456789ab"
  allowed_scopes: ["prod-db"]
controller:
  endpoints: ["10.20.0.10:8443"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/controller"
collector:
  endpoints: ["10.20.0.30:4317"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/collector"
identity:
  trust_domain: "mgmt.example.internal"
  trust_bundle: "/etc/tetragon-relay/trust/spire-bundle.pem"
tetragon:
  socket: "unix:///var/run/tetragon/tetragon.sock"
  persist_dir: "/etc/tetragon/tetragon.tp.d/relay"
  allow_selinux_disabled: true
`
	cfg, err := parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.AllowSELinuxDisabled {
		t.Fatalf("relaxation flags not set: %+v", cfg)
	}
	if len(cfg.SecurityRelaxations()) != 1 {
		t.Fatalf("SecurityRelaxations = %v, want 1 entry", cfg.SecurityRelaxations())
	}
	// ADR 0039: keep_env: true is refused; the environment is always dropped.
	if _, err := parse([]byte(y + "redaction:\n  keep_env: true\n")); !errors.Is(err, ErrKeepEnvUnsupported) {
		t.Fatalf("keep_env: true: err = %v, want ErrKeepEnvUnsupported", err)
	}
}

func TestParse_UnknownField_Rejected(t *testing.T) {
	y := validYAML + "unknown_top_level_key: true\n"
	if _, err := parse([]byte(y)); !errors.Is(err, ErrConfigParse) {
		t.Fatalf("error = %v, want ErrConfigParse", err)
	}
}

func TestParse_UnknownNestedField_Rejected(t *testing.T) {
	y := `
host:
  uuid: "9b2f1a30-1111-4b2a-8c3d-0123456789ab"
  allowed_scopes: ["prod-db"]
  unknown_nested_key: true
controller:
  endpoints: ["10.20.0.10:8443"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/controller"
collector:
  endpoints: ["10.20.0.30:4317"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/collector"
identity:
  trust_domain: "mgmt.example.internal"
  trust_bundle: "/etc/tetragon-relay/trust/spire-bundle.pem"
tetragon:
  socket: "unix:///var/run/tetragon/tetragon.sock"
  persist_dir: "/etc/tetragon/tetragon.tp.d/relay"
`
	if _, err := parse([]byte(y)); !errors.Is(err, ErrConfigParse) {
		t.Fatalf("error = %v, want ErrConfigParse", err)
	}
}

func TestParse_NotAMapping_Rejected(t *testing.T) {
	if _, err := parse([]byte("- a\n- b\n")); !errors.Is(err, ErrConfigParse) {
		t.Fatalf("error = %v, want ErrConfigParse", err)
	}
}

func TestParse_Empty_Rejected(t *testing.T) {
	if _, err := parse([]byte("")); err == nil {
		t.Fatalf("expected an error for an empty document")
	}
}

func TestParse_AmbiguousUnquotedScalar_Rejected(t *testing.T) {
	// redaction.keep_env: yes (unquoted) is YAML-1.1-ambiguous
	// (internal/yamlharden rejects it before the typed decode ever
	// sees it), proving relay.yaml goes through the same hardening
	// pass as policy YAML.
	y := `
host:
  uuid: "9b2f1a30-1111-4b2a-8c3d-0123456789ab"
  allowed_scopes: ["prod-db"]
controller:
  endpoints: ["10.20.0.10:8443"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/controller"
collector:
  endpoints: ["10.20.0.30:4317"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/collector"
identity:
  trust_domain: "mgmt.example.internal"
  trust_bundle: "/etc/tetragon-relay/trust/spire-bundle.pem"
tetragon:
  socket: "unix:///var/run/tetragon/tetragon.sock"
  persist_dir: "/etc/tetragon/tetragon.tp.d/relay"
redaction:
  keep_env: yes
`
	if _, err := parse([]byte(y)); !errors.Is(err, ErrConfigParse) {
		t.Fatalf("error = %v, want ErrConfigParse (ambiguous scalar)", err)
	}
}

// mutateYAML applies a string replacement to validYAML, for building one
// invalid variant per test case without repeating the whole document.
func mutateYAML(oldStr, newStr string) string {
	return replaceOnce(validYAML, oldStr, newStr)
}

func replaceOnce(s, oldStr, newStr string) string {
	i := indexOf(s, oldStr)
	if i < 0 {
		panic("replaceOnce: substring not found: " + oldStr)
	}
	return s[:i] + newStr + s[i+len(oldStr):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestValidateAndBuild_EveryRule(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr error
	}{
		{"missing host uuid", mutateYAML(`uuid: "9b2f1a30-1111-4b2a-8c3d-0123456789ab"`, `uuid: ""`), ErrMissingHostUUID},
		{"invalid host uuid", mutateYAML(`uuid: "9b2f1a30-1111-4b2a-8c3d-0123456789ab"`, `uuid: "NOT-A-UUID"`), ErrInvalidHostUUID},
		{"uppercase host uuid rejected", mutateYAML(`uuid: "9b2f1a30-1111-4b2a-8c3d-0123456789ab"`, `uuid: "9B2F1A30-1111-4b2a-8c3d-0123456789ab"`), ErrInvalidHostUUID},
		{"missing allowed scopes", mutateYAML(`allowed_scopes: ["prod-db"]`, `allowed_scopes: []`), ErrMissingAllowedScopes},
		{"empty allowed scope entry", mutateYAML(`allowed_scopes: ["prod-db"]`, `allowed_scopes: [""]`), ErrEmptyAllowedScope},
		{"missing controller endpoints", mutateYAML(`endpoints: ["10.20.0.10:8443"]`, `endpoints: []`), ErrMissingControllerEndpoints},
		{"invalid controller endpoint", mutateYAML(`endpoints: ["10.20.0.10:8443"]`, `endpoints: ["not-a-host-port"]`), ErrInvalidControllerEndpoint},
		{"missing controller spiffe id", mutateYAML(`spiffe_id: "spiffe://mgmt.example.internal/mgmt/controller"`, `spiffe_id: ""`), ErrMissingControllerSPIFFEID},
		{"invalid heartbeat interval", mutateYAML("controller:\n  endpoints:", "controller:\n  heartbeat_interval: \"not-a-duration\"\n  endpoints:"), ErrInvalidHeartbeatInterval},
		{"non-positive heartbeat interval", mutateYAML("controller:\n  endpoints:", "controller:\n  heartbeat_interval: \"0s\"\n  endpoints:"), ErrInvalidHeartbeatInterval},
		{"missing collector endpoints", mutateYAML(`endpoints: ["10.20.0.30:4317"]`, `endpoints: []`), ErrMissingCollectorEndpoints},
		{"invalid collector endpoint", mutateYAML(`endpoints: ["10.20.0.30:4317"]`, `endpoints: ["bad"]`), ErrInvalidCollectorEndpoint},
		{"missing collector spiffe id", mutateYAML(`spiffe_id: "spiffe://mgmt.example.internal/mgmt/collector"`, `spiffe_id: ""`), ErrMissingCollectorSPIFFEID},
		{"invalid spool max bytes", mutateYAML("collector:\n  endpoints:", "collector:\n  spool_max_bytes: -1\n  endpoints:"), ErrInvalidSpoolMaxBytes},
		{"invalid batch max events", mutateYAML("collector:\n  endpoints:", "collector:\n  batch_max_events: -1\n  endpoints:"), ErrInvalidBatchMaxEvents},
		{"invalid batch max age", mutateYAML("collector:\n  endpoints:", "collector:\n  batch_max_age: \"nope\"\n  endpoints:"), ErrInvalidBatchMaxAge},
		{"missing identity trust domain", mutateYAML(`trust_domain: "mgmt.example.internal"`, `trust_domain: ""`), ErrMissingIdentityTrustDomain},
		{"missing enrollment trust bundle", mutateYAML(`trust_bundle: "/etc/tetragon-relay/trust/spire-bundle.pem"`, `trust_bundle: ""`), ErrMissingEnrollmentTrustBundle},
		{"invalid identity provider", mutateYAML("identity:\n  trust_domain:", "identity:\n  provider: \"neither\"\n  trust_domain:"), ErrInvalidIdentityProvider},
		{"invalid key rotation", mutateYAML("identity:\n  trust_domain:", "identity:\n  key_rotation: \"nope\"\n  trust_domain:"), ErrInvalidKeyRotation},
		{"missing tetragon socket", mutateYAML(`socket: "unix:///var/run/tetragon/tetragon.sock"`, `socket: ""`), ErrMissingTetragonSocket},
		{"missing tetragon persist dir", mutateYAML(`persist_dir: "/etc/tetragon/tetragon.tp.d/relay"`, `persist_dir: ""`), ErrMissingPersistDir},
		{"invalid health window", mutateYAML("tetragon:\n  socket:", "apply:\n  health_window: \"nope\"\ntetragon:\n  socket:"), ErrInvalidHealthWindow},
		{"invalid surge threshold", mutateYAML("tetragon:\n  socket:", "apply:\n  enforcement_event_surge_threshold: -1\ntetragon:\n  socket:"), ErrInvalidSurgeThreshold},
		{"unknown event type", mutateYAML("collector:\n  endpoints:", "collector:\n  event_types: [\"process_bogus\"]\n  endpoints:"), ErrInvalidEventType},
		{"duplicate event type", mutateYAML("collector:\n  endpoints:", "collector:\n  event_types: [\"process_exec\", \"process_exec\"]\n  endpoints:"), ErrInvalidEventType},
		{"empty event types", mutateYAML("collector:\n  endpoints:", "collector:\n  event_types: []\n  endpoints:"), ErrInvalidEventType},
		{"invalid redaction pattern", mutateYAML("tetragon:\n  socket:", "redaction:\n  argv_patterns: [\"(unterminated\"]\ntetragon:\n  socket:"), ErrInvalidRedactionPattern},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse([]byte(tc.yaml))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v\nyaml:\n%s", err, tc.wantErr, tc.yaml)
			}
		})
	}
}

func TestValidateAndBuild_OptionalPositiveOverridesAccepted(t *testing.T) {
	y := `
host:
  uuid: "9b2f1a30-1111-4b2a-8c3d-0123456789ab"
  allowed_scopes: ["prod-db", "staging"]
controller:
  endpoints: ["10.20.0.10:8443", "10.20.0.11:8443"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/controller"
  heartbeat_interval: "30s"
collector:
  endpoints: ["10.20.0.30:4317"]
  spiffe_id: "spiffe://mgmt.example.internal/mgmt/collector"
  spool_max_bytes: 1000
  batch_max_events: 10
  batch_max_age: "5s"
identity:
  provider: "idm"
  trust_domain: "mgmt.example.internal"
  trust_bundle: "/etc/tetragon-relay/trust/spire-bundle.pem"
  key_rotation: "24h"
tetragon:
  socket: "unix:///var/run/tetragon/tetragon.sock"
  persist_dir: "/etc/tetragon/tetragon.tp.d/relay"
apply:
  health_window: "90s"
  enforcement_event_surge_threshold: 10
redaction:
  argv_patterns: ["custom=\\S+"]
`
	cfg, err := parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.HeartbeatInterval != 30*time.Second {
		t.Errorf("HeartbeatInterval = %v", cfg.HeartbeatInterval)
	}
	if cfg.SpoolMaxBytes != 1000 {
		t.Errorf("SpoolMaxBytes = %d", cfg.SpoolMaxBytes)
	}
	if cfg.BatchMaxEvents != 10 {
		t.Errorf("BatchMaxEvents = %d", cfg.BatchMaxEvents)
	}
	if cfg.BatchMaxAge != 5*time.Second {
		t.Errorf("BatchMaxAge = %v", cfg.BatchMaxAge)
	}
	if cfg.IdentityProvider != "idm" {
		t.Errorf("IdentityProvider = %q", cfg.IdentityProvider)
	}
	if cfg.KeyRotation != 24*time.Hour {
		t.Errorf("KeyRotation = %v", cfg.KeyRotation)
	}
	if cfg.HealthWindow != 90*time.Second {
		t.Errorf("HealthWindow = %v", cfg.HealthWindow)
	}
	if cfg.EnforcementSurgeThreshold != 10 {
		t.Errorf("EnforcementSurgeThreshold = %d", cfg.EnforcementSurgeThreshold)
	}
	if len(cfg.ArgvPatterns) != 1 || cfg.ArgvPatterns[0] != `custom=\S+` {
		t.Errorf("ArgvPatterns = %v", cfg.ArgvPatterns)
	}
}

func TestParse_EventTypesSubset(t *testing.T) {
	cfg, err := parse([]byte(mutateYAML("collector:\n  endpoints:", "collector:\n  event_types: [\"process_kprobe\", \"process_exec\"]\n  endpoints:")))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.EventTypes) != 2 || cfg.EventTypes[0] != "process_kprobe" {
		t.Fatalf("EventTypes = %v", cfg.EventTypes)
	}
}
