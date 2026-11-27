package config

import "time"

// rawConfig is relay.yaml's closed schema (architecture doc 8.6), decoded
// with yaml.v3's KnownFields(true): any key not named here is a load
// error (ErrConfigParse), never silently ignored. Duration fields are
// plain strings (time.Duration has no YAML unmarshaler of its own) and
// are parsed by validate.go.
type rawConfig struct {
	Host       rawHost       `yaml:"host"`
	Controller rawController `yaml:"controller"`
	Collector  rawCollector  `yaml:"collector"`
	Identity   rawIdentity   `yaml:"identity"`
	Tetragon   rawTetragon   `yaml:"tetragon"`
	Apply      rawApply      `yaml:"apply"`
	Redaction  rawRedaction  `yaml:"redaction"`
}

type rawHost struct {
	UUID          string   `yaml:"uuid"`
	AllowedScopes []string `yaml:"allowed_scopes"`
}

type rawController struct {
	Endpoints         []string `yaml:"endpoints"`
	SPIFFEID          string   `yaml:"spiffe_id"`
	HeartbeatInterval string   `yaml:"heartbeat_interval"`
}

type rawCollector struct {
	Endpoints      []string `yaml:"endpoints"`
	SPIFFEID       string   `yaml:"spiffe_id"`
	SpoolMaxBytes  int64    `yaml:"spool_max_bytes"`
	BatchMaxEvents int      `yaml:"batch_max_events"`
	BatchMaxAge    string   `yaml:"batch_max_age"`
	EventTypes     []string `yaml:"event_types"`
}

// rawIdentity's TrustDomain field is a deviation from architecture doc
// 8.6's literal example (which has no identity.trust_domain key): Part B3
// requires "identity trust domain" among the fields with no default, and
// internal/identity.Config.TrustDomain has no other source in this
// repository (docs/reports/step-05b.md section 6 / section 9's open
// question 1 -- now answered by this field). See docs/reports/step-06a.md
// for this deviation recorded against the prompt.
type rawIdentity struct {
	Provider              string `yaml:"provider"`
	TrustDomain           string `yaml:"trust_domain"`
	SPIREServer           string `yaml:"spire_server"`
	EnrollmentTrustBundle string `yaml:"trust_bundle"`
	KeyRotation           string `yaml:"key_rotation"`
}

// rawTetragon's AllowSELinuxDisabled field is named (and defaults to
// false) the same way internal/tetra.Config.AllowSELinuxDisabled is
// (rather than architecture doc 8.6's unrelated allow_selinux_disabled
// mention in prose, section 8.7's addendum): a Go bool's zero value must
// be the secure behavior (SELinux required), so the field names the
// RELAXATION, not the requirement.
type rawTetragon struct {
	Socket               string `yaml:"socket"`
	PersistDir           string `yaml:"persist_dir"`
	AllowSELinuxDisabled bool   `yaml:"allow_selinux_disabled"`
}

type rawApply struct {
	HealthWindow                   string `yaml:"health_window"`
	EnforcementEventSurgeThreshold int    `yaml:"enforcement_event_surge_threshold"`
}

// rawRedaction's DropEnv field from architecture doc 8.6's example is
// deliberately renamed KeepEnv (YAML key keep_env): "drop_env: true" as
// written would make the secure behavior (dropping environment variables)
// depend on an explicit true, so a relay.yaml that simply omits the field
// -- Go's bool zero value, false -- would silently KEEP every process's
// environment, the opposite of the project's "zero/absent value is the
// secure behavior" rule. Inverting the name so false (the zero value)
// means "drop the environment" (the secure default) fixes this the same
// way internal/tetra.Config.AllowSELinuxDisabled already does for its own
// field; see docs/reports/step-06a.md for this deviation recorded against
// the architecture doc's literal example.
type rawRedaction struct {
	ArgvPatterns []string `yaml:"argv_patterns"`
	KeepEnv      bool     `yaml:"keep_env"`
}

// validEventTypes is collector.event_types' vocabulary (ADR 0039): the
// Tetragon event types telemetry can classify. Absent means all six.
var validEventTypes = []string{"process_exec", "process_exit", "process_kprobe", "process_tracepoint", "process_uprobe", "process_lsm"}

// Config is the validated result of Load: every required field is
// non-zero, every duration/size field has its default applied, and
// Digest is the SHA-256 of the exact bytes Load read.
type Config struct {
	HostUUID            string
	AllowedScopes       []string
	ControllerEndpoints []string
	ControllerSPIFFEID  string
	HeartbeatInterval   time.Duration

	CollectorEndpoints []string
	CollectorSPIFFEID  string
	SpoolMaxBytes      int64
	BatchMaxEvents     int
	BatchMaxAge        time.Duration
	// EventTypes is collector.event_types: the GetEvents allow-list.
	EventTypes []string

	IdentityProvider      string
	IdentityTrustDomain   string
	SPIREServer           string
	EnrollmentTrustBundle string
	KeyRotation           time.Duration

	TetragonSocket       string
	PersistDir           string
	AllowSELinuxDisabled bool

	HealthWindow              time.Duration
	EnforcementSurgeThreshold int

	// ArgvPatterns are the configured redaction patterns. They are only
	// ever ADDED to internal/telemetry.DefaultArgvPatterns (ADR 0039
	// section 7): config cannot remove a built-in pattern.
	ArgvPatterns []string

	digest [32]byte
}

// Digest returns a copy of the SHA-256 of the exact bytes Load read for
// this Config (architecture doc 6.2's Hello.config_digest).
func (c *Config) Digest() []byte {
	out := make([]byte, len(c.digest))
	copy(out, c.digest[:])
	return out
}

// SecurityRelaxations returns a human-readable line for every configured
// setting that relaxes a security check (Part B3). relayd's startup
// sequence (internal/agent, Part C) is expected to write a loud audit
// record for each one before proceeding; an empty slice means no
// relaxation is configured.
func (c *Config) SecurityRelaxations() []string {
	var out []string
	if c.AllowSELinuxDisabled {
		out = append(out, "tetragon.allow_selinux_disabled=true: SELinux peer-verification checks on the Tetragon socket are disabled")
	}
	return out
}
