package config

import "errors"

// Every rejection this package can produce has a distinct sentinel, per
// this project's "typed errors for every rejection" rule.
var (
	// --- B1: file source checks ---

	// ErrConfigNotFound is returned when the configured path does not exist.
	ErrConfigNotFound = errors.New("config: relay.yaml not found")
	// ErrConfigIsSymlink is returned when the configured path is a symlink.
	ErrConfigIsSymlink = errors.New("config: relay.yaml must not be a symlink")
	// ErrConfigNotRegularFile is returned when the configured path is not a regular file.
	ErrConfigNotRegularFile = errors.New("config: relay.yaml must be a regular file")
	// ErrConfigModeTooPermissive is returned when relay.yaml's mode has any bit set beyond limits.MaxConfigFileMode.
	ErrConfigModeTooPermissive = errors.New("config: relay.yaml mode must be no more permissive than 0640")
	// ErrConfigCannotVerifyOwnership is returned when the platform cannot report file ownership (fails closed).
	ErrConfigCannotVerifyOwnership = errors.New("config: cannot verify relay.yaml ownership on this platform")
	// ErrConfigNotOwnedByRoot is returned when relay.yaml's owning uid is not 0.
	ErrConfigNotOwnedByRoot = errors.New("config: relay.yaml must be owned by root")
	// ErrConfigGroupLookupFailed is returned when the tetragon-relay group cannot be resolved.
	ErrConfigGroupLookupFailed = errors.New("config: could not resolve the tetragon-relay group")
	// ErrConfigWrongGroup is returned when relay.yaml's group is not tetragon-relay.
	ErrConfigWrongGroup = errors.New("config: relay.yaml group must be tetragon-relay")
	// ErrConfigTooLarge is returned when relay.yaml exceeds limits.MaxConfigFileBytes.
	ErrConfigTooLarge = errors.New("config: relay.yaml exceeds the maximum allowed size")

	// --- B2: parsing ---

	// ErrConfigParse is returned when relay.yaml does not decode into the closed schema (including unknown fields).
	ErrConfigParse = errors.New("config: relay.yaml does not parse against the configuration schema")

	// --- B3: required fields ---

	ErrMissingHostUUID              = errors.New("config: host.uuid is required")
	ErrInvalidHostUUID              = errors.New("config: host.uuid must be a canonical lowercase UUID")
	ErrMissingAllowedScopes         = errors.New("config: host.allowed_scopes must be non-empty")
	ErrEmptyAllowedScope            = errors.New("config: host.allowed_scopes must not contain an empty scope")
	ErrMissingControllerEndpoints   = errors.New("config: controller.endpoints must be non-empty")
	ErrInvalidControllerEndpoint    = errors.New("config: controller.endpoints entries must be non-empty host:port strings")
	ErrMissingControllerSPIFFEID    = errors.New("config: controller.spiffe_id is required")
	ErrInvalidHeartbeatInterval     = errors.New("config: controller.heartbeat_interval must be positive")
	ErrMissingCollectorEndpoints    = errors.New("config: collector.endpoints must be non-empty")
	ErrInvalidCollectorEndpoint     = errors.New("config: collector.endpoints entries must be non-empty host:port strings")
	ErrMissingCollectorSPIFFEID     = errors.New("config: collector.spiffe_id is required")
	ErrInvalidSpoolMaxBytes         = errors.New("config: collector.spool_max_bytes must be positive")
	ErrInvalidBatchMaxEvents        = errors.New("config: collector.batch_max_events must be positive")
	ErrInvalidBatchMaxAge           = errors.New("config: collector.batch_max_age must be positive")
	ErrMissingIdentityTrustDomain   = errors.New("config: identity.trust_domain is required")
	ErrMissingEnrollmentTrustBundle = errors.New("config: identity.trust_bundle is required")
	ErrInvalidIdentityProvider      = errors.New("config: identity.provider must be \"spire\" or \"idm\"")
	ErrInvalidKeyRotation           = errors.New("config: identity.key_rotation must be positive")
	ErrMissingTetragonSocket        = errors.New("config: tetragon.socket is required")
	ErrMissingPersistDir            = errors.New("config: tetragon.persist_dir is required")
	ErrInvalidHealthWindow          = errors.New("config: apply.health_window must be positive")
	ErrInvalidSurgeThreshold        = errors.New("config: apply.enforcement_event_surge_threshold must be positive")
	ErrInvalidRedactionPattern      = errors.New("config: redaction.argv_patterns entry does not compile as a regular expression")
)
