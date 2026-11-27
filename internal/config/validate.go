package config

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// uuidPattern matches the canonical 8-4-4-4-12 hyphenated UUID textual
// form, lowercase hex only -- the same rule internal/verify.validUUID
// applies to a bundle's target host UUIDs (step 1 review A7), duplicated
// here rather than imported so internal/config stays decoupled from
// internal/verify (internal/verify.validUUID is unexported, and this
// project's convention -- e.g. internal/tetra's HostSELinuxEnforcing/
// HostSELinuxPermissive constants versus internal/hostprobe -- is to
// duplicate a small, stable rule rather than add a cross-package
// dependency for it).
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validateAndBuild turns raw (already closed-schema decoded) into a
// Config, applying every required-field check and default (Part B3). It
// never mutates raw.
func validateAndBuild(raw rawConfig) (*Config, error) {
	c := &Config{}

	if err := validateHost(raw.Host, c); err != nil {
		return nil, err
	}
	if err := validateController(raw.Controller, c); err != nil {
		return nil, err
	}
	if err := validateCollector(raw.Collector, c); err != nil {
		return nil, err
	}
	if err := validateIdentity(raw.Identity, c); err != nil {
		return nil, err
	}
	if err := validateTetragon(raw.Tetragon, c); err != nil {
		return nil, err
	}
	if err := validateApply(raw.Apply, c); err != nil {
		return nil, err
	}
	if err := validateRedaction(raw.Redaction, c); err != nil {
		return nil, err
	}
	return c, nil
}

func validateHost(h rawHost, c *Config) error {
	if h.UUID == "" {
		return ErrMissingHostUUID
	}
	if !uuidPattern.MatchString(h.UUID) {
		return fmt.Errorf("%w: %q", ErrInvalidHostUUID, h.UUID)
	}
	if len(h.AllowedScopes) == 0 {
		return ErrMissingAllowedScopes
	}
	for _, s := range h.AllowedScopes {
		if s == "" {
			return ErrEmptyAllowedScope
		}
	}
	c.HostUUID = h.UUID
	c.AllowedScopes = append([]string(nil), h.AllowedScopes...)
	return nil
}

// validEndpoint reports whether s parses as a "host:port" pair (accepting
// bracketed IPv6 literals), via net.SplitHostPort rather than a hand
// rolled check, with both parts non-empty.
func validEndpoint(s string) bool {
	host, port, err := net.SplitHostPort(s)
	return err == nil && host != "" && port != ""
}

func validateController(cc rawController, c *Config) error {
	if len(cc.Endpoints) == 0 {
		return ErrMissingControllerEndpoints
	}
	for _, e := range cc.Endpoints {
		if !validEndpoint(e) {
			return fmt.Errorf("%w: %q", ErrInvalidControllerEndpoint, e)
		}
	}
	if cc.SPIFFEID == "" {
		return ErrMissingControllerSPIFFEID
	}
	interval := limits.DefaultHeartbeatInterval
	if cc.HeartbeatInterval != "" {
		d, err := time.ParseDuration(cc.HeartbeatInterval)
		if err != nil || d <= 0 {
			return fmt.Errorf("%w: %q", ErrInvalidHeartbeatInterval, cc.HeartbeatInterval)
		}
		interval = d
	}
	c.ControllerEndpoints = append([]string(nil), cc.Endpoints...)
	c.ControllerSPIFFEID = cc.SPIFFEID
	c.HeartbeatInterval = interval
	return nil
}

func validateCollector(cl rawCollector, c *Config) error {
	if len(cl.Endpoints) == 0 {
		return ErrMissingCollectorEndpoints
	}
	for _, e := range cl.Endpoints {
		if !validEndpoint(e) {
			return fmt.Errorf("%w: %q", ErrInvalidCollectorEndpoint, e)
		}
	}
	if cl.SPIFFEID == "" {
		return ErrMissingCollectorSPIFFEID
	}
	spoolMaxBytes := int64(limits.DefaultCollectorSpoolMaxBytes)
	if cl.SpoolMaxBytes != 0 {
		if cl.SpoolMaxBytes <= 0 {
			return ErrInvalidSpoolMaxBytes
		}
		spoolMaxBytes = cl.SpoolMaxBytes
	}
	batchMaxEvents := limits.DefaultCollectorBatchMaxEvents
	if cl.BatchMaxEvents != 0 {
		if cl.BatchMaxEvents <= 0 {
			return ErrInvalidBatchMaxEvents
		}
		batchMaxEvents = cl.BatchMaxEvents
	}
	batchMaxAge := limits.DefaultCollectorBatchMaxAge
	if cl.BatchMaxAge != "" {
		d, err := time.ParseDuration(cl.BatchMaxAge)
		if err != nil || d <= 0 {
			return fmt.Errorf("%w: %q", ErrInvalidBatchMaxAge, cl.BatchMaxAge)
		}
		batchMaxAge = d
	}
	eventTypes := validEventTypes
	if cl.EventTypes != nil {
		if len(cl.EventTypes) == 0 {
			return fmt.Errorf("%w: empty list", ErrInvalidEventType)
		}
		seen := map[string]bool{}
		for _, t := range cl.EventTypes {
			if seen[t] || !slices.Contains(validEventTypes, t) {
				return fmt.Errorf("%w: %q", ErrInvalidEventType, t)
			}
			seen[t] = true
		}
		eventTypes = cl.EventTypes
	}
	c.EventTypes = append([]string(nil), eventTypes...)
	c.CollectorEndpoints = append([]string(nil), cl.Endpoints...)
	c.CollectorSPIFFEID = cl.SPIFFEID
	c.SpoolMaxBytes = spoolMaxBytes
	c.BatchMaxEvents = batchMaxEvents
	c.BatchMaxAge = batchMaxAge
	return nil
}

// validIdentityProviders is architecture doc 5.2/5.3's two supported
// identity providers.
var validIdentityProviders = map[string]bool{"spire": true, "idm": true}

func validateIdentity(id rawIdentity, c *Config) error {
	if id.TrustDomain == "" {
		return ErrMissingIdentityTrustDomain
	}
	if id.EnrollmentTrustBundle == "" {
		return ErrMissingEnrollmentTrustBundle
	}
	provider := id.Provider
	if provider == "" {
		provider = "spire"
	}
	if !validIdentityProviders[provider] {
		return fmt.Errorf("%w: %q", ErrInvalidIdentityProvider, id.Provider)
	}
	rotation := limits.DefaultIdentityKeyRotation
	if id.KeyRotation != "" {
		d, err := time.ParseDuration(id.KeyRotation)
		if err != nil || d <= 0 {
			return fmt.Errorf("%w: %q", ErrInvalidKeyRotation, id.KeyRotation)
		}
		rotation = d
	}
	c.IdentityProvider = provider
	c.IdentityTrustDomain = id.TrustDomain
	c.SPIREServer = id.SPIREServer
	c.EnrollmentTrustBundle = id.EnrollmentTrustBundle
	c.KeyRotation = rotation
	return nil
}

func validateTetragon(tg rawTetragon, c *Config) error {
	if tg.Socket == "" {
		return ErrMissingTetragonSocket
	}
	if tg.PersistDir == "" {
		return ErrMissingPersistDir
	}
	c.TetragonSocket = tg.Socket
	c.PersistDir = tg.PersistDir
	c.AllowSELinuxDisabled = tg.AllowSELinuxDisabled
	return nil
}

func validateApply(ap rawApply, c *Config) error {
	window := limits.DefaultApplyHealthWindow
	if ap.HealthWindow != "" {
		d, err := time.ParseDuration(ap.HealthWindow)
		if err != nil || d <= 0 {
			return fmt.Errorf("%w: %q", ErrInvalidHealthWindow, ap.HealthWindow)
		}
		window = d
	}
	surge := limits.DefaultApplySurgeThreshold
	if ap.EnforcementEventSurgeThreshold != 0 {
		if ap.EnforcementEventSurgeThreshold <= 0 {
			return ErrInvalidSurgeThreshold
		}
		surge = ap.EnforcementEventSurgeThreshold
	}
	c.HealthWindow = window
	c.EnforcementSurgeThreshold = surge
	return nil
}

// validateRedaction: configured patterns are added to the built-in set,
// never replace it, and each must compile as Go RE2. keep_env: true is
// refused in step 7a: the environment is always dropped (ADR 0039 section
// 7); a relaxation can only come from signed metadata (step 7b).
func validateRedaction(r rawRedaction, c *Config) error {
	for _, p := range r.ArgvPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("%w: %q: %w", ErrInvalidRedactionPattern, p, err)
		}
	}
	if r.KeepEnv {
		return ErrKeepEnvUnsupported
	}
	c.ArgvPatterns = append([]string(nil), r.ArgvPatterns...)
	return nil
}
