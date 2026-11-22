package limits

import (
	"regexp"
	"time"
)

const (
	// MaxEnvelopeBytes is the hard cap on a serialized DSSE envelope
	// (policy bundle or trust-root update) before any parsing happens.
	// Architecture doc section 7.4 step 1.
	MaxEnvelopeBytes = 1 << 20 // 1 MiB

	// MaxRootMetadataBytes bounds a trust-root DSSE envelope. Root
	// metadata is small (a handful of P-384 keys and role lists), so a
	// much lower cap than MaxEnvelopeBytes is used; this is not specified
	// numerically in the architecture doc and is a reviewable choice
	// (see docs/decisions/0002-root-metadata-size-cap.md).
	MaxRootMetadataBytes = 64 << 10 // 64 KiB

	// MaxJSONDepth is the maximum nesting depth accepted by the strict
	// JSON decoder. Architecture doc section 7.4 step 5.
	MaxJSONDepth = 32

	// ClockSkew is the tolerance applied to not_before/expires checks.
	// Architecture doc section 7.4 step 9.
	ClockSkew = 300 * time.Second

	// MaxPoliciesPerBundle is the guardrail cap on policies in one
	// bundle. Architecture doc section 7.5.
	MaxPoliciesPerBundle = 64

	// MaxPolicyYAMLBytes bounds a single policy's YAML document.
	// Architecture doc section 7.5 caps selector counts, not YAML size
	// directly; this cap exists so a single oversized policy cannot be
	// used to exhaust memory while the bundle as a whole is still under
	// MaxEnvelopeBytes (e.g. inside a base64 payload with little other
	// content). See docs/decisions/0003-policy-yaml-size-cap.md.
	MaxPolicyYAMLBytes = 256 << 10 // 256 KiB

	// MaxReasonBytes bounds the human-readable reason string returned
	// alongside a rejection. It must never carry more attacker-controlled
	// content than this, truncated and escaped.
	MaxReasonBytes = 128
)

// PolicyNamePattern is the required shape of a policy name, taken verbatim
// from architecture doc section 7.4 step 11 / typical Kubernetes-style
// resource naming.
var PolicyNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
