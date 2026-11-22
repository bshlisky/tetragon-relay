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

	// MaxSignaturesPerEnvelope bounds the number of {keyid, sig} entries
	// a single DSSE envelope (bundle or root metadata) may carry.
	// Without this, an attacker could pad an otherwise-small envelope
	// with thousands of signatures to force expensive, repeated ECDSA
	// verification work per check. Step 1 review A4.
	MaxSignaturesPerEnvelope = 16

	// MaxBundleValidity bounds expires - not_before for a policy bundle.
	// Step 1 review A5.
	MaxBundleValidity = 90 * 24 * time.Hour

	// MaxEpochJump bounds how far a signed bundle's epoch may exceed a
	// scope's current epoch. Without this, a single signed bundle with
	// an epoch near the top of the uint64 range would permanently brick
	// that scope: every subsequent, legitimately-signed bundle would
	// have to carry an epoch higher still, which is not practical to
	// arrange. Step 1 review A7.
	MaxEpochJump = 1_000_000

	// MaxRootValidity bounds expires - now for a trust-root metadata
	// update accepted by (*trust.Root).Update. The *initial* root
	// shipped in the agent RPM is exempt (there is no prior root to
	// compare "now" against at build time); this only applies to
	// rotations. Step 1 review A6.
	MaxRootValidity = 400 * 24 * time.Hour

	// MaxBundleIDBytes bounds a bundle's bundle_id field. Step 1 review A7.
	MaxBundleIDBytes = 128

	// MinPolicyVersion bounds a policy's version field from below.
	// Step 1 review A7.
	MinPolicyVersion = 1
	// MaxPolicyVersion bounds a policy's version field from above
	// (2^31-1, i.e. any positive int32). Step 1 review A7.
	MaxPolicyVersion = 1<<31 - 1
)

// PolicyNamePattern is the required shape of a policy name, taken verbatim
// from architecture doc section 7.4 step 11 / typical Kubernetes-style
// resource naming.
var PolicyNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// BundleIDPattern is the required shape of a bundle_id. Step 1 review A7.
var BundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// PolicySHA256Pattern requires exactly 64 lowercase hex characters: a
// canonical SHA-256 digest, with no tolerance for uppercase hex (which
// would otherwise require a case-normalizing comparison, see step 1 review
// A7).
var PolicySHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
