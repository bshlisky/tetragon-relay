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

	// MaxKeysPerObject bounds the number of keys any single JSON object
	// may carry while being validated by internal/strictjson. Even after
	// fixing the duplicate-key check's algorithmic complexity (step 1
	// review A11), an unbounded key count is still unnecessary exposure:
	// this caps the amount of per-object bookkeeping (and, transitively,
	// memory) a single object can force regardless of how efficiently
	// it's checked.
	MaxKeysPerObject = 4096

	// MaxYAMLNodeCount bounds the total number of yaml.Node values a
	// single policy document's YAML tree may contain, counted while
	// walking it in internal/policydoc (step 2 prompt Part B1). This
	// bounds memory and CPU for the hardening pass itself, before any
	// JSON conversion happens.
	MaxYAMLNodeCount = 20_000

	// MaxYAMLScalarBytes bounds the length of any single YAML scalar
	// (the node's raw `Value` string). Step 2 prompt Part B1.
	MaxYAMLScalarBytes = 4 << 10 // 4 KiB

	// MaxYAMLDepth bounds YAML mapping/sequence nesting depth, applied
	// during the hardening pass in internal/policydoc, before the
	// strict-JSON depth check (MaxJSONDepth) is applied again to the
	// converted canonical JSON. Step 2 prompt Part B1 specifies the same
	// numeric bound (32) as MaxJSONDepth.
	MaxYAMLDepth = MaxJSONDepth

	// MaxHooksPerBundle bounds the total number of hook specs (kprobes +
	// tracepoints + uprobes + lsmhooks, summed across every policy in a
	// bundle) internal/guard will analyze. Step 2 prompt Part C, G4.
	MaxHooksPerBundle = 256

	// MaxSelectorValuesPerBundle bounds the total number of selector
	// values (every string/uint value inside every MatchBinaries,
	// MatchArgs, MatchPIDs, etc. value list, summed across a bundle)
	// internal/guard will analyze. Step 2 prompt Part C, G4.
	MaxSelectorValuesPerBundle = 4096

	// --- Step 3: internal/tetra, internal/hostprobe, internal/apply ---

	// DefaultTetragonRPCTimeout is the default per-call timeout for every
	// internal/tetra RPC (step 3 prompt Part B3), overridable by config.
	DefaultTetragonRPCTimeout = 10 * time.Second

	// MaxTetragonErrorMessageBytes bounds how much of a Tetragon-returned
	// error message internal/tetra's RejectedByTetragon error retains.
	// Step 3 prompt Part B3.
	MaxTetragonErrorMessageBytes = 512

	// MaxGetEventsResponseBytes bounds a single GetEvents stream message.
	// Step 3 prompt Part B3 ("bounded response sizes"); applied via
	// grpc.MaxCallRecvMsgSize on the client connection.
	MaxGetEventsResponseBytes = 4 << 20 // 4 MiB

	// DefaultApplyHealthWindow is internal/apply's post-add health window
	// default (step 3 prompt Part D5).
	DefaultApplyHealthWindow = 60 * time.Second
	// MinApplyHealthWindow bounds a configured health window from below.
	MinApplyHealthWindow = 15 * time.Second
	// MaxApplyHealthWindow bounds a configured health window from above.
	MaxApplyHealthWindow = 600 * time.Second

	// DefaultApplySurgeThreshold is the default enforcement-events-per-
	// minute rollback threshold (step 3 prompt Part D5).
	DefaultApplySurgeThreshold = 500

	// MaxLoadedPolicyNameBytes is Tetragon v1.8.0's own name limit
	// (RFC 1123 DNS subdomain, apivalidation.NameIsDNSSubdomain; ADR
	// 0016), restated here as a defensive invariant: PolicyNamePattern
	// (63 bytes) plus "-v<version>-<8 hex>" never approaches it.
	MaxLoadedPolicyNameBytes = 253
)

// TetragonVersionFamily is the pinned major.minor version family internal/
// tetra's version gate (step 3 prompt Part B4) requires GetVersion to
// match exactly (any patch release, "v1.8.x"); third_party/tetragon/v1.8.0
// records the exact commit this project was built and tested against.
const TetragonVersionFamily = "1.8"

// TetragonVersionPattern matches an accepted GetVersion response: exactly
// "v1.8." followed by one or more digits (a patch release), optionally
// followed by a build-metadata/pre-release suffix Tetragon's own
// `-ldflags` version string sometimes carries (e.g. "v1.8.0-dirty" from a
// non-release build) — rejected unless the numeric patch component is
// present, so a bare "v1.8" (no patch) is also rejected as not a real
// release identifier.
var TetragonVersionPattern = regexp.MustCompile(`^v1\.8\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)

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
