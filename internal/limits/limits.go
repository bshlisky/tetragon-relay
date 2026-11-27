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

	// MaxRootMetadataBytes bounds a trust-root DSSE envelope. Raised from
	// 64 KiB to 256 KiB in step 4 Part B4 for ML-DSA-87 (FIPS 204)
	// support: an ML-DSA-87 public key's base64-encoded SPKI DER is
	// ~3.5 KiB and its signature ~6.2 KiB, both far larger than ECDSA
	// P-384's equivalents (~0.16 KiB and ~0.14 KiB) — see
	// docs/decisions/0002-root-metadata-size-cap.md's amendment for the
	// full worst-case arithmetic (16 ML-DSA-87 signatures plus a hybrid
	// key set).
	MaxRootMetadataBytes = 256 << 10 // 256 KiB

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

	// HealthWindowDeadlineTolerance bounds how early a stream timeout
	// (tetra.ErrTimeout, on either runHealthWindow select branch that
	// observes one) may be treated as "the health window's own deadline
	// arrived" rather than a real, independent timeout from Tetragon
	// (step-03b-review.md R3B-2). A timeout observed with more than this
	// much of the window still remaining is never the window's own
	// GetEvents(windowCtx, ...) deadline — internal/tetra.GetEvents
	// applies windowCtx directly with no shorter timeout of its own
	// (Part B3) — so treating it as "the window completed" would let a
	// misbehaving or compromised Tetragon shorten a 60s window to
	// seconds without the health check ever noticing.
	HealthWindowDeadlineTolerance = 2 * time.Second

	// MaxLoadedPolicyNameBytes is Tetragon v1.8.0's own name limit
	// (RFC 1123 DNS subdomain, apivalidation.NameIsDNSSubdomain; ADR
	// 0016), restated here as a defensive invariant: PolicyNamePattern
	// (63 bytes) plus "-v<version>-<8 hex>" never approaches it.
	MaxLoadedPolicyNameBytes = 253

	// --- Step 4b: internal/store (step-04b.md Part C8) ---

	// MaxStoreIndexBytes bounds the serialized size of internal/store's
	// index file (everything except the content-addressed blobs/ it
	// references: epochs, monitor history, LKG/root blob references,
	// generation). Chosen generously relative to MaxStoreScopes *
	// (MaxStoreHistoryNamesPerScope * (PolicyNamePattern's 63 bytes) +
	// a domain name and a few blob digests each) so a legitimately
	// busy fleet of scopes/domains never approaches it, while still
	// bounding memory for a single JSON unmarshal of untrusted (if
	// tampered) disk content before any HMAC check can run.
	MaxStoreIndexBytes = 4 << 20 // 4 MiB

	// MaxStoreScopes bounds the number of distinct policy scopes (each
	// with its own epoch and monitor-mode history) the index may track.
	// A single host serves a small, fixed set of scopes (architecture
	// doc section 7.3's "scope" field); this is a defensive cap against
	// an index inflated by a bug or a tampered disk, not a realistic
	// production ceiling.
	MaxStoreScopes = 256

	// MaxStoreHistoryNamesPerScope bounds the number of distinct policy
	// names recorded as "seen in monitor mode" per scope
	// (guard.PolicyHistory). Bounded independently of
	// MaxPoliciesPerBundle because history accumulates across many
	// bundles over the scope's lifetime, not just one.
	MaxStoreHistoryNamesPerScope = 4096

	// MaxStoreBlobBytes bounds a single content-addressed blob (an LKG
	// DSSE-derived envelope or trust-root metadata). Mirrors
	// MaxEnvelopeBytes/MaxRootMetadataBytes, the largest inputs that
	// ever become a blob, with headroom for the store's own minimal
	// framing.
	MaxStoreBlobBytes = 2 << 20 // 2 MiB

	// MaxRevokedReasonBytes bounds the reason text in internal/store's
	// persisted REVOKED marker (docs/reviews/step-06a-e3-decisions.md
	// D2). internal/agent truncates the controller's Terminate detail to
	// fit; the store rejects anything longer, on write and on load.
	MaxRevokedReasonBytes = 256

	// MaxStoreTotalBlobBytes bounds the sum of every live (referenced)
	// blob's size: one LKG blob per domain plus one trust-root blob,
	// each at most MaxStoreBlobBytes, times a generous fixed number of
	// domains, so unbounded domain churn cannot grow the store
	// directory without limit even though old blobs are garbage
	// collected after every successful index swap.
	MaxStoreTotalBlobBytes = 64 << 20 // 64 MiB

	// MaxStoreDomains bounds the number of distinct relay domains
	// (apply.LKGStore keys) the index may track, for the same reason as
	// MaxStoreScopes.
	MaxStoreDomains = 256

	// MaxStoreRootHistoryVersions bounds the number of distinct trust
	// root versions internal/store keeps a live blob for simultaneously
	// (ADR 0025 / step-04b-review.md R4B-2: a root rotation does not
	// retroactively re-verify every domain's existing LKG, so an LKG's
	// recorded root version can be older than the current one).
	// commitLocked prunes this to exactly the currently-referenced set
	// on every write, so in practice it is bounded by MaxStoreDomains
	// (at most one distinct historical version per domain) plus one for
	// the current root; set generously above that so a legitimate,
	// fully-diverse fleet of domain root versions is never the thing
	// that trips this cap.
	MaxStoreRootHistoryVersions = 512

	// --- step-04b-review.md R4B-1: forward root chaining ---

	// MaxRootChainFiles bounds both the number of RPM-shipped
	// versioned root files (internal/agent.Config.AvailableRPMRoots)
	// Startup will consider, and (transitively, since each file can
	// advance the chain by at most one version) the number of
	// trust.Root.Update steps a single Startup call will walk through.
	// A legitimate fleet rotates its root key set on the order of a
	// handful of times a year at most (architecture doc section 7.6:
	// 365-day root metadata expiry); 64 is generous headroom over any
	// plausible number of versions a host could realistically fall
	// behind by, while still bounding the work a maliciously large
	// roots/ directory (or a caller bug) could force onto one Startup
	// call.
	MaxRootChainFiles = 64

	// MaxControlMessageBytes is the gRPC message size cap internal/
	// controlclient enforces on the control channel (architecture doc
	// 6.1: "Max frame 1 MiB"). Applied as both the max receive and max
	// send size on the client's single AgentControl.Connect stream, so a
	// malicious or malfunctioning controller cannot force the agent to
	// buffer an unbounded message, and the agent itself never sends one.
	MaxControlMessageBytes = 1 << 20 // 1 MiB

	// ControlKeepaliveInterval is the control channel's HTTP/2 PING
	// keepalive interval (architecture doc 6.1: "every 30 s").
	ControlKeepaliveInterval = 30 * time.Second
	// ControlKeepaliveTimeout is the control channel's HTTP/2 PING
	// keepalive timeout (architecture doc 6.1: "timeout 10 s").
	ControlKeepaliveTimeout = 10 * time.Second

	// ControlDialBackoffBase is the control channel's reconnect backoff
	// base (architecture doc 6.3 step 6: "full-jitter exponential
	// backoff (1 s base, 5 min cap)").
	ControlDialBackoffBase = 1 * time.Second
	// ControlDialBackoffCap is the control channel's reconnect backoff
	// cap (architecture doc 6.3 step 6).
	ControlDialBackoffCap = 5 * time.Minute

	// --- step-06a: internal/config (relay.yaml) ---

	// MaxConfigFileBytes bounds the size of relay.yaml internal/config
	// will read, before any parsing happens. A legitimate config is a
	// few hundred bytes to a few KiB (architecture doc 8.6's example);
	// this is a defensive cap against an operator error or a tampered
	// file forcing an unbounded read/parse, not a realistic ceiling.
	MaxConfigFileBytes = 1 << 20 // 1 MiB

	// MaxConfigFileMode is the most permissive mode internal/config
	// will accept for relay.yaml (architecture doc 8.5's filesystem
	// table: "root:tetragon-relay, 0640"). A mode with any bit set
	// outside this is refused, never silently masked.
	MaxConfigFileMode = 0o640

	// DefaultHeartbeatInterval is controller.heartbeat_interval's
	// default when relay.yaml omits it (architecture doc 6.3 step 5:
	// "Heartbeat every 15 s").
	DefaultHeartbeatInterval = 15 * time.Second

	// DefaultCollectorSpoolMaxBytes is collector.spool_max_bytes's
	// default (architecture doc 8.6's example: 2147483648, 2 GiB).
	DefaultCollectorSpoolMaxBytes = 2 * (1 << 30)
	// DefaultCollectorBatchMaxEvents is collector.batch_max_events's
	// default (architecture doc 8.6's example).
	DefaultCollectorBatchMaxEvents = 2000
	// DefaultCollectorBatchMaxAge is collector.batch_max_age's default
	// (architecture doc 8.6's example).
	DefaultCollectorBatchMaxAge = 2 * time.Second

	// ControlConnectDegradedTimeout is architecture doc 8.4's DEGRADED
	// row, first entry condition: "No controller for > 5 min" --
	// EventConnectTimeout fires once a session has gone this long
	// without completing Hello/HelloAck (step-06a-resume.md D3).
	ControlConnectDegradedTimeout = 5 * time.Minute

	// ControlConnectAttemptTimeout bounds one RealConnector.Connect
	// attempt end to end (Dial through TLS through Hello/HelloAck;
	// step-06a-e3-prompt.md R6A-4). Without it, a Connect attempt stuck
	// anywhere in that sequence (a network black hole during the TCP/TLS
	// handshake, or a controller that accepts the stream but never
	// answers Hello) never returns, yet RunSession's own liveness touches
	// (connectWithDegradedWatch's touchTicker) keep reporting progress
	// regardless, so the watchdog never notices. Well under
	// sessionLivenessMaxInterval (20 s, internal/agent) so a timed-out
	// attempt, its backoff delay and the next attempt's own timeout all
	// fit comfortably inside one liveness window with margin to spare.
	ControlConnectAttemptTimeout = 8 * time.Second

	// --- internal/agent: step 6b's apply worker and outbox ---

	// MaxOutboxMessages bounds the queue of ApplyResult and Alert
	// messages the agent holds for the control stream, including while
	// it is disconnected (docs/prompts/step-06b.md E1: "a bounded queue
	// (oldest dropped, with a counter)"). One apply runs at a time and
	// each alert kind is rate-limited to one per 5 minutes, so even a
	// day-long outage produces far fewer distinct messages than this;
	// the bound exists so a misbehaving component cannot grow memory
	// without limit.
	MaxOutboxMessages = 64

	// AlertRateLimitInterval is the per-kind Alert rate limit: at most
	// one Alert of each kind per this interval, except the first (docs/prompts/step-06b.md E1).
	AlertRateLimitInterval = 5 * time.Minute

	// MaxPendingTrustUpdates bounds TrustUpdate messages held for the
	// apply worker while a bundle apply runs. Each carries a whole
	// chain (N+1..M) and the controller resends trust metadata on every
	// reconcile (architecture doc 6.3 step 4), so a handful suffices.
	MaxPendingTrustUpdates = 4

	// TrustExpiredAlertInterval is how often Alert TRUST_EXPIRED repeats
	// while the trust root stays expired, besides once per connection
	// (docs/prompts/step-06b.md C3: "daily").
	TrustExpiredAlertInterval = 24 * time.Hour

	// MaxApplyResultDetailBytes bounds ApplyResult.detail and
	// Alert.detail (control.proto: "bounded 4 KiB, no secrets").
	MaxApplyResultDetailBytes = 4096

	// ApplyWorkerLivenessSlack is how long past the configured health
	// window the apply worker keeps reporting liveness while one apply
	// is running. Apply's own Tetragon calls (add, confirm, delete,
	// persist, rollback) take seconds; an apply still running this long
	// after its health window should have ended is stalled, so the
	// worker stops touching liveness and systemd's watchdog restarts
	// relayd (step-06b report, section 11).
	ApplyWorkerLivenessSlack = 120 * time.Second

	// --- internal/audit: architecture doc 8.3's `audit` module ---

	// MaxAuditFieldBytes bounds each individual string field (Step,
	// Detail, Err, Domain, Policy) of a single audit.Event before it is
	// marshaled. A legitimate field is a short identifier or a brief
	// human-readable message (MaxReasonBytes-ish, with headroom for a
	// wrapped error chain's own text); this is a defensive cap against
	// a caller accidentally (or a compromised component deliberately)
	// stuffing a large payload -- e.g. an envelope or policy YAML --
	// into what is supposed to be a short descriptive field.
	MaxAuditFieldBytes = 512
	// MaxAuditLineBytes bounds the total length of one marshaled JSON
	// audit line (every field above, plus JSON structure/escaping
	// overhead and the timestamp). Generous headroom over
	// 5*MaxAuditFieldBytes plus overhead, so legitimate records are
	// never truncated at the line level in practice; MaxAuditFieldBytes
	// is the cap that actually bites.
	MaxAuditLineBytes = 4096

	// DefaultIdentityKeyRotation is identity.key_rotation's default
	// when relay.yaml omits it. Intentionally the same value as
	// internal/identity.DefaultRotationInterval (architecture doc
	// 5.4's host key rotation cadence, 7 days): duplicated rather than
	// imported so internal/config stays decoupled from internal/identity
	// (the same "duplicate a small constant instead of adding an
	// import" convention internal/tetra's HostSELinuxEnforcing/
	// HostSELinuxPermissive constants already use relative to
	// internal/hostprobe).
	DefaultIdentityKeyRotation = 7 * 24 * time.Hour
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
