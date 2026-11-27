package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/guard"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/policydoc"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/trust"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// BundleStore is what the bundle pipeline needs from internal/store:
// the epoch source and policy history verify and the guardrails read,
// the LKG the engine reads, the atomic post-APPLIED commit, and the
// tamper state (*store.Store satisfies it).
type BundleStore interface {
	verify.EpochSource
	guard.PolicyHistory
	apply.LKGStore
	CommitApplied(c store.AppliedCommit) error
	Tampered() error
}

var _ BundleStore = (*store.Store)(nil)

// Applier is the subset of *apply.Engine the apply worker drives.
type Applier interface {
	Apply(ctx context.Context, result *verify.Result) (*apply.Result, error)
}

var _ Applier = (*apply.Engine)(nil)

// VersionSource reports the running Tetragon version (verify step 10).
type VersionSource interface {
	GetVersion(ctx context.Context) (string, error)
}

// TrustState holds the current trust root. Only the apply worker changes
// it (trust updates run on the worker, between bundle verifications:
// docs/prompts/step-06b.md C2), so a verification never sees a root swap
// halfway through.
type TrustState struct {
	mu   sync.Mutex
	root *trust.Root
}

// NewTrustState returns a TrustState holding root, which must not be nil.
func NewTrustState(root *trust.Root) (*TrustState, error) {
	if root == nil {
		return nil, fmt.Errorf("agent: NewTrustState: root must not be nil")
	}
	return &TrustState{root: root}, nil
}

// Current returns the current trust root.
func (t *TrustState) Current() *trust.Root {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.root
}

// CommitOnPut is the apply.LKGStore the engine is constructed with. Get
// reads the store; Put, which the engine calls exactly once after a
// passed health window, persists the LKG together with the epoch and
// monitor history the apply worker armed for that apply, as one
// store.CommitApplied (docs/prompts/step-06b.md B1, step 4b D1). A Put
// with nothing armed is refused: only the apply worker's own applies may
// commit.
type CommitOnPut struct {
	Store BundleStore

	mu      sync.Mutex
	pending *store.AppliedCommit
	lastErr error
	done    bool
}

// Get implements apply.LKGStore.
func (c *CommitOnPut) Get(domain string) (apply.LKGSet, bool) { return c.Store.Get(domain) }

// Put implements apply.LKGStore.
func (c *CommitOnPut) Put(domain string, set apply.LKGSet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		return fmt.Errorf("agent: LKG commit with no armed apply")
	}
	commit := *c.pending
	commit.Domain = domain
	commit.Set = set
	c.lastErr = c.Store.CommitApplied(commit)
	c.done = true
	c.pending = nil
	return c.lastErr
}

func (c *CommitOnPut) arm(commit store.AppliedCommit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = &commit
	c.lastErr = nil
	c.done = false
}

// disarm clears any armed commit and reports whether Put ran since arm,
// and its error.
func (c *CommitOnPut) disarm() (committed bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = nil
	return c.done, c.lastErr
}

// BundleDeps are the bundle pipeline's real dependencies
// (docs/prompts/step-06b.md B1). None may be nil.
type BundleDeps struct {
	Store BundleStore
	// Roots persists adopted trust roots (TrustUpdate, C1).
	Roots   TrustRootStore
	Commit  *CommitOnPut
	Trust   *TrustState
	Engine  Applier
	Version VersionSource
	// HostCaps is hostprobe.Load's result for this boot (R6A-2). When
	// the facts were stale or missing, Load already returned its
	// fail-closed value, which reports no enforcement capability, so
	// G8 rejects enforce bundles with REJECTED_CAPABILITY.
	HostCaps guard.HostCapabilities
	// EnforceAllowed must be true for an enforce-mode bundle to be
	// applied: host facts are fresh for this boot and the usrmerge
	// invariant held at probe time (hostprobe.Capabilities.UsrmergeOK).
	// Guardrail G8 only gates Override; this gates every enforcement
	// action, so stale or missing facts reject every enforce bundle with
	// REJECTED_CAPABILITY (docs/prompts/step-06b.md B1). Its zero value
	// rejects.
	EnforceAllowed bool
	Crypto         Capabilities
	HostUUID       string
	AllowedScopes  []string
	// Digest returns architecture doc 6.4's loaded digest (the same
	// value Heartbeat carries), for ApplyResult.loaded_digest_after.
	Digest func(ctx context.Context) ([]byte, error)
}

func (d BundleDeps) validate() error {
	switch {
	case d.Store == nil, d.Roots == nil, d.Commit == nil, d.Trust == nil, d.Engine == nil, d.Version == nil, d.HostCaps == nil, d.Digest == nil:
		return fmt.Errorf("agent: BundleDeps: every dependency must be set")
	case d.HostUUID == "":
		return fmt.Errorf("agent: BundleDeps: HostUUID must be set")
	}
	return nil
}

type policydocParser struct{}

func (policydocParser) Parse(name, yamlDoc string) (*policydoc.Doc, error) {
	return policydoc.Parse(name, yamlDoc)
}

// verifierFor returns the targets verifier of root at now, or a typed
// reason it cannot (expired metadata; a role requiring mldsa-87 on a
// build whose self-test found ML-DSA unavailable, R4A-3/R4B-6, named
// explicitly rather than surfacing as an opaque signature failure).
func verifierFor(root *trust.Root, caps Capabilities, now time.Time) (trust.Verifier, string) {
	if !caps.MLDSAAvailable && rootRequiresMLDSA(root) {
		return nil, "trust root requires ML-DSA, unavailable in this build"
	}
	v, err := root.TargetsVerifier(now)
	if err != nil {
		if errors.Is(err, trust.ErrRootMetadataExpired) {
			return nil, "trust root metadata has expired"
		}
		return nil, "no usable targets verifier"
	}
	return v, ""
}

// verifyBundle runs architecture doc 7.4 on envelope with the real
// dependencies.
func verifyBundle(ctx context.Context, d BundleDeps, envelope []byte, now time.Time) verify.Result {
	root := d.Trust.Current()
	verifier, why := verifierFor(root, d.Crypto, now)
	if verifier == nil {
		return verify.Result{Code: verify.CodeRejectedSignature, Reason: why}
	}
	tv, err := d.Version.GetVersion(ctx)
	if err != nil {
		// An unknown running version cannot satisfy verify step 10.
		tv = ""
	}
	// Tetragon's GetVersion reports "v1.8.0" (internal/tetra's version
	// gate, limits.TetragonVersionPattern); verify compares bare
	// semantic versions. Exactly one leading "v" is removed; anything
	// else that is not a semantic version still fails step 10.
	tv = strings.TrimPrefix(tv, "v")
	return verify.Verify(verify.Input{
		Envelope:        envelope,
		Now:             now,
		HostUUID:        d.HostUUID,
		AllowedScopes:   d.AllowedScopes,
		TetragonVersion: tv,
		Trust:           verifier,
		RootVersion:     root.Version,
		Epochs:          d.Store,
		PolicyParser:    policydocParser{},
		Guardrails:      &guard.Guardrails{Capabilities: d.HostCaps, History: d.Store},
	})
}

// verifyCodeToStatus maps a verify rejection code to ApplyResult.Status.
func verifyCodeToStatus(c verify.Code) controlv1.ApplyResult_Status {
	switch c { //nolint:exhaustive // CodeAccept never reaches here; schema and any unknown code map to REJECTED_SCHEMA
	case verify.CodeRejectedSignature:
		return controlv1.ApplyResult_REJECTED_SIGNATURE
	case verify.CodeRejectedTarget:
		return controlv1.ApplyResult_REJECTED_TARGET
	case verify.CodeRejectedEpoch:
		return controlv1.ApplyResult_REJECTED_EPOCH
	case verify.CodeRejectedExpired:
		return controlv1.ApplyResult_REJECTED_EXPIRED
	case verify.CodeRejectedGuardrail:
		return controlv1.ApplyResult_REJECTED_GUARDRAIL
	case verify.CodeRejectedCapability:
		return controlv1.ApplyResult_REJECTED_CAPABILITY
	default:
		return controlv1.ApplyResult_REJECTED_SCHEMA
	}
}

// bundleDigest is ApplyResult.bundle_digest: SHA-256 of the exact
// envelope bytes received (control.proto PolicyBundle.envelope).
func bundleDigest(envelope []byte) []byte {
	sum := sha256.Sum256(envelope)
	return sum[:]
}

// boundDetail truncates s to limits.MaxApplyResultDetailBytes without
// splitting a rune.
func boundDetail(s string) string { return truncateUTF8(s, limits.MaxApplyResultDetailBytes) }

func applyResultMessage(r *controlv1.ApplyResult) *controlv1.AgentMessage {
	r.Detail = boundDetail(r.Detail)
	return &controlv1.AgentMessage{Body: &controlv1.AgentMessage_ApplyResult{ApplyResult: r}}
}
