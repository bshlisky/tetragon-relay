package apply

import (
	"context"
	"fmt"
	"sync"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"

	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// Status is Result's outcome, matching architecture doc section 7.7
// step 7/8's vocabulary.
type Status int

const (
	// StatusApplied means the bundle was loaded and its health window
	// passed; LKG was updated.
	StatusApplied Status = iota
	// StatusRolledBack means the health window failed and the LKG set
	// was successfully re-asserted (Part D5/D6).
	StatusRolledBack
	// StatusApplyFailed is APPLY_FAILED (Part D3): adding/confirming the
	// bundle failed, and this attempt's own additions were cleaned up;
	// the previously loaded (LKG) set was never touched.
	StatusApplyFailed
	// StatusRollbackFailed is ROLLBACK_FAILED (Part D6): the health
	// window failed AND re-asserting LKG itself failed.
	StatusRollbackFailed
)

func (s Status) String() string {
	switch s {
	case StatusApplied:
		return "APPLIED"
	case StatusRolledBack:
		return "ROLLED_BACK"
	case StatusApplyFailed:
		return "APPLY_FAILED"
	case StatusRollbackFailed:
		return "ROLLBACK_FAILED"
	default:
		return "UNKNOWN"
	}
}

// Result is Apply's outcome (step 3 prompt Part D).
type Result struct {
	Status Status
	// ModeMechanism records which mechanism produced the loaded mode
	// (Part D2); always "action-rewrite" per ADR 0016.
	ModeMechanism string
	// Digest is internal/apply.Digest's value after a successful apply
	// or rollback (empty if the engine could not even list policies
	// afterward).
	Digest string
	Detail string
}

const modeMechanismActionRewrite = "action-rewrite"

// Config configures an Engine.
type Config struct {
	// Domain is the relay-managed marker (Part D1); defaults to
	// RelayDomain if empty.
	Domain string
	// PersistDir is where PersistDir writes the loaded set (Part D4);
	// defaults to "/etc/tetragon/tetragon.tp.d/relay" if empty.
	PersistDir string
	// PersistUID/PersistGID are the owner PersistDir's files are
	// written with (architecture doc 8.5: root:tetragon-relay).
	PersistUID, PersistGID int
	HealthWindow           HealthWindowConfig
}

func (c Config) domain() string {
	if c.Domain == "" {
		return RelayDomain
	}
	return c.Domain
}

func (c Config) persistDir() string {
	if c.PersistDir == "" {
		return "/etc/tetragon/tetragon.tp.d/relay"
	}
	return c.PersistDir
}

// Engine implements step 3 prompt Part D. One Engine serves one Tetragon
// connection/domain.
type Engine struct {
	client       TetragonClient
	parser       PolicyParser
	lkg          LKGStore
	reachability ReachabilityChecker
	auditor      Auditor
	cfg          Config

	mu sync.Mutex // Part D7: single-flight
}

// NewEngine constructs an Engine. None of client, parser, lkg,
// reachability, or auditor may be nil.
func NewEngine(client TetragonClient, parser PolicyParser, lkg LKGStore, reachability ReachabilityChecker, auditor Auditor, cfg Config) *Engine {
	return &Engine{client: client, parser: parser, lkg: lkg, reachability: reachability, auditor: auditor, cfg: cfg}
}

// resolvedPolicy is one bundle policy after D1 (loaded name) and D2 (mode
// rewrite), ready to send to Tetragon and to persist.
type resolvedPolicy struct {
	baseName   string
	loadedName string
	// finalJSON is sent to Tetragon and persisted: mode-rewritten (if
	// monitor) AND with metadata.name set to loadedName.
	finalJSON []byte
	// preNameJSON is finalJSON's content before the metadata.name
	// rewrite (still mode-rewritten): this, not finalJSON, is what gets
	// stored in the LKG set, so that re-deriving LoadedName from stored
	// LKG content (rollback, Reconcile) reproduces the exact same hash
	// LoadedName originally computed — computing it from finalJSON
	// instead would hash content that already has the *previous*
	// loadedName baked into metadata.name, silently producing a
	// different loaded name every time the set is re-asserted.
	preNameJSON []byte
}

// resolve implements Parts D1/D2 for every policy in bundle.
func (e *Engine) resolve(bundle *verify.Bundle) ([]resolvedPolicy, error) {
	out := make([]resolvedPolicy, 0, len(bundle.Policies))
	for _, p := range bundle.Policies {
		doc, err := e.parser.Parse(p.Name, p.YAML)
		if err != nil {
			return nil, fmt.Errorf("apply: re-parse policy %q: %w", p.Name, err)
		}
		canonicalJSON := doc.CanonicalJSON()

		finalJSON := canonicalJSON
		if bundle.Mode == "monitor" {
			rewritten, err := rewriteActionsToPost(canonicalJSON)
			if err != nil {
				return nil, fmt.Errorf("apply: rewrite actions for %q: %w", p.Name, err)
			}
			finalJSON = rewritten
		}

		loadedName, err := LoadedName(p.Name, p.Version, finalJSON)
		if err != nil {
			return nil, fmt.Errorf("apply: compute loaded name for %q: %w", p.Name, err)
		}
		named, err := setMetadataName(finalJSON, loadedName)
		if err != nil {
			return nil, fmt.Errorf("apply: set metadata.name for %q: %w", p.Name, err)
		}
		out = append(out, resolvedPolicy{baseName: p.Name, loadedName: loadedName, finalJSON: named, preNameJSON: finalJSON})
	}
	return out, nil
}

// existingManaged lists every relay-managed policy currently loaded,
// keyed by its base (bundle) policy name (Part D1's isRelayManaged gate).
func (e *Engine) existingManaged(ctx context.Context) (map[string]string, error) {
	statuses, err := e.client.ListTracingPolicies(ctx, e.cfg.domain())
	if err != nil {
		return nil, fmt.Errorf("apply: list tracing policies: %w", err)
	}
	out := make(map[string]string)
	for _, s := range statuses {
		if !isRelayManaged(s.Name, s.Domain) {
			continue
		}
		baseName, _, _, ok := parseLoadedName(s.Name)
		if !ok {
			continue
		}
		out[baseName] = s.Name
	}
	return out, nil
}

// Apply implements step 3 prompt Part D end to end.
func (e *Engine) Apply(ctx context.Context, result *verify.Result) (*Result, error) {
	if !e.mu.TryLock() {
		return nil, ErrApplyInProgress
	}
	defer e.mu.Unlock()

	if result == nil || result.Code != verify.CodeAccept || result.Bundle == nil {
		return nil, ErrNotAccepted
	}
	bundle := result.Bundle

	if _, err := e.client.RequireVersion(ctx); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedTetragonVersion, err)
	}

	resolved, err := e.resolve(bundle)
	if err != nil {
		return nil, err
	}

	existing, err := e.existingManaged(ctx)
	if err != nil {
		return nil, err
	}

	var additions []resolvedPolicy
	desiredLoadedNames := make(map[string]bool, len(resolved))
	for _, r := range resolved {
		desiredLoadedNames[r.loadedName] = true
		if existing[r.baseName] != r.loadedName {
			additions = append(additions, r)
		}
	}
	var removals []string
	for baseName, loadedName := range existing {
		if desiredLoadedNames[loadedName] {
			continue
		}
		_ = baseName
		removals = append(removals, loadedName)
	}

	e.audit("apply_plan", fmt.Sprintf("additions=%d removals=%d", len(additions), len(removals)), nil, "")

	added, err := e.addAll(ctx, additions)
	if err != nil {
		e.deleteAll(ctx, resolvedNames(added)) // Part D3: undo only what this attempt added
		e.audit("apply_add_failed", err.Error(), err, "")
		return &Result{Status: StatusApplyFailed, Detail: err.Error()}, ErrApplyFailed
	}

	if err := e.confirmLoaded(ctx, added); err != nil {
		e.deleteAll(ctx, resolvedNames(added))
		e.audit("apply_confirm_failed", err.Error(), err, "")
		return &Result{Status: StatusApplyFailed, Detail: err.Error()}, ErrApplyFailed
	}

	// Removals happen only after every addition is confirmed.
	removeFailures := e.deleteAll(ctx, removals)

	if err := e.persist(resolved); err != nil {
		e.audit("apply_persist_failed", err.Error(), err, "")
		// Non-fatal for APPLIED status (Tetragon itself is already
		// correctly loaded via gRPC); a lost persist only affects
		// reload-on-restart, not current enforcement.
	}

	loadedNames := make([]string, 0, len(resolved))
	for _, r := range resolved {
		loadedNames = append(loadedNames, r.loadedName)
	}
	reason, healthy := runHealthWindow(ctx, e.client, e.reachability, e.cfg.HealthWindow, loadedNames)
	if !healthy {
		e.audit("health_window_failed", string(reason), nil, "")
		return e.rollback(ctx, string(reason))
	}

	if err := e.lkg.Put(e.cfg.domain(), bundleToLKG(result, resolved)); err != nil {
		e.audit("lkg_put_failed", err.Error(), err, "")
	}

	digest, _ := e.currentDigest(ctx)
	detail := modeMechanismActionRewrite
	if len(removeFailures) > 0 {
		detail = fmt.Sprintf("%s; %d removal(s) failed and remain loaded (harmless; Reconcile will retry)", detail, len(removeFailures))
	}
	e.audit("applied", detail, nil, "")
	return &Result{Status: StatusApplied, ModeMechanism: modeMechanismActionRewrite, Digest: digest, Detail: detail}, nil
}

// ResolveLKGSet rebuilds the LKGSet a successful Apply would persist for
// bundle, using ONLY bundle's own already-schema-validated content and
// parser — no Tetragon calls, no loaded-name computation (Tetragon's
// loaded names are irrelevant to what gets persisted as LKG content).
// ADR 0025 (step-04b-review.md R4B-2): internal/agent uses this at
// startup to re-derive a domain's LKGSet from a fresh re-parse of its own
// persisted RawEnvelope and compare it against the cached Policies/Mode,
// so any divergence between the two (evidence of tampering, since both
// are supposed to have been produced from the exact same bytes) is
// detected. Mirrors resolve()+bundleToLKG's content-shaping exactly
// (parse, then rewrite actions to Post for monitor mode) but without the
// loaded/final-name rewriting step, which is operational-only and not
// part of what is compared.
func ResolveLKGSet(bundle *verify.Bundle, parser PolicyParser) (LKGSet, error) {
	if bundle == nil {
		return LKGSet{}, fmt.Errorf("apply: ResolveLKGSet: nil bundle")
	}
	if parser == nil {
		return LKGSet{}, fmt.Errorf("apply: ResolveLKGSet: nil PolicyParser")
	}
	set := LKGSet{Mode: bundle.Mode}
	for _, p := range bundle.Policies {
		doc, err := parser.Parse(p.Name, p.YAML)
		if err != nil {
			return LKGSet{}, fmt.Errorf("apply: re-parse policy %q: %w", p.Name, err)
		}
		finalJSON := doc.CanonicalJSON()
		if bundle.Mode == "monitor" {
			rewritten, err := rewriteActionsToPost(finalJSON)
			if err != nil {
				return LKGSet{}, fmt.Errorf("apply: rewrite actions for %q: %w", p.Name, err)
			}
			finalJSON = rewritten
		}
		set.Policies = append(set.Policies, LKGPolicy{Name: p.Name, Version: p.Version, CanonicalJSON: finalJSON})
	}
	return set, nil
}

// bundleToLKG builds the LKGSet persisted after a successful apply.
// result's Bundle supplies the parsed/operational fields (unchanged from
// before ADR 0025); result's RawEnvelope/RootVersion (populated by
// verify.Verify on CodeAccept) are carried through unaltered, the
// architecture-specified integrity-bearing artifact this step adds.
func bundleToLKG(result *verify.Result, resolved []resolvedPolicy) LKGSet {
	bundle := result.Bundle
	byName := make(map[string][]byte, len(resolved))
	for _, r := range resolved {
		// preNameJSON, not finalJSON: see resolvedPolicy's doc comment.
		byName[r.baseName] = r.preNameJSON
	}
	set := LKGSet{Mode: bundle.Mode, RawEnvelope: result.RawEnvelope, RootVersion: result.RootVersion}
	for _, p := range bundle.Policies {
		set.Policies = append(set.Policies, LKGPolicy{Name: p.Name, Version: p.Version, CanonicalJSON: byName[p.Name]})
	}
	return set
}

func (e *Engine) addAll(ctx context.Context, additions []resolvedPolicy) ([]resolvedPolicy, error) {
	var added []resolvedPolicy
	for _, a := range additions {
		if err := e.client.AddTracingPolicy(ctx, string(a.finalJSON), e.cfg.domain()); err != nil {
			return added, fmt.Errorf("add %s: %w", a.loadedName, err)
		}
		added = append(added, a)
	}
	return added, nil
}

// confirmLoaded implements Part D3: after adds, every addition must show
// up via ListTracingPolicies in state TP_STATE_ENABLED exactly (reject
// more: TP_STATE_PARTIALLY_ENABLED means some hooks were not loaded, which
// is still an enforcement gap for part of that policy, so it does not
// count as success here — docs/reports/step-03.md section 14).
func (e *Engine) confirmLoaded(ctx context.Context, added []resolvedPolicy) error {
	if len(added) == 0 {
		return nil
	}
	statuses, err := e.client.ListTracingPolicies(ctx, e.cfg.domain())
	if err != nil {
		return fmt.Errorf("confirm: list tracing policies: %w", err)
	}
	byName := make(map[string]tetragonpb.TracingPolicyState, len(statuses))
	for _, s := range statuses {
		byName[s.Name] = s.State
	}
	for _, a := range added {
		state, ok := byName[a.loadedName]
		if !ok {
			return fmt.Errorf("confirm: %s not present in ListTracingPolicies", a.loadedName)
		}
		if state != tetragonpb.TracingPolicyState_TP_STATE_ENABLED {
			return fmt.Errorf("confirm: %s is in state %s, want TP_STATE_ENABLED", a.loadedName, state)
		}
	}
	return nil
}

// deleteAll deletes every named loaded policy, continuing past individual
// failures (used both for Part D3's "delete only what this attempt added"
// cleanup and for ordinary removals), and returns the names that failed to
// delete.
func (e *Engine) deleteAll(ctx context.Context, names []string) []string {
	var failed []string
	for _, n := range names {
		if err := e.client.DeleteTracingPolicy(ctx, n, e.cfg.domain()); err != nil {
			failed = append(failed, n)
			e.audit("delete_failed", err.Error(), err, n)
		}
	}
	return failed
}

// resolvedNames extracts the loaded names from a []resolvedPolicy, for
// callers of deleteAll.
func resolvedNames(rs []resolvedPolicy) []string {
	names := make([]string, 0, len(rs))
	for _, r := range rs {
		names = append(names, r.loadedName)
	}
	return names
}

func (e *Engine) persist(resolved []resolvedPolicy) error {
	policies := make([]PersistedPolicy, 0, len(resolved))
	for _, r := range resolved {
		policies = append(policies, PersistedPolicy{LoadedName: r.loadedName, CanonicalJSON: r.finalJSON})
	}
	return PersistDir(e.cfg.persistDir(), policies, e.cfg.PersistUID, e.cfg.PersistGID)
}

func (e *Engine) currentDigest(ctx context.Context) (string, error) {
	statuses, err := e.client.ListTracingPolicies(ctx, e.cfg.domain())
	if err != nil {
		return "", err
	}
	return Digest(statuses), nil
}

func (e *Engine) audit(step, detail string, err error, policy string) {
	e.auditor.Record(AuditEvent{Step: step, Detail: detail, Err: err, Domain: e.cfg.domain(), Policy: policy})
}
