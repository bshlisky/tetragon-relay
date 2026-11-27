package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/apply"
)

// Tampered mode (ADR 0038; docs/reviews/step-06b-review.md R6B-5). When
// the store is found TAMPERED at startup, relayd does not exit. It
// connects with its identity as it is, reports the tamper, and otherwise
// changes nothing:
//
//   - it never writes to Tetragon (no apply, reconcile, rollback or
//     re-assert): there is no apply engine or reconcile scheduler;
//   - it never writes to the store, except a best-effort REVOKED marker
//     on Terminate{REVOKED};
//   - every PolicyBundle gets REJECTED_TAMPERED and every TrustUpdate
//     raises TRUST_UPDATE_REJECTED (TamperedJobs);
//   - Hello, Heartbeat and StateReport carry live loaded_digest and
//     health and an EMPTY epochs map (TamperedSnapshotProvider), which
//     the controller can tell apart from "every epoch is zero" because a
//     normal agent always reports one entry per allowed scope;
//   - the REVOKED marker is unknown, not "not revoked": it is never read;
//   - RotateIdentity is refused (the identity is used as it is).

// tamperedBundleDetail is ApplyResult.detail for every bundle in tampered
// mode.
const tamperedBundleDetail = "store TAMPERED at startup: tampered mode, every bundle is rejected until operator re-enrollment"

// tamperedTrustDetail is Alert.detail for every TrustUpdate in tampered
// mode.
const tamperedTrustDetail = "store TAMPERED at startup: tampered mode, every trust update is rejected until operator re-enrollment"

// TamperedJobs is the ControlLoop's JobSink in tampered mode. It answers
// at once and never verifies, applies or persists anything.
type TamperedJobs struct {
	outbox  *Outbox
	alerter *Alerter
	auditor Auditor
}

var _ JobSink = (*TamperedJobs)(nil)

// NewTamperedJobs returns a TamperedJobs. No argument may be nil.
func NewTamperedJobs(outbox *Outbox, alerter *Alerter, auditor Auditor) (*TamperedJobs, error) {
	if outbox == nil || alerter == nil || auditor == nil {
		return nil, fmt.Errorf("agent: NewTamperedJobs: outbox, alerter and auditor must not be nil")
	}
	return &TamperedJobs{outbox: outbox, alerter: alerter, auditor: auditor}, nil
}

// SubmitBundle answers the bundle with REJECTED_TAMPERED. The envelope is
// only hashed for bundle_digest; it is never parsed.
func (j *TamperedJobs) SubmitBundle(envelope []byte) {
	digest := bundleDigest(envelope)
	j.auditor.Record(AuditEvent{Step: "bundle_rejected", Detail: fmt.Sprintf("bundle %x: %s", digest, tamperedBundleDetail)})
	j.outbox.Push(applyResultMessage(&controlv1.ApplyResult{
		BundleDigest: digest,
		Status:       controlv1.ApplyResult_REJECTED_TAMPERED,
		Detail:       tamperedBundleDetail,
	}))
}

// SubmitTrustUpdate raises TRUST_UPDATE_REJECTED; nothing is adopted.
func (j *TamperedJobs) SubmitTrustUpdate(signedRoots [][]byte) {
	j.auditor.Record(AuditEvent{Step: "trust_update_rejected", Detail: fmt.Sprintf("%d root(s): %s", len(signedRoots), tamperedTrustDetail)})
	j.alerter.Raise(controlv1.Alert_TRUST_UPDATE_REJECTED, tamperedTrustDetail)
}

// TamperedConnected returns the RunSession OnConnected hook for tampered
// mode: Alert{TAMPER} after every HelloAck (subject to the per-kind rate
// limit; the first is always sent). The Outbox is drained right after
// HelloAck, so the alert goes out before the first heartbeat.
func TamperedConnected(alerter *Alerter, tamperErr error) func() {
	detail := "store TAMPERED at startup; tampered mode (no Tetragon or store writes, every bundle and trust update rejected)"
	if tamperErr != nil {
		detail += ": " + tamperErr.Error()
	}
	return func() { alerter.Raise(controlv1.Alert_TAMPER, detail) }
}

// TamperedSnapshotProvider is the SnapshotProvider in tampered mode: the
// loaded digest, policies and health come from Tetragon as usual; there
// is no store, so the epochs map is empty and there is no LKG digest.
type TamperedSnapshotProvider struct {
	Client snapshotTetragonClient
}

// Snapshot implements SnapshotProvider.
func (p *TamperedSnapshotProvider) Snapshot(ctx context.Context) (StateSnapshot, error) {
	if p.Client == nil {
		return StateSnapshot{}, fmt.Errorf("agent: tampered snapshot: no Tetragon client")
	}
	snap, err := tetragonSnapshot(ctx, p.Client)
	if err != nil {
		return StateSnapshot{}, err
	}
	snap.Epochs = map[string]uint64{}
	return snap, nil
}

// tetragonSnapshot is the part of a StateSnapshot that comes from
// Tetragon alone: loaded digest (architecture doc 6.4), policies and
// health.
func tetragonSnapshot(ctx context.Context, client snapshotTetragonClient) (StateSnapshot, error) {
	statuses, err := client.ListTracingPolicies(ctx, "")
	if err != nil {
		return StateSnapshot{}, fmt.Errorf("agent: snapshot: ListTracingPolicies: %w", err)
	}
	// architecture doc 6.4's loaded-policy digest, computed from
	// Tetragon's own view (apply.Digest, step 3 prompt Part D8; see
	// docs/decisions/0017-loaded-policy-digest-residual-risk.md for the
	// documented gap between this and the architecture doc's literal
	// algorithm).
	digest, err := hex.DecodeString(apply.Digest(statuses))
	if err != nil {
		return StateSnapshot{}, fmt.Errorf("agent: snapshot: decode digest: %w", err)
	}
	policies := make([]*controlv1.LoadedPolicy, 0, len(statuses))
	for _, s := range statuses {
		policies = append(policies, &controlv1.LoadedPolicy{
			Name:    s.Name,
			State:   s.State.String(),
			Enabled: s.Enabled,
		})
	}
	return StateSnapshot{
		LoadedDigest: digest,
		Policies:     policies,
		Health:       &controlv1.TetragonHealth{Serving: true},
	}, nil
}

// BestEffortRevocations is the RevocationRecorder in tampered mode
// (R6B-5: "tries to persist the marker on a best-effort basis"). Mark
// is called with the store's directory, sealer and counter by the caller
// (cmd/relayd): it re-opens the store and writes only the marker. When
// the tamper is in the index itself the store cannot be opened and the
// marker is not persisted; RunSession audits that
// (revocation_persist_failed) and parks either way. Server-side
// revocation is authoritative (server-contract section 1): a restarted
// host in tampered mode reconnects, and the gateway refuses its revoked
// SPIFFE ID at the mTLS layer.
type BestEffortRevocations struct {
	Mark func(at time.Time, reason string) error
}

// MarkRevoked implements RevocationRecorder.
func (b *BestEffortRevocations) MarkRevoked(at time.Time, reason string) error {
	if b.Mark == nil {
		return fmt.Errorf("agent: tampered mode: no way to persist the REVOKED marker")
	}
	return b.Mark(at, reason)
}
