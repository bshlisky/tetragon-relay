package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// applyWorkerComponent is the apply worker's LivenessRegistry name.
const applyWorkerComponent = "apply_worker"

// applyWorkerLivenessMaxInterval matches sessionLivenessMaxInterval: the
// worker touches every sessionLivenessTouchInterval while idle and while
// an apply is within its bound.
const applyWorkerLivenessMaxInterval = sessionLivenessMaxInterval

// supersededDetail is ApplyResult.detail for a pending bundle replaced
// by a newer one before it was dequeued (ADR 0036).
const supersededDetail = "superseded"

// ApplyWorkerConfig configures an ApplyWorker. Every field is required
// except where noted.
type ApplyWorkerConfig struct {
	Deps     BundleDeps
	SM       *StateMachine
	Link     *Link
	Outbox   *Outbox
	Alerter  *Alerter
	Auditor  Auditor
	Liveness *LivenessRegistry
	Clock    func() time.Time
	// HealthWindow is the engine's configured health window. The worker
	// keeps reporting liveness during one apply for at most
	// HealthWindow + limits.ApplyWorkerLivenessSlack.
	HealthWindow time.Duration

	// touchInterval overrides sessionLivenessTouchInterval if positive
	// (tests only).
	touchInterval time.Duration
}

// ApplyWorker runs every bundle apply on its own goroutine, so the stream
// loop never blocks on one (docs/prompts/step-06b.md B2), and runs them
// one at a time with a single pending slot (B3, ADR 0036).
type ApplyWorker struct {
	cfg ApplyWorkerConfig

	mu         sync.Mutex
	pending    []byte
	has        bool
	trustQueue [][][]byte
	wake       chan struct{}
}

// NewApplyWorker validates cfg and returns a worker. Call Run to start it.
func NewApplyWorker(cfg ApplyWorkerConfig) (*ApplyWorker, error) {
	if err := cfg.Deps.validate(); err != nil {
		return nil, err
	}
	switch {
	case cfg.SM == nil, cfg.Link == nil, cfg.Outbox == nil, cfg.Alerter == nil, cfg.Auditor == nil, cfg.Liveness == nil, cfg.Clock == nil:
		return nil, fmt.Errorf("agent: NewApplyWorker: every dependency must be set")
	case cfg.HealthWindow <= 0:
		return nil, fmt.Errorf("agent: NewApplyWorker: HealthWindow must be positive")
	}
	return &ApplyWorker{cfg: cfg, wake: make(chan struct{}, 1)}, nil
}

// SubmitBundle places envelope in the pending slot and returns at once
// (the stream loop calls it). If the slot already held a bundle that had
// not been dequeued, that bundle is answered with ApplyResult
// REJECTED_EPOCH "superseded". The envelope is copied and kept as raw
// bytes; it is verified only when dequeued (ADR 0036).
func (w *ApplyWorker) SubmitBundle(envelope []byte) {
	raw := append([]byte(nil), envelope...)
	w.mu.Lock()
	superseded, had := w.pending, w.has
	w.pending, w.has = raw, true
	w.mu.Unlock()
	if had {
		w.cfg.Auditor.Record(AuditEvent{Step: "bundle_superseded", Detail: fmt.Sprintf("pending bundle %x replaced by a newer one before it was applied", bundleDigest(superseded))})
		w.cfg.Outbox.Push(applyResultMessage(&controlv1.ApplyResult{
			BundleDigest: bundleDigest(superseded),
			Status:       controlv1.ApplyResult_REJECTED_EPOCH,
			Detail:       supersededDetail,
		}))
	}
	w.signal()
}

func (w *ApplyWorker) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *ApplyWorker) takePending() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.has {
		return nil, false
	}
	env := w.pending
	w.pending, w.has = nil, false
	return env, true
}

func (w *ApplyWorker) touchEvery() time.Duration {
	if w.cfg.touchInterval > 0 {
		return w.cfg.touchInterval
	}
	return sessionLivenessTouchInterval
}

// Run processes jobs until ctx is done. It registers the worker with the
// liveness registry first.
func (w *ApplyWorker) Run(ctx context.Context) {
	w.cfg.Liveness.Register(applyWorkerComponent, applyWorkerLivenessMaxInterval)
	ticker := time.NewTicker(w.touchEvery())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.cfg.Liveness.Touch(applyWorkerComponent)
		case <-w.wake:
			w.drainJobs(ctx)
			w.cfg.Liveness.Touch(applyWorkerComponent)
		}
	}
}

// drainJobs runs queued jobs until none are left: every queued trust
// update first (in arrival order), then the pending bundle, so a bundle
// is always verified against the newest adopted root and a root never
// changes during a bundle's verification or apply (C2).
func (w *ApplyWorker) drainJobs(ctx context.Context) {
	for {
		if roots, ok := w.takeTrustUpdate(); ok {
			w.runJob(ctx, func(context.Context) { w.processTrustUpdate(roots) })
			continue
		}
		env, ok := w.takePending()
		if !ok {
			return
		}
		w.runJob(ctx, func(jctx context.Context) { w.processBundle(jctx, env) })
	}
}

// runJob runs job on its own goroutine and waits for it, touching
// liveness meanwhile, but only for HealthWindow +
// limits.ApplyWorkerLivenessSlack: a job still running after that is
// stalled, and withholding liveness lets systemd's watchdog restart
// relayd (B2).
func (w *ApplyWorker) runJob(ctx context.Context, job func(context.Context)) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		job(ctx)
	}()
	started := w.cfg.Clock()
	bound := w.cfg.HealthWindow + limits.ApplyWorkerLivenessSlack
	ticker := time.NewTicker(w.touchEvery())
	defer ticker.Stop()
	w.cfg.Liveness.Touch(applyWorkerComponent)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if elapsed := w.cfg.Clock().Sub(started); elapsed <= bound {
				w.cfg.Liveness.Touch(applyWorkerComponent)
			} else {
				w.cfg.Auditor.Record(AuditEvent{Step: "apply_worker_stalled", Detail: fmt.Sprintf("job running for %s, over its %s bound; withholding liveness", elapsed, bound)})
			}
		}
	}
}

// processBundle is one bundle's whole pipeline (B1, B5). It sends exactly
// one ApplyResult.
func (w *ApplyWorker) processBundle(ctx context.Context, envelope []byte) {
	d := w.cfg.Deps
	res := &controlv1.ApplyResult{BundleDigest: bundleDigest(envelope)}
	defer func() { w.cfg.Outbox.Push(applyResultMessage(res)) }()

	if terr := d.Store.Tampered(); terr != nil {
		// Step 4b C6: no epoch information is trustworthy, so accepting
		// anything could allow a replay; REJECTED_EPOCH names that.
		res.Status = controlv1.ApplyResult_REJECTED_EPOCH
		res.Detail = "store TAMPERED: every bundle is rejected until operator re-enrollment"
		w.cfg.Auditor.Record(AuditEvent{Step: "bundle_rejected", Detail: res.Detail, Err: terr})
		return
	}

	vr := verifyBundle(ctx, d, envelope, w.cfg.Clock())
	if vr.Code != verify.CodeAccept {
		res.Status = verifyCodeToStatus(vr.Code)
		res.Detail = vr.Code.String() + ": " + vr.Reason
		w.cfg.Auditor.Record(AuditEvent{Step: "bundle_rejected", Detail: res.Detail})
		if vr.Code == verify.CodeRejectedGuardrail || vr.Code == verify.CodeRejectedCapability {
			w.cfg.Alerter.Raise(controlv1.Alert_GUARDRAIL_REJECT, fmt.Sprintf("bundle %x: %s", res.BundleDigest, vr.Reason))
		}
		return
	}
	b := vr.Bundle
	res.Epoch = b.Epoch
	if b.Mode == "enforce" && !d.EnforceAllowed {
		res.Status = controlv1.ApplyResult_REJECTED_CAPABILITY
		res.Detail = "REJECTED_CAPABILITY: host facts are missing, stale or failed the usrmerge check; enforce bundles are refused"
		w.cfg.Auditor.Record(AuditEvent{Step: "bundle_rejected", Detail: res.Detail})
		return
	}

	var from State
	entered := false
	w.cfg.Link.Settle(func(bool) {
		from = w.cfg.SM.Current()
		switch from { //nolint:exhaustive // only STEADY and SYNCING have an edge into APPLYING (architecture doc 8.4); every other state refuses
		case StateSteady:
			entered = w.cfg.SM.Fire(EventVerifiedBundle) == nil
		case StateSyncing:
			entered = w.cfg.SM.Fire(EventBundleReceived) == nil
		}
	})
	if !entered {
		res.Status = controlv1.ApplyResult_APPLY_FAILED
		res.Detail = fmt.Sprintf("not applied: agent state %s does not allow APPLYING", from)
		w.cfg.Auditor.Record(AuditEvent{Step: "bundle_not_applied", Detail: res.Detail})
		return
	}
	w.cfg.Auditor.Record(AuditEvent{Step: "bundle_accepted", Detail: fmt.Sprintf("bundle %s scope=%s epoch=%d mode=%s", b.BundleID, b.Scope, b.Epoch, b.Mode)})

	var monitorNames []string
	if b.Mode == "monitor" {
		for _, p := range b.Policies {
			monitorNames = append(monitorNames, p.Name)
		}
	}
	d.Commit.arm(store.AppliedCommit{Scope: b.Scope, Epoch: b.Epoch, MonitorNames: monitorNames})
	ar, aerr := d.Engine.Apply(ctx, &vr)
	committed, cerr := d.Commit.disarm()

	events, degraded := w.mapApplyOutcome(res, ar, aerr, committed, cerr)
	if digest, err := d.Digest(ctx); err == nil {
		res.LoadedDigestAfter = digest
	}
	w.settle(events)
	if degraded != "" {
		w.cfg.Alerter.Raise(controlv1.Alert_DRIFT, degraded)
	}
	w.cfg.Auditor.Record(AuditEvent{Step: "apply_result", Detail: fmt.Sprintf("status=%s epoch=%d detail=%s", res.Status, res.Epoch, res.Detail)})
}

// mapApplyOutcome fills res from the engine's outcome and returns the
// state-machine events that leave APPLYING, plus a non-empty alert detail
// when the outcome is ROLLBACK_FAILED (B5: DEGRADED with an alert).
//
// Every non-APPLIED outcome leaves APPLYING through ROLLBACK: the
// architecture's table has no APPLYING exit other than "health pass" and
// "fail". APPLY_FAILED (nothing was changed, or this attempt's additions
// were removed) takes ROLLBACK -> STEADY because LKG is what is loaded.
func (w *ApplyWorker) mapApplyOutcome(res *controlv1.ApplyResult, ar *apply.Result, aerr error, committed bool, cerr error) (events []Event, alert string) {
	rolledBack := []Event{EventHealthFail, EventLKGReasserted}
	if ar == nil {
		res.Status = controlv1.ApplyResult_APPLY_FAILED
		res.Detail = errDetail(aerr)
		return rolledBack, ""
	}
	switch ar.Status { //nolint:exhaustive // StatusApplyFailed and any future status take the default APPLY_FAILED branch
	case apply.StatusApplied:
		if !committed || (cerr != nil && !errors.Is(cerr, store.ErrCommittedCounterLag)) {
			// The engine loaded the bundle, but the epoch/LKG/history
			// commit did not happen, so the store still names the
			// previous LKG. Reporting APPLIED would claim an epoch the
			// host has not persisted; reconcile re-asserts the stored
			// LKG on its next cycle.
			res.Status = controlv1.ApplyResult_APPLY_FAILED
			res.Detail = "loaded in Tetragon but the store commit failed; epoch and LKG unchanged, reconcile will re-assert LKG: " + errDetail(cerr)
			w.cfg.Auditor.Record(AuditEvent{Step: "apply_commit_failed", Detail: res.Detail, Err: cerr})
			return []Event{EventHealthPass}, ""
		}
		if cerr != nil {
			w.cfg.Auditor.Record(AuditEvent{Step: "apply_commit_counter_lag", Detail: "commit durable; monotonic counter catches up on next open", Err: cerr})
		}
		res.Status = controlv1.ApplyResult_APPLIED
		res.Detail = ar.Detail
		return []Event{EventHealthPass}, ""
	case apply.StatusRolledBack:
		res.Status = controlv1.ApplyResult_ROLLED_BACK
		res.Detail = ar.Detail
		return rolledBack, ""
	case apply.StatusRollbackFailed:
		res.Status = controlv1.ApplyResult_APPLY_FAILED
		res.Detail = "ROLLBACK_FAILED: " + ar.Detail
		return []Event{EventHealthFail, EventDegradedCondition}, "rollback failed; Tetragon's loaded set may differ from LKG: " + ar.Detail
	default:
		res.Status = controlv1.ApplyResult_APPLY_FAILED
		res.Detail = ar.Detail
		return rolledBack, ""
	}
}

// settle fires events under the Link's lock, then, if the agent is back
// in STEADY while the stream is down, fires StreamLost (RunSession left
// that transition to the worker while it was APPLYING; see Link).
func (w *ApplyWorker) settle(events []Event) {
	w.cfg.Link.Settle(func(connected bool) {
		for _, e := range events {
			if err := w.cfg.SM.Fire(e); err != nil {
				w.cfg.Auditor.Record(AuditEvent{Step: "apply_state_transition_failed", Detail: e.String(), Err: err})
			}
		}
		if !connected && w.cfg.SM.Current() == StateSteady {
			if err := w.cfg.SM.Fire(EventStreamLost); err != nil {
				w.cfg.Auditor.Record(AuditEvent{Step: "apply_state_transition_failed", Detail: EventStreamLost.String(), Err: err})
			}
		}
	})
}

func errDetail(err error) string {
	if err == nil {
		return "unknown error"
	}
	return strings.TrimSpace(err.Error())
}
