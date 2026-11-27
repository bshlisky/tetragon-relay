package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/apply"
)

// Reconciler is the subset of *apply.Engine reconcile needs.
type Reconciler interface {
	Reconcile(ctx context.Context, reassertOnDrift bool) (*apply.DriftReport, error)
}

var _ Reconciler = (*apply.Engine)(nil)

// reconcileSchedulerComponent is the scheduler's LivenessRegistry name.
const reconcileSchedulerComponent = "reconcile_scheduler"

// RequestReconcile asks the worker to run a reconcile cycle after any
// queued trust update or bundle (D1: reconcile never runs concurrently
// with an apply, because both run on this one goroutine). restarted marks
// a cycle triggered by a Tetragon restart, which starts a new drift
// episode: one more re-assert is allowed even if the agent is already in
// DRIFT.
func (w *ApplyWorker) RequestReconcile(restarted bool) {
	w.mu.Lock()
	w.reconcileDue = true
	w.reconcileRestart = w.reconcileRestart || restarted
	w.mu.Unlock()
	w.signal()
}

func (w *ApplyWorker) takeReconcile() (due, restarted bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	due, restarted = w.reconcileDue, w.reconcileRestart
	w.reconcileDue, w.reconcileRestart = false, false
	return due, restarted
}

// processReconcile is one reconcile cycle (D2). It compares Tetragon's
// relay-managed policies with LKG. On drift it raises Alert DRIFT with
// both digests and re-asserts LKG once per drift episode (entering DRIFT
// from STEADY); if the re-assert holds the agent returns to STEADY,
// otherwise it stays in DRIFT and alerts on every cycle (rate-limited by
// the Alerter). Only relay-managed policies are ever added or removed
// (apply.Engine's own rule). A TAMPERED store skips reconcile entirely:
// nothing Tetragon has loaded is changed (step 4b C6).
//
// State transitions happen only between STEADY and DRIFT. In any other
// state (CONNECTING, DEGRADED, REVOKED, ...) drift is still re-asserted
// and alerted, so LKG keeps being enforced after a Tetragon restart while
// the controller is unreachable, but the state is left alone: the
// architecture's table has DRIFT edges from STEADY only.
func (w *ApplyWorker) processReconcile(ctx context.Context, restarted bool) {
	d := w.cfg.Deps
	if terr := d.Store.Tampered(); terr != nil {
		if !w.reconcileTamperAudited {
			w.cfg.Auditor.Record(AuditEvent{Step: "reconcile_skipped", Detail: "store TAMPERED: reconcile never changes Tetragon", Err: terr})
			w.reconcileTamperAudited = true
			w.tamperAlert(terr)
		}
		return
	}
	if restarted {
		w.driftReasserted = false
	}
	report, err := d.Reconciler.Reconcile(ctx, false)
	if err != nil {
		w.cfg.Auditor.Record(AuditEvent{Step: "reconcile_failed", Err: err})
		return
	}
	state := w.cfg.SM.Current()
	if report.InSync {
		if state == StateDrift {
			w.fire(EventReassertHolds)
			w.cfg.Auditor.Record(AuditEvent{Step: "drift_resolved", Detail: "Tetragon matches LKG again"})
		}
		w.driftReasserted = false
		return
	}

	detail := w.driftDetail(ctx, report)
	if w.driftReasserted {
		// This episode's one re-assert already happened and did not
		// hold: stay in DRIFT, alert every cycle.
		if state == StateDrift {
			w.fire(EventReassertFails)
		}
		w.cfg.Alerter.Raise(controlv1.Alert_DRIFT, "still drifted after re-assert: "+detail)
		return
	}
	if state == StateSteady {
		w.fire(EventDigestMismatch)
		state = StateDrift
	}
	w.cfg.Alerter.Raise(controlv1.Alert_DRIFT, detail)
	w.cfg.Auditor.Record(AuditEvent{Step: "drift_detected", Detail: detail})

	w.driftReasserted = true
	holds := false
	if rep, rerr := d.Reconciler.Reconcile(ctx, true); rerr == nil && rep.Reasserted {
		if check, cerr := d.Reconciler.Reconcile(ctx, false); cerr == nil && check.InSync {
			holds = true
		}
	}
	if holds {
		w.driftReasserted = false
		w.cfg.Auditor.Record(AuditEvent{Step: "drift_reasserted", Detail: "LKG re-asserted; Tetragon matches LKG"})
		if state == StateDrift {
			w.fire(EventReassertHolds)
		}
		return
	}
	w.cfg.Auditor.Record(AuditEvent{Step: "drift_reassert_failed", Detail: detail})
	if state == StateDrift {
		w.fire(EventReassertFails)
	}
}

// driftDetail names both digests (D2): the LKG bundle's digest (SHA-256
// of its raw envelope) and Tetragon's loaded digest (architecture doc
// 6.4), plus which relay-managed policies are missing or unexpected.
func (w *ApplyWorker) driftDetail(ctx context.Context, report *apply.DriftReport) string {
	var lkgDigest []byte
	if set, ok := w.cfg.Deps.Store.Get(apply.RelayDomain); ok && len(set.RawEnvelope) > 0 {
		sum := sha256.Sum256(set.RawEnvelope)
		lkgDigest = sum[:]
	}
	loaded, _ := w.cfg.Deps.Digest(ctx)
	return fmt.Sprintf("lkg_bundle_digest=%x loaded_digest=%x missing=[%s] unexpected=[%s]",
		lkgDigest, loaded, strings.Join(report.Missing, ","), strings.Join(report.Unexpected, ","))
}

// fire fires e under the Link's lock (see Link), auditing a refusal.
func (w *ApplyWorker) fire(e Event) {
	w.cfg.Link.Settle(func(bool) {
		if err := w.cfg.SM.Fire(e); err != nil {
			w.cfg.Auditor.Record(AuditEvent{Step: "reconcile_state_transition_failed", Detail: e.String(), Err: err})
		}
	})
}

// ReconcileScheduler requests a reconcile cycle at start, every Interval
// (60 s), and immediately when Tetragon restarts (D1). Tetragon's API
// reports no process start time and relayd cannot read another user's
// /proc entries (ProtectProc=invisible), so a restart is detected as a
// change in the SO_PEERCRED pid of the Tetragon socket's peer
// (tetra.Client.Peer), which internal/tetra records on every verified
// (re)connection; the scheduler's health probe forces that reconnection.
// A restart or a not-serving GetHealth raises Alert TETRAGON_UNHEALTHY
// (architecture doc 10.4). The scheduler is a liveness component.
type ReconcileScheduler struct {
	Worker   *ApplyWorker
	Peer     func() (pid int32, dials uint64)
	Probe    func(ctx context.Context) bool
	Alerter  *Alerter
	Auditor  Auditor
	Liveness *LivenessRegistry
	Clock    func() time.Time
	// Interval is the periodic reconcile interval; zero means 60 s.
	Interval time.Duration

	// checkEvery overrides sessionLivenessTouchInterval (tests only).
	checkEvery time.Duration
}

func (s *ReconcileScheduler) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return 60 * time.Second
}

// Run schedules until ctx is done.
func (s *ReconcileScheduler) Run(ctx context.Context) {
	s.Liveness.Register(reconcileSchedulerComponent, sessionLivenessMaxInterval)
	every := s.checkEvery
	if every <= 0 {
		every = sessionLivenessTouchInterval
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	s.Worker.RequestReconcile(false)
	last := s.Clock()
	var lastPID int32
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.Liveness.Touch(reconcileSchedulerComponent)
		if !s.Probe(ctx) {
			s.Alerter.Raise(controlv1.Alert_TETRAGON_UNHEALTHY, "Tetragon GetHealth is not serving")
		}
		s.Liveness.Touch(reconcileSchedulerComponent)
		pid, _ := s.Peer()
		now := s.Clock()
		if pid != 0 && lastPID != 0 && pid != lastPID {
			detail := fmt.Sprintf("Tetragon restarted (socket peer pid %d -> %d); reconciling now", lastPID, pid)
			s.Auditor.Record(AuditEvent{Step: "tetragon_restarted", Detail: detail})
			s.Alerter.Raise(controlv1.Alert_TETRAGON_UNHEALTHY, detail)
			s.Worker.RequestReconcile(true)
			last = now
		}
		if pid != 0 {
			lastPID = pid
		}
		if now.Sub(last) >= s.interval() {
			s.Worker.RequestReconcile(false)
			last = now
		}
	}
}
