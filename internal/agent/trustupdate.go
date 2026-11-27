package agent

import (
	"errors"
	"fmt"
	"sync"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

// TrustRootStore is what trust-update processing needs from internal/
// store (*store.Store satisfies it).
type TrustRootStore interface {
	PersistTrustRoot(raw []byte, version uint64) error
	Tampered() error
}

// set replaces the current trust root. Only the apply worker calls it,
// between jobs (docs/prompts/step-06b.md C2).
func (t *TrustState) set(root *trust.Root) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.root = root
}

// SubmitTrustUpdate queues a TrustUpdate's signed roots for the worker
// and returns at once. Trust updates are processed in arrival order,
// before any pending bundle, and never while a bundle is being verified
// or applied (C2). At most limits.MaxPendingTrustUpdates are held; when
// full, the oldest is dropped and audited (the controller resends trust
// metadata on every reconcile, architecture doc 6.3 step 4).
func (w *ApplyWorker) SubmitTrustUpdate(signedRoots [][]byte) {
	roots := make([][]byte, len(signedRoots))
	for i, r := range signedRoots {
		roots[i] = append([]byte(nil), r...)
	}
	w.mu.Lock()
	dropped := false
	if len(w.trustQueue) >= limits.MaxPendingTrustUpdates {
		w.trustQueue = w.trustQueue[1:]
		dropped = true
	}
	w.trustQueue = append(w.trustQueue, roots)
	w.mu.Unlock()
	if dropped {
		w.cfg.Auditor.Record(AuditEvent{Step: "trust_update_dropped", Detail: "pending trust-update queue full; oldest dropped"})
	}
	w.signal()
}

func (w *ApplyWorker) takeTrustUpdate() ([][]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.trustQueue) == 0 {
		return nil, false
	}
	roots := w.trustQueue[0]
	w.trustQueue = w.trustQueue[1:]
	return roots, true
}

// processTrustUpdate implements C1: signed_roots is N+1..M in order; each
// must verify against its predecessor ((*trust.Root).Update: old and new
// root thresholds, no skips, unexpired). Each adopted version is
// persisted before it becomes current (atomic per step). The first
// failure stops the walk: the last good root stays, and the failure is
// audited and alerted. Versions at or below the current root are skipped
// (the controller does not know which version the agent has). A root
// requiring mldsa-87 on a build without ML-DSA is refused (R4B-6). A
// TAMPERED store refuses every trust update (step 4b C6).
func (w *ApplyWorker) processTrustUpdate(roots [][]byte) {
	d := w.cfg.Deps
	fail := func(detail string, err error) {
		w.cfg.Auditor.Record(AuditEvent{Step: "trust_update_rejected", Detail: detail, Err: err})
		w.cfg.Alerter.Raise(controlv1.Alert_TRUST_UPDATE_REJECTED, detail)
	}
	if terr := d.Roots.Tampered(); terr != nil {
		fail("store TAMPERED: every trust update is rejected until operator re-enrollment", terr)
		w.tamperAlert(terr)
		return
	}
	if len(roots) == 0 || len(roots) > limits.MaxRootChainFiles {
		fail(fmt.Sprintf("signed_roots has %d entries; want 1..%d", len(roots), limits.MaxRootChainFiles), nil)
		return
	}
	now := w.cfg.Clock()
	start := d.Trust.Current()
	current := start
	for i, raw := range roots {
		next, err := current.Update(raw, now)
		if errors.Is(err, trust.ErrVersionRollback) {
			w.cfg.Auditor.Record(AuditEvent{Step: "trust_update_skipped", Detail: fmt.Sprintf("signed_roots[%d] is not newer than current version %d", i, current.Version)})
			continue
		}
		if err != nil {
			fail(fmt.Sprintf("signed_roots[%d] does not chain from version %d; keeping version %d", i, current.Version, current.Version), err)
			return
		}
		if !d.Crypto.MLDSAAvailable && rootRequiresMLDSA(next) {
			fail(fmt.Sprintf("root version %d requires mldsa-87, unavailable in this build; keeping version %d", next.Version, current.Version), nil)
			return
		}
		if err := d.Roots.PersistTrustRoot(raw, next.Version); err != nil {
			fail(fmt.Sprintf("persisting root version %d failed; keeping version %d", next.Version, current.Version), err)
			return
		}
		d.Trust.set(next)
		current = next
		w.cfg.Auditor.Record(AuditEvent{Step: "trust_root_adopted", Detail: fmt.Sprintf("version %d (from TrustUpdate)", next.Version)})
	}
	if current != start {
		w.cfg.Auditor.Record(AuditEvent{Step: "trust_update_applied", Detail: fmt.Sprintf("trust root version %d -> %d", start.Version, current.Version)})
	}
}

// TrustExpiryMonitor raises Alert TRUST_EXPIRED while the current trust
// root is expired: once per connection, and again every
// limits.TrustExpiredAlertInterval (daily) while it stays expired
// (docs/prompts/step-06b.md C3). Bundles are rejected meanwhile by
// verify (verifierFor). The Alerter's per-kind rate limit still applies.
type TrustExpiryMonitor struct {
	Trust   *TrustState
	Alerter *Alerter
	Clock   func() time.Time

	mu          sync.Mutex
	connection  uint64
	alertedConn uint64
	lastAlert   time.Time
}

// Connected records a new connection (call after every HelloAck) and
// checks.
func (m *TrustExpiryMonitor) Connected() {
	m.mu.Lock()
	m.connection++
	m.mu.Unlock()
	m.Check()
}

// Check raises TRUST_EXPIRED if the root is expired and this connection
// has not been alerted yet, or the last alert is a day old.
func (m *TrustExpiryMonitor) Check() {
	now := m.Clock()
	root := m.Trust.Current()
	if now.Before(root.Expires) {
		return
	}
	m.mu.Lock()
	due := m.connection != 0 && (m.alertedConn != m.connection || now.Sub(m.lastAlert) >= limits.TrustExpiredAlertInterval)
	if due {
		m.alertedConn = m.connection
		m.lastAlert = now
	}
	m.mu.Unlock()
	if due {
		m.Alerter.Raise(controlv1.Alert_TRUST_EXPIRED, fmt.Sprintf("trust root version %d expired at %s; new bundles are rejected, LKG stays enforced", root.Version, root.Expires.UTC().Format(time.RFC3339)))
	}
}
