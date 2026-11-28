package agent

import (
	"fmt"
	"sync"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// Alerter raises control-stream Alerts (docs/prompts/step-06b.md E1).
// Each kind is rate-limited to one per limits.AlertRateLimitInterval,
// except the first. A raised alert goes to the Outbox, so one raised
// while disconnected is sent after the next HelloAck (the Outbox's own
// bound applies: oldest dropped, counted). Every alert, sent or
// suppressed, is also written to the audit log.
type Alerter struct {
	outbox  *Outbox
	auditor Auditor
	clock   func() time.Time

	mu   sync.Mutex
	last map[controlv1.Alert_Kind]time.Time
}

// NewAlerter returns an Alerter. No argument may be nil.
func NewAlerter(outbox *Outbox, auditor Auditor, clock func() time.Time) (*Alerter, error) {
	if outbox == nil || auditor == nil || clock == nil {
		return nil, fmt.Errorf("agent: NewAlerter: outbox, auditor and clock must not be nil")
	}
	return &Alerter{outbox: outbox, auditor: auditor, clock: clock, last: map[controlv1.Alert_Kind]time.Time{}}, nil
}

// Raise queues an Alert of kind with detail unless one of the same kind
// was queued less than limits.AlertRateLimitInterval ago. It reports
// whether the alert was queued.
func (a *Alerter) Raise(kind controlv1.Alert_Kind, detail string) bool {
	detail = boundDetail(detail)
	now := a.clock()
	a.mu.Lock()
	last, seen := a.last[kind]
	if seen && now.Sub(last) < limits.AlertRateLimitInterval {
		a.mu.Unlock()
		a.auditor.Record(AuditEvent{Step: "alert_suppressed", Detail: fmt.Sprintf("kind=%s (rate limit) detail=%s", kind, detail)})
		return false
	}
	a.last[kind] = now
	a.mu.Unlock()
	a.auditor.Record(AuditEvent{Step: "alert", Detail: fmt.Sprintf("kind=%s detail=%s", kind, detail)})
	a.outbox.Push(&controlv1.AgentMessage{Body: &controlv1.AgentMessage_Alert{Alert: &controlv1.Alert{
		Kind:     kind,
		Detail:   detail,
		UnixTime: now.Unix(),
	}}})
	return true
}

// EnvCollectionConnected returns an OnConnected hook that raises Alert
// TETRAGON_ENV_COLLECTION once per connection when the host fact says the
// running Tetragon collects process environment variables
// (step-07b-decisions-3.md F4). It is a privacy finding: enforcement
// bundles still apply. next, if non-nil, runs first.
func EnvCollectionConnected(alerter *Alerter, envCollection string, next func()) func() {
	return func() {
		if next != nil {
			next()
		}
		if envCollection == "on" {
			alerter.Raise(controlv1.Alert_TETRAGON_ENV_COLLECTION, "the running Tetragon collects process environment variables (--enable-process-environment-variables or its equivalent); relayd filters and redacts them, but Tetragon still holds them and serves them to other clients of its socket. Production configuration ships without it.")
		}
	}
}
