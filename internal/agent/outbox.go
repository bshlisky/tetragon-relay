package agent

import (
	"fmt"
	"sync"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// Outbox holds AgentMessages produced outside the stream loop (the apply
// worker's ApplyResults, alerts) until a stream loop sends them. It
// survives reconnects: a message produced while disconnected is sent
// after the next HelloAck (docs/prompts/step-06b.md E1).
//
// Messages are sent in the order they were pushed, but each class has its
// own bound (docs/reviews/step-06b-review.md R6B-3):
//   - ApplyResults: limits.MaxOutboxApplyResults. They are the
//     controller's record of what happened to a signed change, so an
//     alert never evicts one. Past the bound the oldest ApplyResult is
//     dropped, counted (DroppedApplyResults) and audited.
//   - Everything else (alerts): limits.MaxOutboxAlerts. Past the bound
//     the oldest alert is dropped and counted (DroppedAlerts).
//
// Messages are queued without a seq: the stream loop assigns one when it
// sends (ADR 0032), so a message queued on one stream and sent on the
// next never carries a stale sequence number.
type Outbox struct {
	auditor Auditor

	mu             sync.Mutex
	queue          []*controlv1.AgentMessage
	results        int // ApplyResults in queue
	droppedResults uint64
	droppedAlerts  uint64
	notify         chan struct{}
}

// NewOutbox returns an empty Outbox. auditor records every dropped
// ApplyResult; it must not be nil.
func NewOutbox(auditor Auditor) (*Outbox, error) {
	if auditor == nil {
		return nil, fmt.Errorf("agent: NewOutbox: auditor must not be nil")
	}
	return &Outbox{auditor: auditor, notify: make(chan struct{}, 1)}, nil
}

func isApplyResult(m *controlv1.AgentMessage) bool { return m.GetApplyResult() != nil }

// Push queues msg (its Seq is ignored and later overwritten). If msg's
// class is at its bound, the oldest queued message of the same class is
// dropped first; a message of the other class is never touched.
func (o *Outbox) Push(msg *controlv1.AgentMessage) {
	result := isApplyResult(msg)
	var dropped *controlv1.AgentMessage
	o.mu.Lock()
	if result && o.results >= limits.MaxOutboxApplyResults {
		dropped = o.removeOldestLocked(true)
		o.droppedResults++
	} else if !result && len(o.queue)-o.results >= limits.MaxOutboxAlerts {
		o.removeOldestLocked(false)
		o.droppedAlerts++
	}
	o.queue = append(o.queue, msg)
	if result {
		o.results++
	}
	o.mu.Unlock()
	if dropped != nil {
		r := dropped.GetApplyResult()
		o.auditor.Record(AuditEvent{Step: "outbox_apply_result_dropped", Detail: fmt.Sprintf("outbox holds %d ApplyResults; dropped the oldest: bundle %x status=%s epoch=%d", limits.MaxOutboxApplyResults, r.GetBundleDigest(), r.GetStatus(), r.GetEpoch())})
	}
	select {
	case o.notify <- struct{}{}:
	default:
	}
}

// removeOldestLocked removes and returns the oldest queued message whose
// class (ApplyResult or not) is result. The caller holds o.mu and has
// checked that one exists.
func (o *Outbox) removeOldestLocked(result bool) *controlv1.AgentMessage {
	for i, m := range o.queue {
		if isApplyResult(m) == result {
			copy(o.queue[i:], o.queue[i+1:])
			o.queue[len(o.queue)-1] = nil
			o.queue = o.queue[:len(o.queue)-1]
			if result {
				o.results--
			}
			return m
		}
	}
	return nil
}

// Notify returns a channel that receives a value after a Push. A stream
// loop selects on it and then drains with Peek/Pop.
func (o *Outbox) Notify() <-chan struct{} { return o.notify }

// Peek returns the oldest queued message without removing it, or nil.
// The stream loop pops a message only after the transport accepted it,
// so a message whose Send failed is retried on the next stream.
func (o *Outbox) Peek() *controlv1.AgentMessage {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.queue) == 0 {
		return nil
	}
	return o.queue[0]
}

// Pop removes msg if it is still the oldest queued message (a concurrent
// Push may have dropped it in the meantime, in which case Pop does
// nothing).
func (o *Outbox) Pop(msg *controlv1.AgentMessage) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.queue) > 0 && o.queue[0] == msg {
		if isApplyResult(msg) {
			o.results--
		}
		o.queue[0] = nil
		o.queue = o.queue[1:]
	}
}

// Len returns the number of queued messages.
func (o *Outbox) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.queue)
}

// Dropped returns how many messages of either class were dropped because
// their class was at its bound.
func (o *Outbox) Dropped() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.droppedResults + o.droppedAlerts
}

// DroppedApplyResults returns how many ApplyResults were dropped.
func (o *Outbox) DroppedApplyResults() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.droppedResults
}

// DroppedAlerts returns how many alerts were dropped.
func (o *Outbox) DroppedAlerts() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.droppedAlerts
}
