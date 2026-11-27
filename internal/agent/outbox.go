package agent

import (
	"sync"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// Outbox holds AgentMessages produced outside the stream loop (the apply
// worker's ApplyResults, alerts) until a stream loop sends them. It
// survives reconnects: a message produced while disconnected is sent
// after the next HelloAck (docs/prompts/step-06b.md E1). It is bounded by
// limits.MaxOutboxMessages; when full, the oldest message is dropped and
// counted.
//
// Messages are queued without a seq: the stream loop assigns one when it
// sends (ADR 0032), so a message queued on one stream and sent on the
// next never carries a stale sequence number.
type Outbox struct {
	mu      sync.Mutex
	queue   []*controlv1.AgentMessage
	dropped uint64
	notify  chan struct{}
}

// NewOutbox returns an empty Outbox.
func NewOutbox() *Outbox {
	return &Outbox{notify: make(chan struct{}, 1)}
}

// Push queues msg (its Seq is ignored and later overwritten), dropping
// the oldest queued message if the queue is full.
func (o *Outbox) Push(msg *controlv1.AgentMessage) {
	o.mu.Lock()
	if len(o.queue) >= limits.MaxOutboxMessages {
		o.queue[0] = nil
		o.queue = o.queue[1:]
		o.dropped++
	}
	o.queue = append(o.queue, msg)
	o.mu.Unlock()
	select {
	case o.notify <- struct{}{}:
	default:
	}
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

// Dropped returns how many messages were dropped because the queue was
// full.
func (o *Outbox) Dropped() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.dropped
}
