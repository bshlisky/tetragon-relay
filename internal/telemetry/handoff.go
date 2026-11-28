package telemetry

import (
	"context"
	"sync"
	"time"
)

// Chunked handoff from ingest to the builder (step-07b-decisions-2.md
// E1.3). With a channel of single events, every admitted event that finds
// the builder parked costs a goroutine wake-up; the E3 profile put ~33 %
// of relayd's CPU in the scheduler. Here ingest appends to a shared slice
// under a mutex (no wake-up) and signals the builder only when the slice
// goes from empty to non-empty or reaches chunk events. On the first
// signal the builder waits up to drainDelay for more before it takes the
// whole slice, so under load it wakes about once per chunk, not per
// event. Admission (peekAdmit) stays in ingest, before anything is queued.
//
// chunk 1 is the per-event behavior (a signal per event, no delay), kept
// for the E3 A/B measurement.

// Defaults: up to defaultHandoffChunk events per wake-up, or what arrived
// within handoffDrainDelay. The delay adds at most that much latency to an
// event, against BatchMaxAge (seconds).
const (
	defaultHandoffChunk = 64
	handoffDrainDelay   = 10 * time.Millisecond
)

type handoff struct {
	chunk int
	max   int // eventQueueDepth: ingest blocks when this many are queued
	delay time.Duration

	mu  sync.Mutex
	buf [][]byte
	// notify (cap 1) wakes the builder; space (cap 1) wakes ingest after
	// a take, when it was blocked on a full queue.
	notify chan struct{}
	space  chan struct{}
}

func newHandoff(chunk, maxQueued int, delay time.Duration) *handoff {
	if chunk < 1 {
		chunk = 1
	}
	if chunk == 1 {
		delay = 0
	}
	return &handoff{
		chunk: chunk, max: maxQueued, delay: delay,
		buf:    make([][]byte, 0, maxQueued),
		notify: make(chan struct{}, 1),
		space:  make(chan struct{}, 1),
	}
}

// put queues raw for the builder. It blocks while max events are queued
// (so Tetragon is read no faster than the pipeline spools) and returns
// false if ctx ends first.
func (h *handoff) put(ctx context.Context, raw []byte) bool {
	for {
		h.mu.Lock()
		if n := len(h.buf); n < h.max {
			h.buf = append(h.buf, raw)
			h.mu.Unlock()
			if n+1 == 1 || (n+1)%h.chunk == 0 {
				signal(h.notify)
			}
			return true
		}
		h.mu.Unlock()
		select {
		case <-h.space:
		case <-ctx.Done():
			return false
		}
	}
}

// ready is the builder's wake-up channel.
func (h *handoff) ready() <-chan struct{} { return h.notify }

// take waits up to delay for a full chunk (returning early when one is
// signaled or ctx ends),
// then swaps the queue for spare, which must be empty, and returns the
// queued events. The caller hands the returned slice back as the next
// spare, once it no longer needs the events in it.
func (h *handoff) take(ctx context.Context, spare [][]byte) [][]byte {
	if h.delay > 0 && h.len() < h.chunk {
		t := time.NewTimer(h.delay)
		select {
		case <-t.C:
		case <-h.notify: // a full chunk arrived meanwhile
			t.Stop()
		case <-ctx.Done():
			t.Stop()
		}
	}
	h.mu.Lock()
	out := h.buf
	h.buf = spare[:0]
	h.mu.Unlock()
	signal(h.space)
	return out
}

func (h *handoff) len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.buf)
}

// signal is a non-blocking send on a cap-1 channel.
func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}
