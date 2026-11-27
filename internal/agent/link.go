package agent

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Link is the control stream's connection state as the rest of the agent
// sees it (docs/prompts/step-06b.md B4), and the one place where
// connection-driven and apply-driven state-machine transitions are
// serialized.
//
// Two goroutines fire transitions on the same StateMachine: RunSession
// (HelloAck, InSync, StreamLost) and the apply worker (VerifiedBundle,
// HealthPass, HealthFail, ...). Architecture doc 8.4's single-valued state
// machine has no edge for "stream lost while APPLYING", so RunSession
// leaves APPLYING/ROLLBACK alone and the worker, when it settles back in
// STEADY, fires StreamLost itself if the stream is down at that moment.
// Both sides make that decision under Link's mutex, so neither can act on
// a connection state the other is in the middle of changing.
type Link struct {
	clock    func() time.Time
	interval time.Duration

	mu        sync.Mutex
	connected bool
	// lastAck is when the transport last accepted a message on the
	// current stream (Send returned nil), or when the stream completed
	// Hello/HelloAck, whichever is later.
	lastAck time.Time
}

// NewLink returns a disconnected Link. heartbeatInterval is the session's
// heartbeat interval: Reachable requires a transport acknowledgment within
// two of them.
func NewLink(clock func() time.Time, heartbeatInterval time.Duration) (*Link, error) {
	if clock == nil {
		return nil, fmt.Errorf("agent: NewLink: clock must not be nil")
	}
	if heartbeatInterval <= 0 {
		return nil, fmt.Errorf("agent: NewLink: heartbeat interval must be positive")
	}
	return &Link{clock: clock, interval: heartbeatInterval}, nil
}

// Up records a completed Hello/HelloAck and runs fire (the connect-time
// transitions) under the Link's lock.
func (l *Link) Up(fire func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.connected = true
	l.lastAck = l.clock()
	fire()
}

// Down records the stream's loss and runs fire under the Link's lock.
func (l *Link) Down(fire func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.connected = false
	fire()
}

// Acked records that the transport accepted a message on the current
// stream.
func (l *Link) Acked() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.connected {
		l.lastAck = l.clock()
	}
}

// Settle runs fire with the current connection state under the Link's
// lock (the apply worker's end-of-apply transitions).
func (l *Link) Settle(fire func(connected bool)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fire(l.connected)
}

// Connected reports whether a stream is currently up.
func (l *Link) Connected() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.connected
}

// Reachable implements apply.ReachabilityChecker for the health window
// (architecture doc 7.7 step 7: "agent can still reach the controller"):
// a stream is up and the transport accepted a message on it within the
// last two heartbeat intervals. A heartbeat is sent every interval, so a
// healthy stream always satisfies this.
func (l *Link) Reachable(context.Context) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.connected {
		return false
	}
	return l.clock().Sub(l.lastAck) <= 2*l.interval
}
