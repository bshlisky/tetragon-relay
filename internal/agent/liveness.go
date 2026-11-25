package agent

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// LivenessRegistry implements the step-06a-resume.md R6A-1 liveness
// registry: each long-running component (the session runner, D3; later
// the reconcile scheduler, 6b; the telemetry shipper, 7) reports its own
// forward progress by calling Touch, using the SAME injected clock every
// other security-relevant decision in this package uses (ADR 0008) --
// never time.Now() read implicitly. cmd/relayd's watchdog loop (R6A-1)
// calls Healthy before every WATCHDOG=1 and withholds the ping (with a
// named audit record) unless every registered component has reported
// within its own allowed interval, so a hung component -- a deadlocked
// apply, a stuck stream -- causes systemd to restart relayd after
// WatchdogSec instead of the watchdog proving only that its own select
// loop is still scheduled.
type LivenessRegistry struct {
	clock func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
	max  map[string]time.Duration
}

// NewLivenessRegistry constructs an empty registry. clock must not be
// nil (this package's clock-injection convention); production callers
// pass time.Now, tests pass a fixed or stepped clock so staleness is
// deterministic rather than racing the wall clock.
func NewLivenessRegistry(clock func() time.Time) (*LivenessRegistry, error) {
	if clock == nil {
		return nil, fmt.Errorf("agent: NewLivenessRegistry: clock must not be nil")
	}
	return &LivenessRegistry{clock: clock, last: map[string]time.Time{}, max: map[string]time.Duration{}}, nil
}

// Register adds component to the registry with maxInterval as its
// allowed staleness window, and records an initial Touch at registration
// time: a component that has just started is presumed alive until its
// own first missed interval elapses, not immediately stale before it has
// had a chance to report at all. Registering the same name again resets
// both its interval and its last-progress time (a component restarting
// its own internal loop, e.g. after a reconnect, is not itself a
// liveness problem).
func (r *LivenessRegistry) Register(component string, maxInterval time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.max[component] = maxInterval
	r.last[component] = r.clock()
}

// Touch records that component made forward progress at the current
// time. Touching a component that was never Registered is a no-op
// (Healthy only ever evaluates registered components): this keeps
// Connector/session-runner code free to call Touch defensively without
// having to know whether a liveness registry is even wired in every
// caller (e.g. a unit test that constructs a ControlLoop directly).
func (r *LivenessRegistry) Touch(component string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.max[component]; !ok {
		return
	}
	r.last[component] = r.clock()
}

// Healthy reports whether every registered component has reported within
// its own allowed interval. When one or more have not, it also returns
// the lexicographically first stale component's name (map iteration
// order is otherwise nondeterministic; sorting makes a failing Healthy
// call -- and the audit record cmd/relayd's watchdog loop writes from it
// -- reproducible from one call to the next even with multiple stale
// components) and how long it has been stale.
func (r *LivenessRegistry) Healthy() (healthy bool, staleComponent string, staleFor time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()

	names := make([]string, 0, len(r.max))
	for name := range r.max {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		age := now.Sub(r.last[name])
		if age > r.max[name] {
			return false, name, age
		}
	}
	return true, "", 0
}
