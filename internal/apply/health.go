package apply

import (
	"context"
	"errors"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// HealthWindowConfig configures Part D5's health window.
type HealthWindowConfig struct {
	// Window is the health window duration (default
	// limits.DefaultApplyHealthWindow; must be within
	// [limits.MinApplyHealthWindow, limits.MaxApplyHealthWindow]).
	Window time.Duration
	// SurgeThreshold is the enforcement-events-per-minute rollback
	// trigger (default limits.DefaultApplySurgeThreshold).
	SurgeThreshold int
	// PollInterval is how often GetHealth/process-start-time are
	// re-checked during the window.
	PollInterval time.Duration
}

// window returns the configured window, or limits.DefaultApplyHealthWindow
// if unset. It deliberately does NOT clamp to
// [limits.MinApplyHealthWindow, limits.MaxApplyHealthWindow] here: that
// bound is a *configuration-loading-time* validation rule (the real
// relayd config loader must reject or clamp an out-of-range
// apply.health_window from relay.yaml before ever constructing a
// Config), not something this package re-applies silently to whatever
// Window value a caller passes in. Applying it here as well would also
// make this package's own tests unable to use short windows to stay fast.
func (c HealthWindowConfig) window() time.Duration {
	if c.Window <= 0 {
		return limits.DefaultApplyHealthWindow
	}
	return c.Window
}

// ClampHealthWindow bounds d to
// [limits.MinApplyHealthWindow, limits.MaxApplyHealthWindow]. Production
// callers that load a configurable health_window from relay.yaml
// (architecture doc section 8.6) must call this (or reject an
// out-of-range value outright) before constructing a Config; this
// package's own HealthWindowConfig.window() does not call it (see that
// method's doc comment).
func ClampHealthWindow(d time.Duration) time.Duration {
	if d < limits.MinApplyHealthWindow {
		return limits.MinApplyHealthWindow
	}
	if d > limits.MaxApplyHealthWindow {
		return limits.MaxApplyHealthWindow
	}
	return d
}

func (c HealthWindowConfig) surgeThreshold() int {
	if c.SurgeThreshold <= 0 {
		return limits.DefaultApplySurgeThreshold
	}
	return c.SurgeThreshold
}

func (c HealthWindowConfig) pollInterval() time.Duration {
	if c.PollInterval <= 0 {
		return 2 * time.Second
	}
	return c.PollInterval
}

// healthFailureReason explains why the health window failed, for the
// Auditor/Result detail.
type healthFailureReason string

const (
	reasonHealthNotServing  healthFailureReason = "tetragon_health_not_serving"
	reasonProcessRestarted  healthFailureReason = "tetragon_process_restarted"
	reasonControlPlaneDown  healthFailureReason = "control_plane_unreachable_entire_window"
	reasonAdminPathEnforced healthFailureReason = "admin_path_enforcement_event"
	reasonEnforcementSurge  healthFailureReason = "enforcement_event_surge"
	// reasonEventStreamClosed means GetEvents' events channel closed
	// (cleanly, with no error) before windowCtx's own deadline — i.e.
	// Tetragon ended the event stream early, not as a side effect of the
	// window itself ending (step-03a-review.md R3-4).
	reasonEventStreamClosed healthFailureReason = "event_stream_closed_early"
)

// runHealthWindow implements step 3 prompt Part D5. policyNames bounds the
// GetEvents subscription to the policies this apply just loaded (Part D5
// only cares about enforcement events from this bundle, not the whole
// fleet's pre-existing policies). It returns ("", true) if the window
// passed, or (reason, false) on the first failure condition observed
// (health window returns as soon as a failure is detected, it does not
// wait out the rest of the window once failed).
func runHealthWindow(
	ctx context.Context,
	client TetragonClient,
	reachability ReachabilityChecker,
	cfg HealthWindowConfig,
	policyNames []string,
) (healthFailureReason, bool) {
	windowCtx, cancel := context.WithTimeout(ctx, cfg.window())
	defer cancel()

	events, errc := client.GetEvents(windowCtx, policyNames)
	eventTimes := newSlidingEventCounter(time.Minute)

	// Each poll (GetHealth, reachability) below gets its own fixed-size
	// timeout derived from ctx (the caller's context, for cancellation
	// propagation) rather than windowCtx directly: windowCtx's deadline
	// shrinks to zero as the window elapses, so a poll issued near the
	// very end of an otherwise-healthy window could otherwise be starved
	// of time to complete and be misread as "not serving" purely due to
	// the window's own countdown, not any real Tetragon health problem.
	pollTimeout := cfg.pollInterval() * 5
	if pollTimeout < time.Second {
		pollTimeout = time.Second
	}
	pollCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, pollTimeout)
	}

	everReachable := false
	if ok := func() bool {
		c, cancel := pollCtx()
		defer cancel()
		_, ok := checkHealthServing(c, client)
		return ok
	}(); !ok {
		return reasonHealthNotServing, false
	}
	if func() bool {
		c, cancel := pollCtx()
		defer cancel()
		return reachability.Reachable(c)
	}() {
		everReachable = true
	}

	ticker := time.NewTicker(cfg.pollInterval())
	defer ticker.Stop()

	for {
		select {
		case <-windowCtx.Done():
			// The window elapsed naturally: fail only if the control
			// plane was unreachable at every single poll across the
			// entire window (Part D5: "unreachable for the whole
			// window"), not merely at some point within it.
			if !everReachable {
				return reasonControlPlaneDown, false
			}
			return "", true

		case ev, ok := <-events:
			if !ok {
				// Every path below returns: events closing always ends
				// the window one way or another, so there is no
				// "disable this case and keep looping" branch left to
				// reach (unlike errc below, which tolerates a closed
				// channel by itself).
				if windowCtx.Err() != nil {
					// step-03a-review.md R3-4: events closing races
					// windowCtx.Done() at the window's own deadline
					// (internal/tetra.GetEvents closes it, without
					// sending, exactly when ctx ends) — handle it
					// identically to that branch rather than looping
					// back around only to pick Done() up next time.
					if !everReachable {
						return reasonControlPlaneDown, false
					}
					return "", true
				}
				// The window has not ended: Tetragon closed the event
				// stream of its own accord, which is itself a health
				// failure, not something to silently ignore.
				return reasonEventStreamClosed, false
			}
			if reason, failed := evaluateEvent(ev); failed {
				return reason, false
			}
			eventTimes.add(time.Now())
			if eventTimes.count(time.Now()) > cfg.surgeThreshold() {
				return reasonEnforcementSurge, false
			}

		case err, ok := <-errc:
			if !ok {
				errc = nil // channel closed; disable this case (avoid a
				// busy loop reading a closed channel's zero value
				// forever) and keep watching the ticker/windowCtx.Done()
				continue
			}
			if err != nil {
				if windowCtx.Err() != nil || errors.Is(err, tetra.ErrTimeout) {
					// step-03a-review.md R3-4: a timeout racing
					// windowCtx.Done() at the exact deadline must not
					// fail a window that actually completed healthily.
					// windowCtx.Err() != nil is the common case;
					// errors.Is(err, tetra.ErrTimeout) additionally
					// covers a real timing gap observed under load
					// (-count=200 -race stress): internal/tetra.GetEvents
					// never applies a shorter timeout of its own to this
					// call (unlike every other RPC method, it uses
					// windowCtx directly, Part B3), so a DeadlineExceeded
					// gRPC status for it can only ever mean windowCtx's
					// own deadline — including when it arrives from the
					// server's grpc-timeout-propagated deadline slightly
					// before this goroutine's local windowCtx.Err() has
					// been set (a scheduling race, not a real Tetragon
					// problem). internal/tetra.GetEvents no longer sends
					// this once ctx.Err() is locally observed non-nil
					// either, but this closes the remaining gap.
					if !everReachable {
						return reasonControlPlaneDown, false
					}
					return "", true
				}
				return reasonHealthNotServing, false
			}

		case <-ticker.C:
			c, cancel := pollCtx()
			_, ok := checkHealthServing(c, client)
			cancel()
			if !ok {
				return reasonHealthNotServing, false
			}
			c2, cancel2 := pollCtx()
			reachable := reachability.Reachable(c2)
			cancel2()
			if reachable {
				everReachable = true
			}
		}
	}
}

// checkHealthServing reports whether every HealthStatus entry Tetragon
// returns is HEALTH_STATUS_RUNNING (Part D5: "Tetragon GetHealth not
// serving"). An empty response (no event types configured) is treated as
// non-serving: a Tetragon that returns nothing at all to GetHealth is not
// a Tetragon this engine trusts is healthy.
func checkHealthServing(ctx context.Context, client TetragonClient) ([]*tetragonpb.HealthStatus, bool) {
	statuses, err := client.GetHealth(ctx)
	if err != nil || len(statuses) == 0 {
		return nil, false
	}
	for _, s := range statuses {
		if s.GetStatus() != tetragonpb.HealthStatusResult_HEALTH_STATUS_RUNNING {
			return statuses, false
		}
	}
	return statuses, true
}

// evaluateEvent implements Part D5's admin-path rule: any enforcement
// event (Sigkill/Signal/Override — the same enforcementActionNames set
// Part D2 rewrites, checked here on the *observed* action, which is
// exactly why a monitor-mode load, having already had every action
// rewritten to Post, can never trip this: there is nothing left for
// Tetragon to enforce) whose process or any ancestor's binary is in
// adminPathBinaries fails the window.
func evaluateEvent(ev tetra.Event) (healthFailureReason, bool) {
	switch {
	case ev.Kprobe != nil:
		if isEnforcementKprobeAction(ev.Kprobe.GetAction()) && processTreeHitsAdminPath(ev.Kprobe.GetProcess(), ev.Kprobe.GetParent(), ev.Kprobe.GetAncestors()) {
			return reasonAdminPathEnforced, true
		}
	case ev.Uprobe != nil:
		if isEnforcementKprobeAction(ev.Uprobe.GetAction()) && processTreeHitsAdminPath(ev.Uprobe.GetProcess(), ev.Uprobe.GetParent(), ev.Uprobe.GetAncestors()) {
			return reasonAdminPathEnforced, true
		}
	case ev.Lsm != nil:
		if isEnforcementKprobeAction(ev.Lsm.GetAction()) && processTreeHitsAdminPath(ev.Lsm.GetProcess(), ev.Lsm.GetParent(), ev.Lsm.GetAncestors()) {
			return reasonAdminPathEnforced, true
		}
	}
	return "", false
}

// isEnforcementKprobeAction reports whether action is one of
// Sigkill/Signal/Override (Part D5's explicit list; a strict subset of
// enforcementActionNames, excluding NotifyEnforcer/Set, which do not by
// themselves stop or alter a process the way Part D5 is concerned with).
func isEnforcementKprobeAction(action tetragonpb.KprobeAction) bool {
	switch action { //nolint:exhaustive // every other KprobeAction is not one of Part D5's three named triggers
	case tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL, tetragonpb.KprobeAction_KPROBE_ACTION_SIGNAL, tetragonpb.KprobeAction_KPROBE_ACTION_OVERRIDE:
		return true
	default:
		return false
	}
}

func processTreeHitsAdminPath(proc, parent *tetragonpb.Process, ancestors []*tetragonpb.Process) bool {
	if proc != nil && isAdminPathBinary(proc.GetBinary()) {
		return true
	}
	if parent != nil && isAdminPathBinary(parent.GetBinary()) {
		return true
	}
	for _, a := range ancestors {
		if a != nil && isAdminPathBinary(a.GetBinary()) {
			return true
		}
	}
	return false
}

// slidingEventCounter counts events within a trailing window (Part D5's
// surge threshold, "events/min").
type slidingEventCounter struct {
	window time.Duration
	times  []time.Time
}

func newSlidingEventCounter(window time.Duration) *slidingEventCounter {
	return &slidingEventCounter{window: window}
}

func (s *slidingEventCounter) add(t time.Time) {
	s.times = append(s.times, t)
}

func (s *slidingEventCounter) count(now time.Time) int {
	cutoff := now.Add(-s.window)
	kept := s.times[:0]
	for _, t := range s.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.times = kept
	return len(s.times)
}
