package apply

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	// MaxWindow bounds how far the window may extend while its
	// observation path is unverifiable (default
	// limits.MaxApplyHealthWindow; never less than Window).
	MaxWindow time.Duration
	// SentinelInterval, SentinelMaxLatency and SettleMargin default to
	// the limits package's values (ADR 0042); tests shorten them.
	SentinelInterval   time.Duration
	SentinelMaxLatency time.Duration
	SettleMargin       time.Duration
	// CPUStat, if set, returns relayd's own cgroup usage_usec and
	// nr_throttled; the window records the delta (F0.2).
	CPUStat func() (usageUsec, nrThrottled uint64, err error)
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

func (c HealthWindowConfig) maxWindow() time.Duration {
	m := c.MaxWindow
	if m <= 0 {
		m = limits.MaxApplyHealthWindow
	}
	if w := c.window(); m < w {
		m = w
	}
	return m
}

func (c HealthWindowConfig) sentinelInterval() time.Duration {
	return orDefault(c.SentinelInterval, limits.SentinelInterval)
}

func (c HealthWindowConfig) sentinelMaxLatency() time.Duration {
	return orDefault(c.SentinelMaxLatency, limits.SentinelMaxLatency)
}

func (c HealthWindowConfig) settleMargin() time.Duration {
	return orDefault(c.SettleMargin, limits.SentinelSettleMargin)
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
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
	// reasonEventStreamClosed means GetEvents' stream ended (closed, or
	// an error) before the window reached a verdict. The window never
	// sets a deadline on its own stream (it cancels it after deciding),
	// so any end before that is Tetragon's doing and a failure
	// (step-03a-review.md R3-4; ADR 0042 removed the deadline races).
	reasonEventStreamClosed healthFailureReason = "event_stream_closed_early"
	// reasonUnverifiable means the observation path was never proven
	// current for a full nominal window before MaxWindow (ADR 0042):
	// freshness sentinels were late or missing. ROLLED_BACK_UNVERIFIABLE.
	reasonUnverifiable healthFailureReason = "health_unverifiable"
	// reasonCanceled means the caller's context ended mid-window (relayd
	// shutting down): never a pass.
	reasonCanceled healthFailureReason = "health_window_canceled"
)

// maxRecordedLatencies bounds windowStats.Latencies (MaxWindow /
// SentinelInterval is 300 with the defaults).
const maxRecordedLatencies = 512

// windowStats is what the window measured (F0.1, F0.2): every sentinel's
// latency, how often the clean span restarted, the stream's receive rate,
// and relayd's own CPU throttling during the window.
type windowStats struct {
	Nominal    time.Duration
	Elapsed    time.Duration
	Fired      int
	FireErrors int
	Arrived    int
	Late       int // exceeded SentinelMaxLatency (arrived late or never)
	Restarts   int // clean-span restarts (extensions)
	MaxLatency time.Duration
	Latencies  []time.Duration // arrival order, bounded
	Received   int             // events on the window stream, sentinels included
	CPUOK      bool
	CPUUsec    uint64
	Throttled  uint64
}

// Summary is one bounded line for the audit log, ApplyResult.detail and
// the HEALTH_UNVERIFIABLE alert.
func (s windowStats) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "nominal=%s elapsed=%s sentinels fired=%d arrived=%d late=%d fire_errors=%d restarts=%d max_latency_ms=%d",
		s.Nominal, s.Elapsed.Round(time.Millisecond), s.Fired, s.Arrived, s.Late, s.FireErrors, s.Restarts, s.MaxLatency.Milliseconds())
	if len(s.Latencies) > 0 {
		sorted := append([]time.Duration(nil), s.Latencies...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		p := func(q float64) int64 { return sorted[int(q*float64(len(sorted)-1))].Milliseconds() }
		fmt.Fprintf(&b, " p50_ms=%d p90_ms=%d", p(0.5), p(0.9))
		// The last (most recent) latencies, so a reader sees the trend.
		tail := s.Latencies
		if len(tail) > 24 {
			tail = tail[len(tail)-24:]
		}
		b.WriteString(" last_ms=[")
		for i, l := range tail {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%d", l.Milliseconds())
		}
		b.WriteByte(']')
	}
	secs := s.Elapsed.Seconds()
	if secs <= 0 {
		secs = 1
	}
	fmt.Fprintf(&b, " received=%d rate=%.0f/s", s.Received, float64(s.Received)/secs)
	if s.CPUOK {
		fmt.Fprintf(&b, " relayd_cpu=%.1f%% nr_throttled=+%d", 100*float64(s.CPUUsec)/1e6/secs, s.Throttled)
	}
	return b.String()
}

// windowOutcome is runHealthWindow's verdict.
type windowOutcome struct {
	passed bool
	reason healthFailureReason // set when !passed
	stats  windowStats
}

// sentinelShot is one fired sentinel.
type sentinelShot struct {
	fired   time.Time
	arrived time.Time // zero until seen
	late    bool      // exceeded max latency (arrived late, or still missing)
}

// runHealthWindow implements step 3 Part D5 with ADR 0042's fail-closed
// rule (step-07b-decisions-3.md F0.1): the absence of failure events is
// evidence only while the observation path is proven current.
//
//   - The stream subscribes to policyNames plus the sentinel's policy.
//   - A sentinel fires at the start and every SentinelInterval; each must
//     arrive within SentinelMaxLatency.
//   - The window passes only once a sentinel fired at or after
//     cleanStart+Window has arrived, every sentinel fired since
//     cleanStart arrived in time, SettleMargin has passed since that
//     arrival, GetHealth stayed serving and the control plane was
//     reachable at least once.
//   - A late or missing sentinel restarts the clean span at the next
//     firing (the window extends), up to MaxWindow from the start; then
//     the window is unverifiable.
//   - Admin-path enforcement events, a surge, GetHealth not serving, or
//     the stream ending fail the window at any point, extension included.
//
// With no sentinel the window can never pass: it ends unverifiable.
func runHealthWindow(
	ctx context.Context,
	client TetragonClient,
	reachability ReachabilityChecker,
	sentinel Sentinel,
	cfg HealthWindowConfig,
	policyNames []string,
) windowOutcome {
	nominal := cfg.window()
	maxLatency := cfg.sentinelMaxLatency()
	settle := cfg.settleMargin()
	interval := cfg.sentinelInterval()
	start := time.Now()
	st := windowStats{Nominal: nominal}

	var cpu0, thr0 uint64
	cpuOK := false
	if cfg.CPUStat != nil {
		if u, t, err := cfg.CPUStat(); err == nil {
			cpu0, thr0, cpuOK = u, t, true
		}
	}
	finish := func(passed bool, reason healthFailureReason) windowOutcome {
		st.Elapsed = time.Since(start)
		if cpuOK {
			if u, t, err := cfg.CPUStat(); err == nil && u >= cpu0 && t >= thr0 {
				st.CPUOK, st.CPUUsec, st.Throttled = true, u-cpu0, t-thr0
			}
		}
		return windowOutcome{passed: passed, reason: reason, stats: st}
	}

	if sentinel == nil {
		return finish(false, reasonUnverifiable)
	}

	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	names := append(append([]string(nil), policyNames...), sentinel.PolicyName())
	events, errc := client.GetEvents(streamCtx, names)
	eventTimes := newSlidingEventCounter(time.Minute)

	// Each poll gets its own fixed-size timeout derived from ctx.
	pollTimeout := cfg.pollInterval() * 5
	if pollTimeout < time.Second {
		pollTimeout = time.Second
	}
	pollCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, pollTimeout)
	}
	everReachable := false
	pollOnce := func() bool {
		c, cancel := pollCtx()
		_, ok := checkHealthServing(c, client)
		cancel()
		if !ok {
			return false
		}
		c2, cancel2 := pollCtx()
		if reachability.Reachable(c2) {
			everReachable = true
		}
		cancel2()
		return true
	}
	if !pollOnce() {
		return finish(false, reasonHealthNotServing)
	}

	shots := make(map[string]*sentinelShot)
	var order []*sentinelShot
	var cleanStart time.Time // zero: the clean span starts at the next firing
	restart := func() {
		if !cleanStart.IsZero() {
			st.Restarts++
		}
		cleanStart = time.Time{}
	}
	fire := func() {
		now := time.Now()
		nonce, err := newNonce()
		if err == nil {
			// Recorded before firing: the event can only follow the open.
			shots[nonce] = &sentinelShot{fired: now}
			err = sentinel.Fire(nonce)
			if err != nil {
				delete(shots, nonce)
			}
		}
		if err != nil {
			st.FireErrors++
			restart()
			return
		}
		st.Fired++
		order = append(order, shots[nonce])
		if cleanStart.IsZero() {
			cleanStart = now
		}
	}
	markLate := func(s *sentinelShot) {
		if s.late {
			return
		}
		s.late = true
		st.Late++
		if !cleanStart.IsZero() && !s.fired.Before(cleanStart) {
			restart()
		}
	}
	// verdict reports whether the clean span is proven and settled.
	verdict := func(now time.Time) bool {
		if cleanStart.IsZero() {
			return false
		}
		end := cleanStart.Add(nominal)
		for _, s := range order {
			if s.fired.Before(cleanStart) {
				continue
			}
			if s.late || s.arrived.IsZero() {
				return false // an outstanding sentinel inside the span
			}
			if !s.fired.Before(end) {
				return !now.Before(s.arrived.Add(settle))
			}
		}
		return false
	}

	fire()
	deadline := time.NewTimer(cfg.maxWindow())
	defer deadline.Stop()
	fireTicker := time.NewTicker(interval)
	defer fireTicker.Stop()
	tick := min(interval, maxLatency, settle) / 4
	if tick < time.Millisecond {
		tick = time.Millisecond
	}
	checkTicker := time.NewTicker(tick)
	defer checkTicker.Stop()
	pollTicker := time.NewTicker(cfg.pollInterval())
	defer pollTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return finish(false, reasonCanceled)

		case <-deadline.C:
			return finish(false, reasonUnverifiable)

		case ev, ok := <-events:
			if !ok {
				if ctx.Err() != nil {
					return finish(false, reasonCanceled)
				}
				return finish(false, reasonEventStreamClosed)
			}
			now := time.Now()
			st.Received++
			if nonce, isSentinel := sentinel.Nonce(ev); isSentinel {
				s, known := shots[nonce]
				if !known || !s.arrived.IsZero() {
					continue // not ours, or a duplicate
				}
				s.arrived = now
				lat := now.Sub(s.fired)
				st.Arrived++
				if lat > st.MaxLatency {
					st.MaxLatency = lat
				}
				if len(st.Latencies) < maxRecordedLatencies {
					st.Latencies = append(st.Latencies, lat)
				}
				if lat > maxLatency {
					markLate(s)
				}
				continue
			}
			if reason, failed := evaluateEvent(ev); failed {
				return finish(false, reason)
			}
			eventTimes.add(now)
			if eventTimes.count(now) > cfg.surgeThreshold() {
				return finish(false, reasonEnforcementSurge)
			}

		case err, ok := <-errc:
			if !ok {
				errc = nil
				continue
			}
			if err != nil {
				if ctx.Err() != nil {
					return finish(false, reasonCanceled)
				}
				// No deadline is ever set on this stream, so a timeout is
				// never "the window ending" (ADR 0042).
				if errors.Is(err, tetra.ErrTimeout) {
					return finish(false, reasonHealthNotServing)
				}
				return finish(false, reasonEventStreamClosed)
			}

		case <-fireTicker.C:
			fire()

		case <-pollTicker.C:
			if !pollOnce() {
				return finish(false, reasonHealthNotServing)
			}

		case <-checkTicker.C:
			now := time.Now()
			for _, s := range order {
				if s.arrived.IsZero() && now.Sub(s.fired) > maxLatency {
					markLate(s)
				}
			}
			if verdict(now) {
				if !everReachable {
					return finish(false, reasonControlPlaneDown)
				}
				return finish(true, "")
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
