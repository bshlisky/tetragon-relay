//go:build testca

package agent

import (
	"os"
	"sync"
	"time"
)

// This file exists only in a testca build (never production, never a
// default `go build ./...`): it is the single place step-06a-e3-
// prompt.md's S5/S6 test-only hooks read any environment variable.
// Both are read exactly once (sync.Once), not on every call, so a test
// that changes the process environment mid-run never observes a
// different hook value than the one RunSession's own goroutines
// already captured -- matching every other "read once at startup"
// convention this package's production code already follows (e.g.
// cmd/relayd's flag parsing).

var (
	e3StallOnce sync.Once
	e3StallVal  string

	e3DegradedOnce     sync.Once
	e3DegradedOverride time.Duration
)

// e3StalledComponent names the LivenessRegistry component (today, only
// "session_runner" is ever registered) whose Touch calls RunSession
// should silently skip, read from RELAYD_E3_STALL_COMPONENT
// (step-06a-e3-prompt.md S6). Unset (the default) behaves exactly like
// the production !testca build: every Touch call goes through.
func e3StalledComponent() string {
	e3StallOnce.Do(func() { e3StallVal = os.Getenv("RELAYD_E3_STALL_COMPONENT") })
	return e3StallVal
}

// e3DegradedTimeoutOverride parses RELAYD_E3_DEGRADED_TIMEOUT as a
// time.Duration (e.g. "10s"), read once, for step-06a-e3-prompt.md S5's
// explicitly-permitted shortened DEGRADED threshold. An unset or
// unparseable value returns 0 ("no override"), the same as the
// production build -- an operator error in this test-only variable must
// never silently become "wait 5 real minutes less than intended" or
// "wait forever"; it must behave exactly as if the variable were never
// set.
func e3DegradedTimeoutOverride() time.Duration {
	e3DegradedOnce.Do(func() {
		e3DegradedOverride = parseE3DegradedTimeout(os.Getenv("RELAYD_E3_DEGRADED_TIMEOUT"))
	})
	return e3DegradedOverride
}

// parseE3DegradedTimeout is e3DegradedTimeoutOverride's parsing logic,
// factored out as a pure function of a string so it can be unit-tested
// directly without fighting sync.Once's "exactly once per process"
// semantics.
func parseE3DegradedTimeout(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}
