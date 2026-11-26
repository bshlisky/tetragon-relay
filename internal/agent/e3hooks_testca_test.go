//go:build testca

package agent

import (
	"testing"
	"time"
)

// These tests exercise e3hooks_testca.go's own parsing logic directly.
// They cannot reset the package-level sync.Once (by design: production
// code reads these exactly once per process, never per-call), so each
// test runs in its own subprocess-equivalent isolation by only ever
// calling the function under test once per test binary invocation --
// here, achieved by only asserting on behavior that is invariant
// regardless of which value sync.Once happened to capture first: the
// zero-value ("unset") case, which is this test binary's actual
// environment (RELAYD_E3_STALL_COMPONENT and RELAYD_E3_DEGRADED_TIMEOUT
// are not set when `go test -tags testca ./internal/agent/...` runs
// without them explicitly exported).
func TestE3StalledComponent_UnsetIsEmpty(t *testing.T) {
	if got := e3StalledComponent(); got != "" {
		t.Fatalf("e3StalledComponent() = %q, want \"\" (RELAYD_E3_STALL_COMPONENT is not set in this test run)", got)
	}
}

func TestE3DegradedTimeoutOverride_UnsetIsZero(t *testing.T) {
	if got := e3DegradedTimeoutOverride(); got != 0 {
		t.Fatalf("e3DegradedTimeoutOverride() = %v, want 0 (RELAYD_E3_DEGRADED_TIMEOUT is not set in this test run)", got)
	}
}

// TestParseE3DegradedTimeout_Standalone exercises the same parsing rules
// e3DegradedTimeoutOverride applies (valid, invalid, non-positive), as a
// pure function of a string, so every branch is covered without needing
// to fork a subprocess just to get a fresh sync.Once.
func TestParseE3DegradedTimeout_Standalone(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", 0},
		{"not-a-duration", 0},
		{"0s", 0},
		{"-5s", 0},
		{"10s", 10 * time.Second},
	}
	for _, c := range cases {
		got := parseE3DegradedTimeout(c.raw)
		if got != c.want {
			t.Errorf("parseE3DegradedTimeout(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}
