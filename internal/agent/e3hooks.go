//go:build !testca

package agent

import "time"

// e3StalledComponent always returns "" outside the testca build: no
// production, or default-tagged, build can ever make RunSession skip a
// LivenessRegistry Touch call via this hook. Only the testca build
// (e3hooks_testca.go) reads any environment variable here at all --
// step-06a-e3-prompt.md S6's "a test-tagged hook that blocks the session
// loop" is this hook, never reachable from a production relayd binary
// because this file (not e3hooks_testca.go) is the one compiled into
// it.
func e3StalledComponent() string { return "" }

// e3DegradedTimeoutOverride always returns 0 (meaning "no override")
// outside the testca build: connectWithDegradedWatch always uses
// limits.ControlConnectDegradedTimeout (5 min) in every production and
// default-tagged build. Only the testca build (CI's E3 job, S5) may
// shorten this, and only via an explicit environment variable read once
// at startup -- step-06a-e3-prompt.md S5: "You may shorten the threshold
// only through a testca-tagged constant override."
func e3DegradedTimeoutOverride() time.Duration { return 0 }
