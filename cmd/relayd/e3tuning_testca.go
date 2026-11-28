//go:build testca

package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

// E3 only (step-07b-decisions-2.md E1.3: measure, don't guess). The testca
// build reads three environment variables, set by an E3 drop-in, so one E3
// run can compare settings on the same machine:
//
//	RELAYD_E3_HANDOFF_CHUNK      telemetry.Config.HandoffChunk (1: per event)
//	RELAYD_E3_TETRA_READ_BUFFER  tetra.Config.ReadBufferSize (bytes)
//	RELAYD_E3_TETRA_WINDOW       tetra.Config.InitialWindowSize (bytes)
//
// Unset or unparsable means the default. What was applied is audited.
func e3Tuning(auditor agent.Auditor, tc tetra.Config) (tetra.Config, int) {
	get := func(name string) int {
		v, err := strconv.Atoi(os.Getenv(name))
		if err != nil || v <= 0 {
			return 0
		}
		return v
	}
	chunk := get("RELAYD_E3_HANDOFF_CHUNK")
	tc.ReadBufferSize = get("RELAYD_E3_TETRA_READ_BUFFER")
	if w := get("RELAYD_E3_TETRA_WINDOW"); w <= 1<<30 {
		tc.InitialWindowSize = int32(w) //nolint:gosec // G115: bounded above
	}
	auditor.Record(agent.AuditEvent{Step: "e3_tuning", Detail: fmt.Sprintf("handoff_chunk=%d tetra_read_buffer=%d tetra_window=%d (0: default)", chunk, tc.ReadBufferSize, tc.InitialWindowSize)})
	return tc, chunk
}
