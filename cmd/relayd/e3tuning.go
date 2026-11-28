//go:build !testca

package main

import (
	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/telemetry"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

// e3Knobs are the testca build's E3 measurement settings; production has
// none.
type e3Knobs struct{ handoffChunk int }

// e3Tuning is the identity outside the testca (E3) build: production
// relayd takes no tuning from its environment.
func e3Tuning(_ agent.Auditor, tc tetra.Config) (tetra.Config, e3Knobs) { return tc, e3Knobs{} }

// e3Source is the identity outside the testca build.
func e3Source(src telemetry.EventSource, _ e3Knobs) telemetry.EventSource { return src }
