//go:build testca

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/telemetry"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// E3 only (step-07b-decisions-2.md E1.3, step 7b V3: measure, don't
// guess). The testca build reads these environment variables, set by an
// E3 drop-in, so one E3 run can compare settings on the same machine:
//
//	RELAYD_E3_HANDOFF_CHUNK      telemetry.Config.HandoffChunk (1: per event)
//	RELAYD_E3_TETRA_READ_BUFFER  tetra.Config.ReadBufferSize (bytes)
//	RELAYD_E3_TETRA_WINDOW       tetra.Config.InitialWindowSize (bytes)
//	RELAYD_E3_SOURCE_RATE        at most this many GetEvents messages per
//	                             second are read from Tetragon (T-S6's
//	                             slow client)
//
// Unset or unparsable means the default. What was applied is audited.
type e3Knobs struct{ handoffChunk, sourceRate int }

func e3Tuning(auditor agent.Auditor, tc tetra.Config) (tetra.Config, e3Knobs) {
	get := func(name string) int {
		v, err := strconv.Atoi(os.Getenv(name))
		if err != nil || v <= 0 {
			return 0
		}
		return v
	}
	k := e3Knobs{handoffChunk: get("RELAYD_E3_HANDOFF_CHUNK"), sourceRate: get("RELAYD_E3_SOURCE_RATE")}
	tc.ReadBufferSize = get("RELAYD_E3_TETRA_READ_BUFFER")
	if w := get("RELAYD_E3_TETRA_WINDOW"); w <= 1<<30 {
		tc.InitialWindowSize = int32(w) //nolint:gosec // G115: bounded above
	}
	auditor.Record(agent.AuditEvent{Step: "e3_tuning", Detail: fmt.Sprintf("handoff_chunk=%d tetra_read_buffer=%d tetra_window=%d source_rate=%d (0: default)", k.handoffChunk, tc.ReadBufferSize, tc.InitialWindowSize, k.sourceRate)})
	return tc, k
}

// e3Source paces src's deliveries to k.sourceRate per second, if set:
// while deliver sleeps, nothing more is read from the socket, so Tetragon
// sees a client that reads that slowly.
func e3Source(src telemetry.EventSource, k e3Knobs) telemetry.EventSource {
	if k.sourceRate <= 0 {
		return src
	}
	return pacedSource{src: src, every: time.Second / time.Duration(k.sourceRate)}
}

type pacedSource struct {
	src   telemetry.EventSource
	every time.Duration
}

func (p pacedSource) StreamEvents(ctx context.Context, types []tetragonpb.EventType, exclude []string, deliver func([]byte) bool) error {
	next := time.Now()
	return p.src.StreamEvents(ctx, types, exclude, func(raw []byte) bool {
		if d := time.Until(next); d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return false
			}
		}
		next = time.Now().Add(p.every)
		return deliver(raw)
	})
}
