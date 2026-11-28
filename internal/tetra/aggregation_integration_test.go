//go:build integration

// step-07b-decisions-2.md E1.5: GetEventsRequest.aggregation_options on the
// real Tetragon v1.8.0, checked rather than assumed (report only; relayd
// does not set it). The vendored API says only process_accept and
// process_connect are aggregated, other events "remain unaggregated", and
// that the aggregator drops events, with only a log line in Tetragon, when
// its channel buffer is full.
//
// Each round opens a GetEvents stream for PROCESS_EXEC and PROCESS_EXIT,
// with aggregation_options (a 5 s window, the default buffer) or without
// (the control), runs the same marker command 20 times, and counts the
// marker's exec and exit responses and any response carrying
// aggregation_info. Rounds alternate, three of each. The counts are
// printed for the report. It fails only if a response is aggregated:
// delivery counts are data (run 46119904742 saw 19 exec / 20 exit in one
// aggregated round, run 46117755144 20 / 20).
package tetra

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

type aggRound struct{ execs, exits, aggregated, total int }

func aggregationRound(t *testing.T, c *Client, marker string, aggregate bool) aggRound {
	t.Helper()
	const runs = 20
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	types := []tetragonpb.EventType{tetragonpb.EventType_PROCESS_EXEC, tetragonpb.EventType_PROCESS_EXIT}
	req := &tetragonpb.GetEventsRequest{AllowList: []*tetragonpb.Filter{{EventSet: types}}}
	if aggregate {
		req.AggregationOptions = &tetragonpb.AggregationOptions{WindowSize: durationpb.New(5 * time.Second)}
	}
	stream, err := c.stub.GetEvents(ctx, req, grpc.ForceCodecV2(rawResponseCodec{}))
	if err != nil {
		t.Fatalf("GetEvents (aggregate=%v): %v", aggregate, err)
	}
	var mu sync.Mutex
	var r aggRound
	errc := make(chan error, 1)
	go func() {
		for {
			var b []byte
			if err := stream.RecvMsg(&b); err != nil {
				errc <- err
				return
			}
			var ev tetragonpb.GetEventsResponse
			if proto.Unmarshal(b, &ev) != nil {
				continue
			}
			mu.Lock()
			r.total++
			if ev.GetAggregationInfo() != nil {
				r.aggregated++
			}
			if ev.GetProcessExec().GetProcess().GetBinary() == marker {
				r.execs++
			}
			if ev.GetProcessExit().GetProcess().GetBinary() == marker {
				r.exits++
			}
			mu.Unlock()
		}
	}()
	time.Sleep(2 * time.Second) // the stream is open before the execs
	for i := 0; i < runs; i++ {
		cmd := exec.Command(marker, "--agg-marker")
		cmd.Dir = "/tmp"
		if err := cmd.Run(); err != nil {
			t.Fatalf("marker run: %v", err)
		}
	}
	// Past one aggregation window, so an aggregated summary would be out.
	time.Sleep(7 * time.Second)
	select {
	case err := <-errc:
		if ctx.Err() == nil {
			t.Fatalf("stream ended (aggregate=%v): %v", aggregate, err)
		}
	default:
	}
	mu.Lock()
	defer mu.Unlock()
	return r
}

func TestIntegration_AggregationOptions(t *testing.T) {
	c := dialIntegration(t)
	marker := filepath.Join(t.TempDir(), "agg-marker-true")
	raw, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, raw, 0o755); err != nil { //nolint:gosec // G306: an executable test copy
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		aggregate := i%2 == 0
		r := aggregationRound(t, c, marker, aggregate)
		t.Logf("AGGREGATION round=%d aggregation_options=%v window=5s buffer=default: marker runs=20 exec=%d exit=%d responses_with_aggregation_info=%d (of %d responses)",
			i, aggregate, r.execs, r.exits, r.aggregated, r.total)
		if r.aggregated != 0 {
			t.Errorf("round %d: %d responses carried aggregation_info for exec/exit", i, r.aggregated)
		}
	}
}
