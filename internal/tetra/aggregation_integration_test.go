//go:build integration

// step-07b-decisions-2.md E1.5: GetEventsRequest.aggregation_options on the
// real Tetragon v1.8.0, checked rather than assumed (report only; relayd
// does not set it). The vendored API says only process_accept and
// process_connect are aggregated, other events "remain unaggregated", and
// that the aggregator drops events, with only a log line in Tetragon, when
// its channel buffer is full.
//
// The test opens a GetEvents stream for PROCESS_EXEC and PROCESS_EXIT with
// aggregation_options set (a 5 s window, the default buffer), runs
// the same marker command 20 times within the window, and counts the
// marker's exec and exit responses and any response carrying
// aggregation_info. It prints what it saw for the report and fails if the
// count of messages went down or any field changed shape (aggregated
// responses), which would contradict the API's comment.
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
	const runs = 20
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	types := []tetragonpb.EventType{tetragonpb.EventType_PROCESS_EXEC, tetragonpb.EventType_PROCESS_EXIT}
	req := &tetragonpb.GetEventsRequest{
		AllowList:          []*tetragonpb.Filter{{EventSet: types}},
		AggregationOptions: &tetragonpb.AggregationOptions{WindowSize: durationpb.New(5 * time.Second)},
	}
	stream, err := c.stub.GetEvents(ctx, req, grpc.ForceCodecV2(rawResponseCodec{}))
	if err != nil {
		t.Fatalf("GetEvents with aggregation_options: %v", err)
	}
	var mu sync.Mutex
	var execs, exits, aggregated, total int
	var sample *tetragonpb.ProcessExec
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
			total++
			if ev.GetAggregationInfo() != nil {
				aggregated++
			}
			if e := ev.GetProcessExec(); e != nil && e.GetProcess().GetBinary() == marker {
				execs++
				if sample == nil {
					sample = e
				}
			}
			if e := ev.GetProcessExit(); e != nil && e.GetProcess().GetBinary() == marker {
				exits++
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
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := execs >= runs && exits >= runs
		mu.Unlock()
		if done {
			break
		}
		select {
		case err := <-errc:
			t.Fatalf("stream ended: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
	}
	time.Sleep(6 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	t.Logf("AGGREGATION window=5s buffer=default: marker runs=%d exec=%d exit=%d responses_with_aggregation_info=%d (of %d responses)",
		runs, execs, exits, aggregated, total)
	if sample != nil {
		t.Logf("AGGREGATION sample exec: binary=%q args=%q pid=%d", sample.GetProcess().GetBinary(), sample.GetProcess().GetArguments(), sample.GetProcess().GetPid().GetValue())
	}
	if execs != runs || exits != runs {
		t.Fatalf("aggregation_options changed exec/exit delivery: %d exec, %d exit for %d runs", execs, exits, runs)
	}
	if aggregated != 0 {
		t.Fatalf("%d responses carried aggregation_info for exec/exit", aggregated)
	}
}
