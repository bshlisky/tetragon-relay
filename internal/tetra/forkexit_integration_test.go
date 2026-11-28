//go:build integration

// step-07b-decisions-3.md F2 (report only): what exit events a fork-only
// child produces on the real Tetragon v1.8.0. relayd's drop estimate pairs
// exits with execs on exec_id; E3 run 46149776060 showed idle "losses"
// when an exit removed its exec, consistent with the API's note that
// Tetragon does not track forks exactly (Process.flags `taskWalk`).
//
// A private copy of bash runs `( : ); ( : ); /usr/bin/true`: two pure
// forks (a builtin in a subshell never execs) and one exec. The test
// prints every exec and exit whose process or parent is the marker, with
// exec_id and flags. Run 46156508611 showed each fork-only child exiting
// with its own exec_id, no exec, and its parent's binary. relayd's rule
// (count an unpaired exit only if both binaries are known and differ) is
// asserted: it must count none of them.
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

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

func TestIntegration_ForkOnlyChildExits(t *testing.T) {
	c := dialIntegration(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "forkmarker")
	src, err := os.ReadFile("/usr/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, src, 0o755); err != nil { //nolint:gosec // G306: an executable test copy
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	types := []tetragonpb.EventType{tetragonpb.EventType_PROCESS_EXEC, tetragonpb.EventType_PROCESS_EXIT}
	stream, err := c.stub.GetEvents(ctx, &tetragonpb.GetEventsRequest{AllowList: []*tetragonpb.Filter{{EventSet: types}}}, grpc.ForceCodecV2(rawResponseCodec{}))
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	var mu sync.Mutex
	var lines []string
	exitsByID := map[string]int{}
	ruleCounted := 0
	execIDs := map[string]bool{}
	go func() {
		for {
			var b []byte
			if err := stream.RecvMsg(&b); err != nil {
				return
			}
			var ev tetragonpb.GetEventsResponse
			if proto.Unmarshal(b, &ev) != nil {
				continue
			}
			var kind string
			var p, parent *tetragonpb.Process
			switch {
			case ev.GetProcessExec() != nil:
				kind, p, parent = "exec", ev.GetProcessExec().GetProcess(), ev.GetProcessExec().GetParent()
			case ev.GetProcessExit() != nil:
				kind, p, parent = "exit", ev.GetProcessExit().GetProcess(), ev.GetProcessExit().GetParent()
			default:
				continue
			}
			if p.GetBinary() != marker && parent.GetBinary() != marker {
				continue
			}
			mu.Lock()
			lines = append(lines, kind+" binary="+p.GetBinary()+" exec_id="+p.GetExecId()+" pid="+itoa(p.GetPid().GetValue())+" flags="+p.GetFlags()+" parent="+parent.GetBinary())
			if kind == "exec" {
				execIDs[p.GetExecId()] = true
			} else {
				exitsByID[p.GetExecId()]++
				if !execIDs[p.GetExecId()] && p.GetBinary() != "" && parent.GetBinary() != "" && p.GetBinary() != parent.GetBinary() {
					ruleCounted++
				}
			}
			mu.Unlock()
		}
	}()
	time.Sleep(2 * time.Second)
	cmd := exec.Command(marker, "-c", "( : ); ( : ); /usr/bin/true")
	cmd.Dir = "/tmp"
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("marker: %v %s", err, out)
	}
	time.Sleep(4 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	for _, l := range lines {
		t.Logf("FORKEXIT %s", l)
	}
	unpaired := 0
	for id, n := range exitsByID {
		t.Logf("FORKEXIT exec_id=%s exits=%d exec_seen=%t", id, n, execIDs[id])
		if !execIDs[id] {
			unpaired += n
		}
	}
	t.Logf("FORKEXIT summary: %d exec, %d distinct exit exec_ids, %d exits with no exec on this stream, %d counted by relayd's rule", len(execIDs), len(exitsByID), unpaired, ruleCounted)
	if ruleCounted != 0 {
		t.Fatalf("relayd's pairing rule would count %d fork-only exits as Tetragon drops", ruleCounted)
	}
}

func itoa(v uint32) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{digits[v%10]}, b...)
		v /= 10
	}
	return string(b)
}
