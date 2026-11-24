//go:build integration

// Temporary diagnostic for step-04a prompt Part A3 (step-03b-review.md
// R3B-3): re-run the original E1 experiment (ADR 0020, PR #2, deleted)
// with every trigger's wall-clock time recorded, and for each trigger
// after AddTracingPolicy returns, whether a matching event exists, using
// the EVENT'S OWN kernel timestamp (GetEventsResponse.Time, not this
// test's delivery-time observation of it). NOT for merge: this file and
// its throwaway branch/PR are deleted once the measurement is recorded in
// docs/reports/step-04a.md.
//
// Unlike the original E1 (no selectors at all, since the caller-vs-
// new-image semantics ADR 0020 later established were not yet known),
// this version scopes matchBinaries to this test binary's own path
// (os.Executable()): security_bprm_check fires on the forked child before
// its image is replaced, so the reported process.binary is still this Go
// test binary's own path and process.pid is the freshly-forked child's
// pid, which this test can correlate 1:1 against each trigger's
// exec.Cmd.Process.Pid. This eliminates cross-host noise and lets each of
// the ~100ms-spaced triggers be matched to its own event individually,
// rather than only observing the first event as the original E1 did.
package apply

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// a3Trigger records one exec(/usr/bin/true) trigger: its wall-clock time
// (immediately before the forked child's exec.Cmd.Start() call returns,
// i.e. after fork but essentially at the moment the child performs its
// own execve) and its pid.
type a3Trigger struct {
	index   int
	pid     uint32
	trigger time.Time
}

// a3Event records one matching security_bprm_check event: the event's own
// kernel timestamp (GetEventsResponse.Time, read directly off the raw
// proto response rather than through internal/tetra.Event, which does not
// carry it) and this test's own delivery-time observation of when it
// arrived, for comparison.
type a3Event struct {
	pid       uint32
	kernel    time.Time
	delivered time.Time
}

// TestDiagnoseA3_E1_PerTriggerGap connects directly to the real Tetragon
// socket with the raw tetragonpb client (bypassing internal/tetra.Client,
// whose Event type intentionally does not carry the kernel Time field —
// see client.go's doc comment), so this diagnostic can read
// GetEventsResponse.Time directly.
func TestDiagnoseA3_E1_PerTriggerGap(t *testing.T) {
	selfPath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	// dialIntegration (internal/tetra.Dial) already verifies the socket
	// and peer; reuse it only to get a known-good SocketPath and to
	// AddTracingPolicy/DeleteTracingPolicy through the already-allowlisted,
	// already-verified path. The raw GetEvents stream below is opened as
	// a second, unverified connection purely to read the Time field this
	// diagnostic needs; it never calls anything outside the same 8-RPC
	// allowlist internal/tetra itself uses.
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	t0 := time.Now()
	elapsed := func() string { return time.Since(t0).String() }

	yaml := fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: %q
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    selectors:
    - matchActions:
      - action: "Post"
      matchBinaries:
      - operator: "In"
        values:
        - %q
`, "diag-a3-e1", selfPath)

	doc, err := RealPolicyParser{}.Parse("diag-a3-e1", yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	canonicalJSON := doc.CanonicalJSON()
	loadedName, err := LoadedName("diag-a3-e1", 1, canonicalJSON)
	if err != nil {
		t.Fatalf("LoadedName: %v", err)
	}
	named, err := setMetadataName(canonicalJSON, loadedName)
	if err != nil {
		t.Fatalf("setMetadataName: %v", err)
	}

	ctx := context.Background()
	addReturnedAt := time.Now()
	if err := client.AddTracingPolicy(ctx, string(named), RelayDomain); err != nil {
		t.Fatalf("AddTracingPolicy: %v", err)
	}
	t.Logf("[%s] AddTracingPolicy returned", elapsed())
	defer func() { _ = client.DeleteTracingPolicy(ctx, loadedName, RelayDomain) }()

	conn, err := grpc.NewClient("unix://"+integrationSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("raw grpc.NewClient: %v", err)
	}
	defer func() { _ = conn.Close() }()
	raw := tetragonpb.NewFineGuidanceSensorsClient(conn)

	streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stream, err := raw.GetEvents(streamCtx, &tetragonpb.GetEventsRequest{
		AllowList: []*tetragonpb.Filter{{PolicyNames: []string{loadedName}}},
	})
	if err != nil {
		t.Fatalf("raw GetEvents: %v", err)
	}

	var mu sync.Mutex
	var events []a3Event
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			resp, err := stream.Recv()
			if err != nil {
				t.Logf("[%s] raw stream ended: %v", elapsed(), err)
				return
			}
			kp, ok := resp.GetEvent().(*tetragonpb.GetEventsResponse_ProcessKprobe)
			if !ok {
				continue
			}
			ev := a3Event{
				pid:       kp.ProcessKprobe.GetProcess().GetPid().GetValue(),
				delivered: time.Now(),
			}
			if resp.GetTime() != nil {
				ev.kernel = resp.GetTime().AsTime()
			}
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
			t.Logf("[%s] KPROBE event: pid=%d kernel_time=%s binary=%q", elapsed(), ev.pid, ev.kernel.Format(time.RFC3339Nano), kp.ProcessKprobe.GetProcess().GetBinary())
		}
	}()

	// Give the subscription a moment to establish server-side before the
	// first trigger, same as the original diagnostics did.
	time.Sleep(200 * time.Millisecond)
	t.Logf("[%s] starting trigger loop (every 100ms for 10s)", elapsed())

	var triggers []a3Trigger
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		cmd := exec.Command("/usr/bin/true")
		triggerAt := time.Now()
		if err := cmd.Start(); err != nil {
			t.Fatalf("exec #%d Start: %v", i, err)
		}
		pid := uint32(cmd.Process.Pid) //nolint:gosec // diagnostic-only test; pids never negative in practice
		triggers = append(triggers, a3Trigger{index: i, pid: pid, trigger: triggerAt})
		_ = cmd.Wait()
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("[%s] trigger loop done: %d triggers", elapsed(), len(triggers))

	// Give in-flight events a little longer to arrive before closing the
	// stream, then stop it and wait for the receive goroutine to exit.
	time.Sleep(2 * time.Second)
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	byPID := make(map[uint32]a3Event, len(events))
	for _, ev := range events {
		byPID[ev.pid] = ev
	}

	t.Logf("=== A3 per-trigger table (trigger# | wall-clock trigger time | pid | matched | kernel_time | kernel-trigger delta) ===")
	addReturnedElapsed := addReturnedAt.Sub(t0)
	t.Logf("AddTracingPolicy returned at %s (elapsed %s)", addReturnedAt.Format(time.RFC3339Nano), addReturnedElapsed)
	firstMatchIndex := -1
	unmatched := 0
	for _, tr := range triggers {
		ev, ok := byPID[tr.pid]
		if !ok {
			unmatched++
			t.Logf("trigger #%d | t=%s | pid=%d | NO MATCHING EVENT", tr.index, tr.trigger.Format(time.RFC3339Nano), tr.pid)
			continue
		}
		if firstMatchIndex == -1 {
			firstMatchIndex = tr.index
		}
		t.Logf("trigger #%d | t=%s | pid=%d | matched | kernel_time=%s | kernel-trigger=%s | since_add=%s",
			tr.index, tr.trigger.Format(time.RFC3339Nano), tr.pid, ev.kernel.Format(time.RFC3339Nano),
			ev.kernel.Sub(tr.trigger), tr.trigger.Sub(addReturnedAt))
	}
	t.Logf("=== summary: %d/%d triggers matched, first match at trigger #%d, %d unmatched ===", len(triggers)-unmatched, len(triggers), firstMatchIndex, unmatched)
	if unmatched > 0 {
		t.Logf("STOP CONDITION: %d of %d triggers after AddTracingPolicy returned had no matching event (possible enforcement gap) - see step-03b-review.md R3B-3", unmatched, len(triggers))
	}
}
