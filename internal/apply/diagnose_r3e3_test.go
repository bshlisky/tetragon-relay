//go:build integration

// Temporary diagnostic (round 2) for TestIntegration_RollbackOnAdminPathKill's
// real-Tetragon failure. NOT for merge: this file exists only to gather
// evidence on a throwaway branch/PR run.
//
// Architect's corrected hypothesis: security_bprm_check's process/
// matchBinaries describe the CALLER of exec, not the new image about to be
// loaded. `bash -c true` execs nothing externally (`true` is a bash
// builtin), so the caller chain never produces a security_bprm_check event
// matching "/usr/bin/bash" at all; the caller of the FIRST exec is this Go
// test binary. E1 measures raw attach latency (no selectors, so our own
// exec of /usr/bin/true should trigger it immediately if attach is fast).
// E2 repeats the real scenario correctly: a copied bash at
// /tmp/testbin/bash as the matched CALLER, executing two external commands
// (avoiding bash's exec-tail-call optimization for a single trailing
// command) so bash itself remains the caller when it execs /usr/bin/true.
package apply

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll("/tmp/testbin", 0o755); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src) //nolint:gosec // diagnostic-only test, src is a fixed system path
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //nolint:gosec // diagnostic-only test
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy %s -> %s: %v", src, dst, err)
	}
}

func TestDiagnoseE1_AttachLatency_NoSelectors(t *testing.T) {
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
`, "diag-e1-no-selectors")

	doc, err := RealPolicyParser{}.Parse("diag-e1-no-selectors", yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	canonicalJSON := doc.CanonicalJSON()
	loadedName, err := LoadedName("diag-e1-no-selectors", 1, canonicalJSON)
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

	eventsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	events, errc := client.GetEvents(eventsCtx, []string{loadedName})

	var mu sync.Mutex
	var firstEventAt time.Time
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					return
				}
				if ev.Kprobe != nil {
					mu.Lock()
					if firstEventAt.IsZero() {
						firstEventAt = time.Now()
					}
					mu.Unlock()
					t.Logf("[%s] KPROBE event: policy=%q process.binary=%q", elapsed(), ev.Kprobe.GetPolicyName(), ev.Kprobe.GetProcess().GetBinary())
				}
			case e, ok := <-errc:
				if !ok {
					return
				}
				t.Logf("[%s] errc: %v", elapsed(), e)
			}
		}
	}()

	deadline := time.Now().Add(20 * time.Second)
	attempts := 0
	for time.Now().Before(deadline) {
		mu.Lock()
		gotFirst := !firstEventAt.IsZero()
		mu.Unlock()
		if gotFirst {
			break
		}
		attempts++
		_ = exec.Command("/usr/bin/true").Run()
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if firstEventAt.IsZero() {
		t.Fatalf("[%s] no kprobe event observed after %d exec(/usr/bin/true) attempts over 20s", elapsed(), attempts)
	}
	t.Logf("ATTACH LATENCY: %s (AddTracingPolicy return -> first matching event), attempts=%d", firstEventAt.Sub(addReturnedAt), attempts)

	_ = client.DeleteTracingPolicy(ctx, loadedName, RelayDomain)
}

func TestDiagnoseE2_CallerSemantics_CopiedBash(t *testing.T) {
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	copyExecutable(t, "/usr/bin/bash", "/tmp/testbin/bash")

	t0 := time.Now()
	elapsed := func() string { return time.Since(t0).String() }

	yaml := canaryPolicyYAML("diag-e2-caller", "Sigkill")
	yaml = withBinaryPath(yaml, "/tmp/testbin/bash")

	doc, err := RealPolicyParser{}.Parse("diag-e2-caller", yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	canonicalJSON := doc.CanonicalJSON()
	loadedName, err := LoadedName("diag-e2-caller", 1, canonicalJSON)
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

	eventsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	events, errc := client.GetEvents(eventsCtx, []string{loadedName})

	var mu sync.Mutex
	var firstEventAt, firstKillAt time.Time
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					return
				}
				if ev.Kprobe != nil {
					mu.Lock()
					if firstEventAt.IsZero() {
						firstEventAt = time.Now()
					}
					if ev.Kprobe.GetAction().String() == "KPROBE_ACTION_SIGKILL" && firstKillAt.IsZero() {
						firstKillAt = time.Now()
					}
					mu.Unlock()
					t.Logf("[%s] KPROBE event: action=%v policy=%q process.binary=%q", elapsed(), ev.Kprobe.GetAction(), ev.Kprobe.GetPolicyName(), ev.Kprobe.GetProcess().GetBinary())
				}
			case e, ok := <-errc:
				if !ok {
					return
				}
				t.Logf("[%s] errc: %v", elapsed(), e)
			}
		}
	}()

	deadline := time.Now().Add(20 * time.Second)
	attempts := 0
	killed := 0
	for time.Now().Before(deadline) {
		attempts++
		cmd := exec.Command("/tmp/testbin/bash", "-c", "/usr/bin/true; /usr/bin/true")
		if err := cmd.Run(); err != nil {
			killed++
			t.Logf("[%s] exec #%d error: %v ProcessState=%v", elapsed(), attempts, err, cmd.ProcessState)
		}
		mu.Lock()
		gotKill := !firstKillAt.IsZero()
		mu.Unlock()
		if gotKill {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	t.Logf("attempts=%d killed=%d", attempts, killed)
	if firstEventAt.IsZero() {
		t.Errorf("[%s] no kprobe event observed at all for /tmp/testbin/bash as caller", elapsed())
	} else {
		t.Logf("TIME TO FIRST EVENT: %s", firstEventAt.Sub(addReturnedAt))
	}
	if firstKillAt.IsZero() {
		t.Errorf("[%s] no kill observed for /tmp/testbin/bash as caller", elapsed())
	} else {
		t.Logf("TIME TO FIRST KILL: %s", firstKillAt.Sub(addReturnedAt))
	}

	_ = client.DeleteTracingPolicy(ctx, loadedName, RelayDomain)
}
