//go:build integration

// Temporary diagnostic for TestIntegration_RollbackOnAdminPathKill's
// real-Tetragon failure. NOT for merge: this file exists only to gather
// evidence on a throwaway branch/PR run and must be deleted before this
// branch's findings are folded into a real fix on main.
package apply

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestDiagnose_AdminPathKill(t *testing.T) {
	client := dialIntegration(t)
	defer func() { _ = client.Close() }()

	t0 := time.Now()
	elapsed := func() string { return time.Since(t0).String() }

	yaml := canaryPolicyYAML("diag-admin-kill", "Sigkill")
	yaml = withBinaryPath(yaml, "/usr/bin/bash")

	doc, err := RealPolicyParser{}.Parse("diag-admin-kill", yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	canonicalJSON := doc.CanonicalJSON()
	loadedName, err := LoadedName("diag-admin-kill", 1, canonicalJSON)
	if err != nil {
		t.Fatalf("LoadedName: %v", err)
	}
	named, err := setMetadataName(canonicalJSON, loadedName)
	if err != nil {
		t.Fatalf("setMetadataName: %v", err)
	}
	t.Logf("[%s] computed loadedName=%q", elapsed(), loadedName)

	ctx := context.Background()
	if err := client.AddTracingPolicy(ctx, string(named), RelayDomain); err != nil {
		t.Fatalf("AddTracingPolicy: %v", err)
	}
	t.Logf("[%s] AddTracingPolicy returned", elapsed())

	statuses, err := client.ListTracingPolicies(ctx, "")
	if err != nil {
		t.Fatalf("ListTracingPolicies: %v", err)
	}
	for _, s := range statuses {
		t.Logf("[%s] loaded policy: name=%q domain=%q state=%v", elapsed(), s.Name, s.Domain, s.State)
	}

	eventsCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	events, errc := client.GetEvents(eventsCtx, []string{loadedName})
	t.Logf("[%s] GetEvents call returned (subscription request sent)", elapsed())

	var mu sync.Mutex
	var log []string
	record := func(s string) {
		mu.Lock()
		log = append(log, s)
		mu.Unlock()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					record(fmt.Sprintf("[%s] events channel closed", elapsed()))
					return
				}
				if ev.Kprobe != nil {
					record(fmt.Sprintf("[%s] KPROBE event: action=%v policy_name=%q func=%q process.binary=%q parent.binary=%q ancestors=%d",
						elapsed(), ev.Kprobe.GetAction(), ev.Kprobe.GetPolicyName(), ev.Kprobe.GetFunctionName(),
						ev.Kprobe.GetProcess().GetBinary(), ev.Kprobe.GetParent().GetBinary(), len(ev.Kprobe.GetAncestors())))
				} else {
					record(fmt.Sprintf("[%s] non-kprobe event: %+v", elapsed(), ev))
				}
			case e, ok := <-errc:
				if !ok {
					record(fmt.Sprintf("[%s] errc channel closed", elapsed()))
					return
				}
				record(fmt.Sprintf("[%s] errc: %v", elapsed(), e))
			}
		}
	}()

	// Give the subscription a moment to actually establish server-side
	// before the first exec, purely for this diagnostic's own
	// observability (not a production assumption).
	time.Sleep(200 * time.Millisecond)
	t.Logf("[%s] starting bash exec loop", elapsed())

	killed := 0
	attempts := 0
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		attempts++
		cmd := exec.Command("/usr/bin/bash", "-c", "true")
		execErr := cmd.Run()
		if execErr != nil {
			killed++
			record(fmt.Sprintf("[%s] exec #%d error: %v ProcessState=%v", elapsed(), attempts, execErr, cmd.ProcessState))
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("[%s] exec loop done: attempts=%d killed=%d", elapsed(), attempts, killed)

	cancel()
	<-done

	mu.Lock()
	for _, l := range log {
		t.Log(l)
	}
	mu.Unlock()

	statuses, err = client.ListTracingPolicies(ctx, "")
	if err != nil {
		t.Logf("ListTracingPolicies (post): %v", err)
	}
	for _, s := range statuses {
		t.Logf("[%s] post-run loaded policy: name=%q domain=%q state=%v", elapsed(), s.Name, s.Domain, s.State)
	}

	_ = client.DeleteTracingPolicy(ctx, loadedName, RelayDomain)
}
