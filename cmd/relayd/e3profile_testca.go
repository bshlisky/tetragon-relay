//go:build testca

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/agent"
)

// E3 only (step 7b D1: "profile relayd itself in E3"). On SIGUSR1 the
// testca build writes a CPU profile of the whole process for
// e3ProfileFor to e3ProfilePath, in the unit's RuntimeDirectory (already
// writable by relayd: no new path, no new privilege). Go's profiler uses
// timer_create/setitimer, which the unit's @system-service filter allows.
const (
	e3ProfilePath = "/run/tetragon-relay/e3-cpu.pprof"
	e3ProfileFor  = 50 * time.Second
)

func startE3Profiler(ctx context.Context, auditor agent.Auditor) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				auditor.Record(agent.AuditEvent{Step: "e3_cpu_profile", Detail: fmt.Sprintf("%s for %s", e3ProfilePath, e3ProfileFor), Err: e3Profile(ctx)})
			}
		}
	}()
}

func e3Profile(ctx context.Context) error {
	f, err := os.OpenFile(e3ProfilePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		return err
	}
	select {
	case <-ctx.Done():
	case <-time.After(e3ProfileFor):
	}
	pprof.StopCPUProfile()
	return f.Close()
}
