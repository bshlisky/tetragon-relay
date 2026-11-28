//go:build e3

// Command e3execflood is the E3 job's exec-event generator
// (docs/reviews/step-07b-decisions-2.md E1.1): N workers, each in a tight
// fork/execve loop of a short-lived binary (/usr/bin/true by default) for a
// fixed duration. Each exec is one process_exec and one process_exit event
// in Tetragon. The shell loops it replaces spent most of their time in bash;
// this one spends it in clone, execve and wait4.
//
// It prints one line at the end, which scripts/e3-run.sh parses:
//
//	e3execflood workers=4 secs=60.0 execs=812345 generated=1624690 rate=27078/s failed=0
//
// generated is 2 x execs (exec + exit). With --rate R the workers together
// start at most R execs per second (T-S6's slow-client experiment);
// --rate 0, the default, means as fast as the runner can. SIGTERM or SIGINT
// ends the run early, and the summary line is still printed.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	workers := flag.Int("workers", 4, "number of concurrent fork/execve loops")
	dur := flag.Duration("duration", 60*time.Second, "how long to generate")
	bin := flag.String("binary", "/usr/bin/true", "binary to exec (must exit quickly)")
	rate := flag.Int("rate", 0, "total execs per second across all workers (0: unlimited)")
	flag.Parse()
	if *workers < 1 || *dur <= 0 || *rate < 0 {
		fmt.Fprintln(os.Stderr, "e3execflood: --workers >= 1, --duration > 0, --rate >= 0")
		os.Exit(2)
	}
	if _, err := os.Stat(*bin); err != nil {
		fmt.Fprintf(os.Stderr, "e3execflood: %v\n", err)
		os.Exit(2)
	}

	var execs, failed atomic.Int64
	var stop atomic.Bool
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; stop.Store(true) }()
	start := time.Now()
	deadline := start.Add(*dur)
	// Per-worker pacing: worker w may start its k-th exec at
	// start + k*interval, interval = workers/rate.
	var interval time.Duration
	if *rate > 0 {
		interval = time.Duration(float64(time.Second) * float64(*workers) / float64(*rate))
	}
	argv := []string{*bin}
	attr := &syscall.ProcAttr{Env: []string{}, Files: []uintptr{0, 1, 2}}

	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := time.Now()
			for k := 0; ; k++ {
				now := time.Now()
				if stop.Load() || !now.Before(deadline) {
					return
				}
				if interval > 0 {
					if d := next.Sub(now); d > 0 {
						time.Sleep(d)
					}
					next = next.Add(interval)
				}
				pid, err := syscall.ForkExec(*bin, argv, attr)
				if err != nil {
					failed.Add(1)
					continue
				}
				var ws syscall.WaitStatus
				for {
					_, err = syscall.Wait4(pid, &ws, 0, nil)
					if err != syscall.EINTR {
						break
					}
				}
				execs.Add(1)
			}
		}()
	}
	wg.Wait()
	secs := time.Since(start).Seconds()
	n := execs.Load()
	fmt.Printf("e3execflood workers=%d secs=%.1f execs=%d generated=%d rate=%.0f/s failed=%d\n",
		*workers, secs, n, 2*n, float64(2*n)/secs, failed.Load())
}
