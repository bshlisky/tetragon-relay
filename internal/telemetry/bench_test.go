package telemetry

import (
	"context"
	"runtime"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

func benchEvent(i int) *tetragonpb.GetEventsResponse {
	proc := func(bin, args string) *tetragonpb.Process {
		return &tetragonpb.Process{
			ExecId: "aG9zdDoxMjM0NTY3ODkwOjEyMzQ1", Cwd: "/var/lib/app",
			Binary: bin, Arguments: args, Flags: "execve rootcwd clone", StartTime: timestamppb.New(time.Unix(1700000000, int64(i))),
			EnvironmentVariables: []*tetragonpb.EnvVar{{Key: "PATH", Value: "/usr/bin:/bin"}, {Key: "TOKEN", Value: "secret"}},
		}
	}
	return &tetragonpb.GetEventsResponse{
		Time:     timestamppb.New(time.Unix(1700000000, int64(i))),
		NodeName: "host-0001.prod.example.internal",
		Event: &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{
			Process:   proc("/usr/bin/curl", "-s --header token=abcdef https://internal.example/api/v1/items?id=12345"),
			Parent:    proc("/usr/bin/bash", "-c /opt/app/bin/poll.sh"),
			Ancestors: []*tetragonpb.Process{proc("/usr/lib/systemd/systemd", "--system --deserialize 31")},
		}},
	}
}

// BenchmarkPipeline5k runs the whole pipeline (redact, marshal, batch,
// chain, HMAC'd spool with fsync, export, ack, delete) on a realistic exec
// event (process, parent and one ancestor, ~1 KiB marshaled). It reports
// CPU time per event and the share of one core that 5,000 events/s would
// use (architecture doc 8.13: < 1%), and the process's max RSS.
func BenchmarkPipeline5k(b *testing.B) {
	cfg := spoolCfg(&testing.T{}, b.TempDir(), OSFS{}, "boot-a")
	s, err := OpenSpool(cfg)
	if err != nil {
		b.Fatal(err)
	}
	red, _ := NewRedactor(nil)
	src := &chanSource{ch: make(chan *tetragonpb.GetEventsResponse, 4096)}
	col := &memCollector{discard: true}
	p, _ := New(Config{
		Source: src, EventTypes: []tetragonpb.EventType{1}, Redactor: red, Spool: s, Dialer: col,
		BatchMaxEvents: 2000, BatchMaxAge: 2 * time.Second, Clock: time.Now, Auditor: cfg.Auditor, Liveness: &fakeLiveness{},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	// The cost of building the input events is measured separately and
	// subtracted: it is the benchmark's, not the pipeline's.
	var gb, ga syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &gb)
	for i := 0; i < b.N; i++ {
		_ = benchEvent(i)
	}
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ga)
	genCPU := ga.Utime.Nano() + ga.Stime.Nano() - gb.Utime.Nano() - gb.Stime.Nano()
	var before syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		src.ch <- benchEvent(i) // a fresh message each time: redaction mutates it
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		st := s.Stats()
		if p.events != nil && len(p.events) == 0 && st.Backlog == 0 && time.Since(start) > 2100*time.Millisecond {
			break
		}
		if time.Now().After(deadline) {
			b.Fatalf("pipeline did not drain: %+v", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.StopTimer()
	var after syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	cancel()
	<-done
	cpu := time.Duration(after.Utime.Nano()+after.Stime.Nano()-before.Utime.Nano()-before.Stime.Nano()-genCPU) * time.Nanosecond
	perEvent := float64(cpu.Nanoseconds()) / float64(b.N)
	b.ReportMetric(perEvent, "cpu-ns/event")
	b.ReportMetric(perEvent*5000/1e9*100, "%core@5k/s")
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b.ReportMetric(float64(ms.Sys)/(1<<20), "go-sys-MiB")
	b.ReportMetric(float64(maxRSSBytes(after))/(1<<20), "maxrss-MiB")
}
