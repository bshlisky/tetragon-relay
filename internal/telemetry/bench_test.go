package telemetry

import (
	"context"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// Step 7b P1: the pipeline benchmark measures the pipeline only. Its
// input is pre-built: benchCorpus marshals a varied corpus before the
// timer starts, and bytesSource only hands out those bytes. Decoding them
// (what gRPC does on the GetEvents stream) is the pipeline's first stage.
// Every pipeline goroutine runs under the pprof label pipeline=1 (labels
// are inherited by the goroutines Run starts), so a CPU profile separates
// them from the harness:
//
//	go tool pprof -tagfocus=pipeline=1 cpu.out
//
// cpu-ns/event is the process's CPU time (getrusage: user + system, every
// thread, GC included) over the measured window divided by the events.
// The harness does no work in that window except waiting, so it is an
// upper bound on the pipeline's own cost. scripts/bench-gate.sh gates it
// (step 7b P3: <= 6000 ns, 3 % of one core at 5k events/s).

const corpusSize = 8192

var benchInput = sync.OnceValue(func() [][]byte { return benchCorpus(corpusSize) })

// bytesSource decodes pre-built events, the way the GetEvents stream does,
// and delivers n of them.
type bytesSource struct {
	corpus    [][]byte
	n         int
	delivered atomic.Int64
}

func (s *bytesSource) StreamEvents(ctx context.Context, _ []tetragonpb.EventType, deliver func(*tetragonpb.GetEventsResponse) bool) error {
	for i := int(s.delivered.Load()); i < s.n; i++ {
		ev := new(tetragonpb.GetEventsResponse)
		if err := proto.Unmarshal(s.corpus[i%len(s.corpus)], ev); err != nil {
			return err
		}
		if !deliver(ev) {
			return nil
		}
		s.delivered.Add(1)
	}
	<-ctx.Done()
	return nil
}

func cpuNow() time.Duration {
	var r syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &r)
	return time.Duration(r.Utime.Nano() + r.Stime.Nano())
}

// BenchmarkPipeline5k runs the whole pipeline (decode, classify, redact,
// marshal, batch, chain, HMAC'd spool with fsync, export read, send to an
// in-process collector, ack, delete) on b.N corpus events.
func BenchmarkPipeline5k(b *testing.B) {
	corpus := benchInput()
	cfg := spoolCfg(&testing.T{}, b.TempDir(), OSFS{}, "boot-a")
	s, err := OpenSpool(cfg)
	if err != nil {
		b.Fatal(err)
	}
	red, _ := NewRedactor(nil)
	src := &bytesSource{corpus: corpus, n: b.N}
	col := &memCollector{discard: true}
	p, _ := New(Config{
		Source: src, EventTypes: []tetragonpb.EventType{1}, Redactor: red, Spool: s, Dialer: col,
		BatchMaxEvents: 2000, BatchMaxAge: 2 * time.Second, Clock: time.Now, Auditor: cfg.Auditor, Liveness: &fakeLiveness{},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	runtime.GC()
	b.ResetTimer()
	cpu0 := cpuNow()
	go pprof.Do(ctx, pprof.Labels("pipeline", "1"), func(ctx context.Context) { p.Run(ctx); close(done) })
	deadline := time.Now().Add(10 * time.Minute)
	for col.events.Load() < uint64(b.N) || s.Stats().Backlog != 0 {
		if time.Now().After(deadline) {
			b.Fatalf("pipeline did not drain: delivered %d, received %d, %+v", src.delivered.Load(), col.events.Load(), s.Stats())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cpu := cpuNow() - cpu0
	b.StopTimer()
	cancel()
	<-done
	perEvent := float64(cpu.Nanoseconds()) / float64(b.N)
	b.ReportMetric(perEvent, "cpu-ns/event")
	b.ReportMetric(perEvent*5000/1e9*100, "%core@5k/s")
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b.ReportMetric(float64(ms.Sys)/(1<<20), "go-sys-MiB")
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	b.ReportMetric(float64(maxRSSBytes(ru))/(1<<20), "maxrss-MiB")
}

// The per-stage benchmarks below split the cost. Stages that mutate their
// input work on chunks prepared with the timer stopped.

const stageChunk = 1024

func decodeChunk(b *testing.B, corpus [][]byte, off int) []*tetragonpb.GetEventsResponse {
	out := make([]*tetragonpb.GetEventsResponse, stageChunk)
	for i := range out {
		out[i] = new(tetragonpb.GetEventsResponse)
		if err := proto.Unmarshal(corpus[(off+i)%len(corpus)], out[i]); err != nil {
			b.Fatal(err)
		}
	}
	return out
}

// chunked runs f on b.N events, stageChunk at a time, preparing each chunk
// with the timer stopped. It reports cpu-ns/event over the timed parts.
func chunked(b *testing.B, prep func(off int) []*tetragonpb.GetEventsResponse, f func(evs []*tetragonpb.GetEventsResponse)) {
	b.ReportAllocs()
	var cpu time.Duration
	b.ResetTimer()
	for done := 0; done < b.N; done += stageChunk {
		b.StopTimer()
		evs := prep(done)
		if n := b.N - done; n < len(evs) {
			evs = evs[:n]
		}
		b.StartTimer()
		c0 := cpuNow()
		f(evs)
		cpu += cpuNow() - c0
	}
	b.ReportMetric(float64(cpu.Nanoseconds())/float64(b.N), "cpu-ns/event")
}

func BenchmarkStageDecode(b *testing.B) {
	corpus := benchInput()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := new(tetragonpb.GetEventsResponse)
		if err := proto.Unmarshal(corpus[i%len(corpus)], ev); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStageClassify(b *testing.B) {
	corpus := benchInput()
	evs := decodeChunk(b, corpus, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := ClassOf(evs[i%len(evs)]); !ok {
			b.Fatal("unclassified")
		}
	}
}

func BenchmarkStageRedact(b *testing.B) {
	corpus := benchInput()
	red, _ := NewRedactor(nil)
	chunked(b, func(off int) []*tetragonpb.GetEventsResponse { return decodeChunk(b, corpus, off) },
		func(evs []*tetragonpb.GetEventsResponse) {
			for _, ev := range evs {
				red.Redact(ev)
			}
		})
}

func BenchmarkStageMarshal(b *testing.B) {
	corpus := benchInput()
	red, _ := NewRedactor(nil)
	opts := proto.MarshalOptions{Deterministic: true}
	chunked(b, func(off int) []*tetragonpb.GetEventsResponse {
		evs := decodeChunk(b, corpus, off)
		for _, ev := range evs {
			red.Redact(ev)
		}
		return evs
	}, func(evs []*tetragonpb.GetEventsResponse) {
		for _, ev := range evs {
			if _, err := opts.Marshal(ev); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// stageRecords is one realistic batch of redacted, marshaled records
// (cut where the builder cuts: 2000 events or 1 MiB of payload).
func stageRecords(b *testing.B) [][]byte {
	corpus := benchInput()
	red, _ := NewRedactor(nil)
	opts := proto.MarshalOptions{Deterministic: true}
	var recs [][]byte
	size := 0
	for i := 0; len(recs) < 2000; i++ {
		ev := new(tetragonpb.GetEventsResponse)
		if err := proto.Unmarshal(corpus[i%len(corpus)], ev); err != nil {
			b.Fatal(err)
		}
		red.Redact(ev)
		raw, _ := opts.Marshal(ev)
		if size+len(raw)+batch.RecordOverhead > 1<<20 {
			break
		}
		size += len(raw) + batch.RecordOverhead
		recs = append(recs, raw)
	}
	return recs
}

// BenchmarkStageSpool appends one realistic batch per op (payload build,
// header, hashes, HMAC, file write, fsync, rename, directory fsync, head),
// then reads it back as the exporter does and acks it (delete).
func BenchmarkStageSpool(b *testing.B) {
	recs := stageRecords(b)
	cfg := spoolCfg(&testing.T{}, b.TempDir(), OSFS{}, "boot-a")
	s, err := OpenSpool(cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	c0 := cpuNow()
	for i := 0; i < b.N; i++ {
		e, err := s.AppendEvents(batch.ClassNonSecurity, recs, 1, 2)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := s.Read(e); err != nil {
			b.Fatal(err)
		}
		s.Ack(e.Chain, e.Seq)
	}
	cpu := cpuNow() - c0
	b.ReportMetric(float64(len(recs)), "events/batch")
	b.ReportMetric(float64(cpu.Nanoseconds())/float64(b.N*len(recs)), "cpu-ns/event")
}
