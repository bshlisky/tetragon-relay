package telemetry

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/chainverify"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

func procEvent(t *testing.T, exit bool, execID string, start time.Time) []byte {
	t.Helper()
	p := &tetragonpb.Process{ExecId: execID, Binary: "/usr/bin/true", StartTime: timestamppb.New(start)}
	r := &tetragonpb.GetEventsResponse{Time: timestamppb.New(start)}
	if exit {
		r.Event = &tetragonpb.GetEventsResponse_ProcessExit{ProcessExit: &tetragonpb.ProcessExit{Process: p}}
	} else {
		r.Event = &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{Process: p}}
	}
	raw, err := proto.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPeekProcess(t *testing.T) {
	start := time.Unix(1700000000, 123)
	ev, id, ns, ok := peekProcess(procEvent(t, false, "abc", start))
	if !ok || ev != fieldProcessExec || string(id) != "abc" || ns != start.UnixNano() {
		t.Fatalf("exec: %v %q %d %t", ev, id, ns, ok)
	}
	ev, id, _, ok = peekProcess(procEvent(t, true, "abc", start))
	if !ok || ev != fieldProcessExit || string(id) != "abc" {
		t.Fatalf("exit: %v %q %t", ev, id, ok)
	}
	k, _ := proto.Marshal(kprobe("/x"))
	noID, _ := proto.Marshal(&tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{Process: &tetragonpb.Process{StartTime: timestamppb.New(start)}}}})
	noStart, _ := proto.Marshal(&tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{Process: &tetragonpb.Process{ExecId: "x"}}}})
	good := procEvent(t, false, "abc", start)
	for name, raw := range map[string][]byte{
		"kprobe": k, "no exec_id": noID, "no start": noStart, "empty": nil,
		"truncated": good[:len(good)-3], "garbage": {0xff, 0xff, 0xff},
		"two events": append(append([]byte(nil), good...), procEvent(t, true, "abc", start)...),
	} {
		if _, _, _, ok := peekProcess(raw); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExecPairing(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	x := newExecPairing()
	x.reset(t0.UnixNano())
	after := t0.Add(10 * time.Second)

	x.observe(procEvent(t, false, "a", after))
	x.observe(procEvent(t, true, "a", after))                   // paired
	x.observe(procEvent(t, true, "b", after))                   // exec never seen: one missing
	x.observe(procEvent(t, true, "old", t0.Add(-time.Hour)))    // started before the stream: not counted
	x.observe(procEvent(t, true, "grace", t0.Add(time.Second))) // inside the grace: not counted
	x.observe(procEvent(t, false, "c", after))
	x.observe(procEvent(t, false, "c", after)) // duplicate exec
	x.observe(procEvent(t, true, "c", after))
	x.observe(procEvent(t, true, "c", after)) // a second exit for c: its exec is gone, counted
	x.observe([]byte{0xff})                   // ignored
	missing, received := x.take()
	if missing != 2 || received != 9 {
		t.Fatalf("missing=%d received=%d, want 2 and 9", missing, received)
	}
	if m, r := x.take(); m != 0 || r != 0 {
		t.Fatalf("take did not clear: %d %d", m, r)
	}
	x.putBack(3)
	if m, _ := x.take(); m != 3 {
		t.Fatalf("putBack: %d", m)
	}
	// A new stream forgets what the old one saw.
	x.observe(procEvent(t, false, "d", after))
	x.reset(after.UnixNano())
	x.observe(procEvent(t, true, "d", after.Add(time.Minute)))
	if m, _ := x.take(); m != 1 {
		t.Fatalf("after reset: missing=%d, want 1", m)
	}
}

// Eviction keeps the estimate a lower bound: an evicted process's exit is
// never counted.
func TestExecPairing_EvictionNeverOvercounts(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	x := newExecPairing()
	x.reset(t0.UnixNano())
	base := t0.Add(time.Minute)
	n := pairingCapacity + 100
	for i := 0; i < n; i++ {
		x.observe(procEvent(t, false, "p"+itoa(i), base.Add(time.Duration(i)*time.Millisecond)))
	}
	for i := 0; i < n; i++ {
		x.observe(procEvent(t, true, "p"+itoa(i), base.Add(time.Duration(i)*time.Millisecond)))
	}
	if m, _ := x.take(); m != 0 {
		t.Fatalf("eviction produced %d false losses", m)
	}
	if len(x.seen) != 0 {
		t.Fatalf("%d entries left", len(x.seen))
	}
}

func itoa(i int) string { return string(rune('a'+i%26)) + time.Duration(i).String() }

// End to end: exits with no exec become a tetragon_unsignalled dropped
// record in the chain, and OnLoss fires above 1 %.
func TestPipeline_DeclaresUnsignalledLoss(t *testing.T) {
	cfg := spoolCfg(t, t.TempDir(), OSFS{}, "boot-a")
	s := mustOpen(t, cfg)
	red, _ := NewRedactor(nil)
	src := &rawSource{ch: make(chan []byte, 64)}
	col := &memCollector{}
	type loss struct{ m, r uint64 }
	losses := make(chan loss, 4)
	p, err := New(Config{
		Source: src, EventTypes: []tetragonpb.EventType{tetragonpb.EventType_PROCESS_EXEC}, Redactor: red, Spool: s, Dialer: col,
		BatchMaxEvents: 100, BatchMaxAge: 50 * time.Millisecond, MaxEventRate: limits.MaxCollectorEventRate, Clock: time.Now,
		Auditor: cfg.Auditor, Liveness: &fakeLiveness{}, BackoffMin: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond,
		LossInterval: 100 * time.Millisecond,
		OnLoss:       func(m, r uint64) { losses <- loss{m, r} },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	future := time.Now().Add(time.Hour)
	src.ch <- procEvent(t, false, "seen", future)
	src.ch <- procEvent(t, true, "seen", future)
	src.ch <- procEvent(t, true, "lost-1", future)
	src.ch <- procEvent(t, true, "lost-2", future)
	select {
	case l := <-losses:
		if l.m != 2 || l.r != 4 {
			t.Fatalf("OnLoss(%d, %d), want (2, 4)", l.m, l.r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnLoss not called")
	}
	waitFor(t, "the estimate in the chain", func() bool {
		for _, c := range chainverify.Verify(testHost, col.snapshot()).Chains {
			if c.UnsignalledAtLeast == 2 {
				return true
			}
		}
		return false
	})
	if p.Counters()["tetragon_unsignalled_at_least"] != 2 {
		t.Fatalf("counters: %v", p.Counters())
	}
}
