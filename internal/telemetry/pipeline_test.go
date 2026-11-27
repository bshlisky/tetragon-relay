package telemetry

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	telemetryv1 "github.com/bshlisky/tetragon-relay/api/relay/telemetry/v1"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/chainverify"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// --- fakes ---

type fakeLiveness struct {
	mu      sync.Mutex
	touched map[string]int
}

func (l *fakeLiveness) Register(string, time.Duration) {}
func (l *fakeLiveness) Touch(n string) {
	l.mu.Lock()
	if l.touched == nil {
		l.touched = map[string]int{}
	}
	l.touched[n]++
	l.mu.Unlock()
}

type chanSource struct {
	ch    chan *tetragonpb.GetEventsResponse
	calls int
	mu    sync.Mutex
	types []tetragonpb.EventType
}

func (s *chanSource) StreamEvents(ctx context.Context, types []tetragonpb.EventType, deliver func(*tetragonpb.GetEventsResponse) bool) error {
	s.mu.Lock()
	s.calls++
	s.types = types
	s.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-s.ch:
			if !ok {
				return errors.New("source closed")
			}
			if !deliver(ev) {
				return nil
			}
		}
	}
}

// memCollector is an in-memory collector: it records every batch, verifies
// the chain, and acks per its policy.
type memCollector struct {
	mu       sync.Mutex
	received []chainverify.Input
	streams  int
	// hostileOnce makes the first stream send an ack for a seq never sent.
	hostileOnce bool
	// noAck suppresses acks.
	noAck bool
	// down makes Dial fail.
	down bool
	// discard keeps nothing (the benchmark).
	discard bool
	// events counts the events in every batch received (the benchmark's
	// drain condition).
	events atomic.Uint64
}

type memStream struct {
	c    *memCollector
	ctx  context.Context
	acks chan *telemetryv1.Ack
	n    int
}

func (c *memCollector) Dial(ctx context.Context) (Stream, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return nil, nil, errors.New("collector down")
	}
	c.streams++
	s := &memStream{c: c, ctx: ctx, acks: make(chan *telemetryv1.Ack, 1024), n: c.streams}
	return s, func() {}, nil
}

func (s *memStream) Send(b *telemetryv1.Batch) error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	s.c.mu.Lock()
	if !s.c.discard {
		s.c.received = append(s.c.received, chainverify.Input{Header: b.GetHeader(), Payload: b.GetPayload()})
	}
	hostile, noAck := s.c.hostileOnce && s.n == 1, s.c.noAck
	s.c.mu.Unlock()
	h, err := batch.ParseHeader(b.GetHeader())
	if err != nil {
		return err
	}
	s.c.events.Add(h.Count)
	switch {
	case hostile:
		s.acks <- &telemetryv1.Ack{ChainId: h.ChainID[:], Seq: h.Seq + 100}
	case !noAck:
		s.acks <- &telemetryv1.Ack{ChainId: h.ChainID[:], Seq: h.Seq}
	}
	return nil
}

func (s *memStream) Recv() (*telemetryv1.Ack, error) {
	select {
	case <-s.ctx.Done():
		return nil, io.EOF
	case a := <-s.acks:
		return a, nil
	}
}

func (c *memCollector) snapshot() []chainverify.Input {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]chainverify.Input(nil), c.received...)
}

func exec(binary, args string) *tetragonpb.GetEventsResponse {
	return &tetragonpb.GetEventsResponse{
		Time: timestamppb.New(time.Unix(1700000000, 0)),
		Event: &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{Process: &tetragonpb.Process{
			Binary: binary, Arguments: args,
			EnvironmentVariables: []*tetragonpb.EnvVar{{Key: "AWS_SECRET", Value: "s"}},
		}}},
	}
}

func kprobe(path string) *tetragonpb.GetEventsResponse {
	return &tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragonpb.ProcessKprobe{
		Process: &tetragonpb.Process{Binary: "/usr/bin/cat"},
		Args:    []*tetragonpb.KprobeArgument{{Arg: &tetragonpb.KprobeArgument_FileArg{FileArg: &tetragonpb.KprobeFile{Path: path}}}},
	}}}
}

type rig struct {
	p    *Pipeline
	s    *Spool
	src  *chanSource
	col  *memCollector
	aud  *recAuditor
	live *fakeLiveness
	stop func()
}

func newRig(t *testing.T, col *memCollector, maxEvents int, maxAge time.Duration) *rig {
	t.Helper()
	cfg := spoolCfg(t, t.TempDir(), OSFS{}, "boot-a")
	aud := cfg.Auditor.(*recAuditor)
	s := mustOpen(t, cfg)
	red, err := NewRedactor([]string{`hunter2`})
	if err != nil {
		t.Fatal(err)
	}
	src := &chanSource{ch: make(chan *tetragonpb.GetEventsResponse, 64)}
	live := &fakeLiveness{}
	p, err := New(Config{
		Source: src, EventTypes: []tetragonpb.EventType{tetragonpb.EventType_PROCESS_EXEC}, Redactor: red, Spool: s,
		Dialer: col, BatchMaxEvents: maxEvents, BatchMaxAge: maxAge, Clock: time.Now, Auditor: aud,
		Liveness: live, BackoffMin: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	return &rig{p: p, s: s, src: src, col: col, aud: aud, live: live, stop: func() { cancel(); <-done }}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- tests ---

func TestPipeline_EndToEndRedactedChainedAcked(t *testing.T) {
	col := &memCollector{}
	r := newRig(t, col, 2, 50*time.Millisecond)
	defer r.stop()
	r.src.ch <- exec("/home/alice/.ssh/evil", "--password hunter2 /home/alice/.ssh/id_rsa ok")
	r.src.ch <- kprobe("/home/bob/.ssh/authorized_keys")
	r.src.ch <- exec("/usr/bin/true", "x") // second non_security: count 2 flushes
	r.src.ch <- &tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_RateLimitInfo{RateLimitInfo: &tetragonpb.RateLimitInfo{NumberOfDroppedProcessEvents: 7}}}
	r.src.ch <- &tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_ProcessLoader{ProcessLoader: &tetragonpb.ProcessLoader{}}}
	waitFor(t, "everything acked", func() bool {
		st := r.s.Stats()
		return st.Backlog == 0 && st.LastSeq >= 3
	})
	got := col.snapshot()
	rep := chainverify.Verify(testHost, got)
	if !rep.Clean() {
		t.Fatalf("findings: %+v", rep.Findings)
	}
	var all string
	for _, in := range got {
		b, err := batch.Parse(in.Header, in.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if b.Header.Kind != batch.KindEvents {
			continue
		}
		dec, _ := batch.NewPayloadDecoder()
		raw, err := dec.Decode(&b.Header, b.Payload)
		if err != nil {
			t.Fatal(err)
		}
		recs, err := batch.SplitRecords(raw, b.Header.Count)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range recs {
			var ev tetragonpb.GetEventsResponse
			if err := proto.Unmarshal(raw, &ev); err != nil {
				t.Fatal(err)
			}
			if e := ev.GetProcessExec(); e != nil && len(e.GetProcess().GetEnvironmentVariables()) != 0 {
				t.Fatal("environment not dropped")
			}
			all += ev.String()
		}
		if b.Header.Epochs["prod"] != 3 || b.Header.AgentVersion != "test" {
			t.Fatalf("enrichment missing: %+v", b.Header)
		}
	}
	for _, leak := range []string{"hunter2", "/home/alice/.ssh", "/home/bob/.ssh", "AWS_SECRET"} {
		if strings.Contains(all, leak) {
			t.Fatalf("%q leaked into telemetry: %s", leak, all)
		}
	}
	for _, want := range []string{Redacted, HashPath("/home/alice/.ssh/id_rsa"), HashPath("/home/bob/.ssh/authorized_keys"), HashPath("/home/alice/.ssh/evil"), "/usr/bin/true"} {
		if !strings.Contains(all, want) {
			t.Fatalf("%q missing from telemetry: %s", want, all)
		}
	}
	c := r.p.Counters()
	if c["tetragon_rate_limited"] != 7 || c["unclassified_events"] != 1 {
		t.Fatalf("counters = %v", c)
	}
	last, backlog := r.p.HeartbeatStats()
	if last != r.s.Stats().LastSeq || backlog != 0 {
		t.Fatalf("heartbeat stats = %d, %d", last, backlog)
	}
}

func TestPipeline_HostileAckDeletesNothingAndResends(t *testing.T) {
	col := &memCollector{hostileOnce: true}
	r := newRig(t, col, 1, time.Hour)
	defer r.stop()
	r.src.ch <- exec("/bin/a", "")
	waitFor(t, "a protocol error and a second stream", func() bool {
		col.mu.Lock()
		defer col.mu.Unlock()
		return col.streams >= 2
	})
	waitFor(t, "backlog drained on the honest stream", func() bool { return r.s.Stats().Backlog == 0 })
	if r.aud.count("telemetry_protocol_error") < 1 || r.p.Counters()["protocol_errors"] < 1 {
		t.Fatal("hostile ack not audited/counted")
	}
	// Everything was resent on the second stream, in order.
	got := col.snapshot()
	if len(got) < 4 {
		t.Fatalf("only %d batches received", len(got))
	}
	rep := chainverify.Verify(testHost, got)
	if !rep.Clean() {
		t.Fatalf("findings: %+v", rep.Findings)
	}
	dups := 0
	for _, f := range rep.Findings {
		if f.Kind == chainverify.Duplicate {
			dups++
		}
	}
	if dups == 0 {
		t.Fatal("nothing was resent after the protocol error")
	}
}

func TestPipeline_OutageSpoolsThenDrainsInOrder(t *testing.T) {
	col := &memCollector{down: true}
	r := newRig(t, col, 1, time.Hour)
	defer r.stop()
	for i := 0; i < 5; i++ {
		r.src.ch <- exec("/bin/a", "")
	}
	waitFor(t, "5 batches spooled", func() bool { return r.s.Stats().LastSeq >= 6 })
	if _, backlog := r.p.HeartbeatStats(); backlog < 6 {
		t.Fatalf("backlog during outage = %d", backlog)
	}
	col.mu.Lock()
	col.down = false
	col.mu.Unlock()
	waitFor(t, "drained", func() bool { return r.s.Stats().Backlog == 0 })
	rep := chainverify.Verify(testHost, col.snapshot())
	if !rep.Clean() || len(rep.Chains) != 1 || rep.Chains[0].Contiguous != 6 {
		t.Fatalf("report: %+v", rep)
	}
	for _, f := range rep.Findings {
		if f.Kind == chainverify.ChainReorder {
			t.Fatal("drained out of order")
		}
	}
	r.live.mu.Lock()
	defer r.live.mu.Unlock()
	if r.live.touched[LivenessExporter] == 0 || r.live.touched[LivenessIngest] == 0 {
		t.Fatalf("liveness = %v", r.live.touched)
	}
}

func TestExporter_AckRules(t *testing.T) {
	c1, c2 := batch.ChainID{1}, batch.ChainID{2}
	st := &ackState{sent: map[batch.ChainID]uint64{c1: 5}, acked: map[batch.ChainID]uint64{}}
	ok := []*telemetryv1.Ack{{ChainId: c1[:], Seq: 3}, {ChainId: c1[:], Seq: 3}, {ChainId: c1[:], Seq: 5}}
	for _, a := range ok {
		if _, err := st.check(a); err != nil {
			t.Fatalf("valid ack %v: %v", a, err)
		}
	}
	for name, a := range map[string]*telemetryv1.Ack{
		"above sent":   {ChainId: c1[:], Seq: 6},
		"regressed":    {ChainId: c1[:], Seq: 4},
		"other chain":  {ChainId: c2[:], Seq: 1},
		"bad chain id": {ChainId: []byte{1}, Seq: 1},
	} {
		if _, err := st.check(a); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPipeline_ConfigAndIngestReconnect(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
	col := &memCollector{}
	r := newRig(t, col, 1, time.Hour)
	close(r.src.ch) // the source fails; ingest must reconnect, not stop
	waitFor(t, "ingest reconnect", func() bool {
		r.src.mu.Lock()
		defer r.src.mu.Unlock()
		return r.src.calls >= 2
	})
	r.stop()
	if r.aud.count("telemetry_ingest_stream_ended") < 1 {
		t.Fatal("ingest stream end not audited")
	}
	if _, err := NewRedactor([]string{"("}); err == nil {
		t.Fatal("bad pattern accepted")
	}
}

func TestClassOf(t *testing.T) {
	for ev, want := range map[*tetragonpb.GetEventsResponse]string{
		exec("/x", ""): batch.ClassNonSecurity,
		{Event: &tetragonpb.GetEventsResponse_ProcessExit{ProcessExit: &tetragonpb.ProcessExit{}}}: batch.ClassNonSecurity,
		kprobe("/x"): batch.ClassSecurity,
		{Event: &tetragonpb.GetEventsResponse_ProcessLsm{ProcessLsm: &tetragonpb.ProcessLsm{}}}:                      batch.ClassSecurity,
		{Event: &tetragonpb.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &tetragonpb.ProcessTracepoint{}}}: batch.ClassSecurity,
		{Event: &tetragonpb.GetEventsResponse_ProcessUprobe{ProcessUprobe: &tetragonpb.ProcessUprobe{}}}:             batch.ClassSecurity,
	} {
		if got, ok := ClassOf(ev); !ok || got != want {
			t.Errorf("%T: %q", ev.GetEvent(), got)
		}
	}
	if len(EventTypeNames) != 6 {
		t.Fatal("event type names")
	}
}

func TestRedactor_AncestorsAndLists(t *testing.T) {
	red, _ := NewRedactor(nil)
	ev := &tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{
		Process:   &tetragonpb.Process{Cwd: "/home/u/.ssh", Arguments: "AKIAABCDEFGHIJKLMNOP token=abc"},
		Parent:    &tetragonpb.Process{EnvironmentVariables: []*tetragonpb.EnvVar{{Key: "K"}}, Binary: "/home/u/.sshd"},
		Ancestors: []*tetragonpb.Process{{Arguments: "--PASSWORD=x", EnvironmentVariables: []*tetragonpb.EnvVar{{Key: "K"}}}},
	}}}
	red.Redact(ev)
	e := ev.GetProcessExec()
	if e.GetProcess().GetCwd() != HashPath("/home/u/.ssh") || e.GetProcess().GetArguments() != Redacted+" "+Redacted {
		t.Fatalf("process = %v", e.GetProcess())
	}
	if len(e.GetParent().GetEnvironmentVariables()) != 0 || e.GetParent().GetBinary() != "/home/u/.sshd" {
		t.Fatalf("parent = %v", e.GetParent())
	}
	if a := e.GetAncestors()[0]; len(a.GetEnvironmentVariables()) != 0 || a.GetArguments() != Redacted {
		t.Fatalf("ancestor = %v", a)
	}
}
