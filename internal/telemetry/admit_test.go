package telemetry

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/chainverify"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

func mustMarshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPeekAdmit(t *testing.T) {
	ev := func(e any) []byte {
		r := &tetragonpb.GetEventsResponse{NodeName: "n", Time: nil}
		switch e := e.(type) {
		case *tetragonpb.GetEventsResponse_ProcessExec:
			r.Event = e
		case *tetragonpb.GetEventsResponse_ProcessExit:
			r.Event = e
		case *tetragonpb.GetEventsResponse_ProcessKprobe:
			r.Event = e
		case *tetragonpb.GetEventsResponse_ProcessTracepoint:
			r.Event = e
		case *tetragonpb.GetEventsResponse_ProcessUprobe:
			r.Event = e
		case *tetragonpb.GetEventsResponse_ProcessLsm:
			r.Event = e
		case *tetragonpb.GetEventsResponse_ProcessLoader:
			r.Event = e
		case *tetragonpb.GetEventsResponse_RateLimitInfo:
			r.Event = e
		}
		return mustMarshal(t, r)
	}
	kp := ev(&tetragonpb.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragonpb.ProcessKprobe{PolicyName: "p"}})
	ex := ev(&tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{}})
	for name, c := range map[string]struct {
		raw  []byte
		want admitKind
	}{
		"exec":       {ex, admitOther},
		"exit":       {ev(&tetragonpb.GetEventsResponse_ProcessExit{ProcessExit: &tetragonpb.ProcessExit{}}), admitOther},
		"kprobe":     {kp, admitSecurity},
		"tracepoint": {ev(&tetragonpb.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &tetragonpb.ProcessTracepoint{}}), admitSecurity},
		"uprobe":     {ev(&tetragonpb.GetEventsResponse_ProcessUprobe{ProcessUprobe: &tetragonpb.ProcessUprobe{}}), admitSecurity},
		"lsm":        {ev(&tetragonpb.GetEventsResponse_ProcessLsm{ProcessLsm: &tetragonpb.ProcessLsm{}}), admitSecurity},
		"loader":     {ev(&tetragonpb.GetEventsResponse_ProcessLoader{ProcessLoader: &tetragonpb.ProcessLoader{}}), admitOther},
		"rate info":  {ev(&tetragonpb.GetEventsResponse_RateLimitInfo{RateLimitInfo: &tetragonpb.RateLimitInfo{}}), admitRateLimitInfo},
		"no event":   {mustMarshal(t, &tetragonpb.GetEventsResponse{NodeName: "n"}), admitOther},
		"empty":      {nil, admitOther},
		// Proto keeps the last of two oneof fields; admission does not
		// guess which: two distinct event fields are not security.
		"exec then kprobe": {append(append([]byte{}, ex...), kp...), admitOther},
		"kprobe then exec": {append(append([]byte{}, kp...), ex...), admitOther},
		// The same field twice merges: still one event.
		"kprobe twice": {append(append([]byte{}, kp...), kp...), admitSecurity},
		"truncated":    {kp[:len(kp)-1], admitOther},
		"bad tag":      {[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, admitOther},
		// Field 9 as a varint is not a kprobe message.
		"kprobe wrong wire type": {protowire.AppendVarint(protowire.AppendTag(nil, fieldProcessKprobe, protowire.VarintType), 1), admitOther},
		"unknown fields only":    {protowire.AppendBytes(protowire.AppendTag(nil, 7777, protowire.BytesType), []byte("x")), admitOther},
	} {
		if got := peekAdmit(c.raw); got != c.want {
			t.Errorf("%s: peekAdmit = %d, want %d", name, got, c.want)
		}
	}
}

func TestTokenBucket(t *testing.T) {
	t0 := time.Unix(1000, 0)
	b := newTokenBucket(3, t0)
	for i := 0; i < 3; i++ {
		if !b.allow(t0) {
			t.Fatalf("burst token %d refused", i)
		}
	}
	if b.allow(t0) {
		t.Fatal("4th token at the same instant allowed")
	}
	if !b.allow(t0.Add(400 * time.Millisecond)) { // 1.2 tokens refilled
		t.Fatal("refill after 400 ms refused")
	}
	if b.allow(t0.Add(400 * time.Millisecond)) {
		t.Fatal("0.2 tokens allowed")
	}
	if b.allow(t0) { // the clock going back refills nothing
		t.Fatal("token after the clock went back")
	}
	n := 0
	for b.allow(t0.Add(time.Hour)) {
		n++
	}
	if n != 3 {
		t.Fatalf("after an hour idle, %d tokens; want the burst (3)", n)
	}
}

// rawSource delivers raw bytes as they are.
type rawSource struct{ ch chan []byte }

func (s *rawSource) StreamEvents(ctx context.Context, _ []tetragonpb.EventType, deliver func([]byte) bool) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case raw := <-s.ch:
			if !deliver(raw) {
				return nil
			}
		}
	}
}

// TestPipeline_AdmissionControl: with a budget of 3 non_security events
// and a clock that does not move, 3 execs are admitted and 7 are dropped
// before decode and declared in a rate_limited dropped record; every
// kprobe is admitted; a malformed response within the budget is counted
// and never spooled.
func TestPipeline_AdmissionControl(t *testing.T) {
	col := &memCollector{}
	cfg := spoolCfg(t, t.TempDir(), OSFS{}, "boot-a")
	aud := cfg.Auditor.(*recAuditor)
	s := mustOpen(t, cfg)
	red, _ := NewRedactor(nil)
	var offset atomic.Int64
	t0 := time.Unix(5000, 0)
	clock := func() time.Time { return t0.Add(time.Duration(offset.Load())) }
	src := &rawSource{ch: make(chan []byte)}
	p, err := New(Config{
		Source: src, EventTypes: []tetragonpb.EventType{tetragonpb.EventType_PROCESS_EXEC}, Redactor: red, Spool: s,
		Dialer: col, BatchMaxEvents: 1, BatchMaxAge: 40 * time.Millisecond, MaxEventRate: 4, Clock: clock,
		Auditor: aud, Liveness: &fakeLiveness{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	src.ch <- []byte{0x0a, 0x05, 0x01} // malformed: takes 1 of the 4 tokens
	for i := 0; i < 10; i++ {
		src.ch <- mustMarshal(t, exec("/usr/bin/true", "x"))
		src.ch <- mustMarshal(t, kprobe("/etc/passwd"))
	}
	src.ch <- mustMarshal(t, &tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_RateLimitInfo{RateLimitInfo: &tetragonpb.RateLimitInfo{NumberOfDroppedProcessEvents: 2}}})
	offset.Store(int64(time.Hour)) // lets the builder declare what is left
	waitFor(t, "7 rate-limited events declared and everything acked", func() bool {
		rep := chainverify.Verify(testHost, col.snapshot())
		return len(rep.Chains) == 1 && rep.Chains[0].RateLimited == 7 && s.Stats().Backlog == 0
	})
	got := col.snapshot()
	rep := chainverify.Verify(testHost, got)
	if !rep.Clean() {
		t.Fatalf("findings: %+v", rep.Findings)
	}
	var execs, kprobes uint64
	for _, in := range got {
		b, err := batch.Parse(in.Header, in.Payload)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case b.Header.Kind == batch.KindEvents && b.Header.Class == batch.ClassSecurity:
			kprobes += b.Header.Count
		case b.Header.Kind == batch.KindEvents:
			execs += b.Header.Count
		case b.Header.Kind == batch.KindDropped:
			d, err := batch.ParseDropped(b.Payload)
			if err != nil || d.Reason != batch.DropRateLimited || b.Header.FirstTS != t0.UnixNano() {
				t.Fatalf("dropped record %+v (first_ts %d): %v", d, b.Header.FirstTS, err)
			}
		}
	}
	c := p.Counters()
	if execs != 3 || kprobes != 10 || c["rate_limited_events"] != 7 || c["malformed_events"] != 1 || c["tetragon_rate_limited"] != 2 {
		t.Fatalf("execs %d (want 3), kprobes %d (want 10), counters %v", execs, kprobes, c)
	}
	if aud.count("telemetry_rate_limited") == 0 {
		t.Fatal("admission drops not audited")
	}
}

func TestPipeline_MaxEventRateBounds(t *testing.T) {
	s := mustOpen(t, spoolCfg(t, t.TempDir(), OSFS{}, "boot-a"))
	red, _ := NewRedactor(nil)
	for _, rate := range []int{0, -1, 5001} {
		if _, err := New(Config{
			Source: &rawSource{}, EventTypes: []tetragonpb.EventType{1}, Redactor: red, Spool: s, Dialer: &memCollector{},
			BatchMaxEvents: 1, BatchMaxAge: time.Second, MaxEventRate: rate, Clock: time.Now, Auditor: &recAuditor{}, Liveness: &fakeLiveness{},
		}); err == nil {
			t.Errorf("MaxEventRate %d accepted", rate)
		}
	}
}

func TestRateDrops_PutBack(t *testing.T) {
	var d rateDrops
	d.putBack(2, 10, 20)
	d.add(5)
	d.add(30)
	n, first, last := d.take()
	if n != 4 || first != 5 || last != 30 {
		t.Fatalf("take = %d %d %d", n, first, last)
	}
	if n, _, _ := d.take(); n != 0 {
		t.Fatal("take after take not empty")
	}
}

func TestSpool_AppendRateLimited(t *testing.T) {
	s := mustOpen(t, spoolCfg(t, t.TempDir(), OSFS{}, "boot-a"))
	if _, err := s.AppendRateLimited(0, 1, 2); err == nil {
		t.Fatal("zero events accepted")
	}
	if _, err := s.AppendRateLimited(9, 1, 2); err != nil {
		t.Fatal(err)
	}
	rep := chainverify.Verify(testHost, spooled(t, s))
	if !rep.Clean() || rep.Chains[0].RateLimited != 9 {
		t.Fatalf("%+v", rep)
	}
}

// FuzzPeekAdmit checks admission's safety property: whatever it lets past
// the budget as security decodes, if it decodes at all, to a security
// event. A non_security event can never bypass the budget.
func FuzzPeekAdmit(f *testing.F) {
	f.Add(mustMarshal(f, kprobe("/x")))
	f.Add(mustMarshal(f, exec("/bin/true", "a")))
	f.Add(append(mustMarshal(f, exec("/bin/true", "a")), mustMarshal(f, kprobe("/x"))...))
	f.Add(append(mustMarshal(f, kprobe("/x")), mustMarshal(f, exec("/bin/true", "a"))...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		k := peekAdmit(raw)
		var ev tetragonpb.GetEventsResponse
		if proto.Unmarshal(raw, &ev) != nil {
			return
		}
		class, _ := ClassOf(&ev)
		switch k {
		case admitSecurity:
			if class != batch.ClassSecurity {
				t.Fatalf("admitted as security, decodes as %q: %v", class, &ev)
			}
		case admitRateLimitInfo:
			if ev.GetRateLimitInfo() == nil {
				t.Fatalf("admitted as RateLimitInfo, decodes as %T", ev.GetEvent())
			}
		case admitOther: // within the budget only: nothing to check
		}
	})
}

// TestHeartbeatStats_NeverWaitsForTheSpoolLock: the heartbeat's view is
// read while a spool write holds the lock (step 7b D0).
func TestHeartbeatStats_NeverWaitsForTheSpoolLock(t *testing.T) {
	s := mustOpen(t, spoolCfg(t, t.TempDir(), OSFS{}, "boot-a"))
	if _, err := s.AppendEvents(batch.ClassSecurity, rec(2), 1, 2); err != nil {
		t.Fatal(err)
	}
	red, _ := NewRedactor(nil)
	p, err := New(Config{
		Source: &rawSource{}, EventTypes: []tetragonpb.EventType{1}, Redactor: red, Spool: s, Dialer: &memCollector{},
		BatchMaxEvents: 1, BatchMaxAge: time.Second, MaxEventRate: 1, Clock: time.Now, Auditor: &recAuditor{}, Liveness: &fakeLiveness{},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock() // a write in progress
	defer s.mu.Unlock()
	got := make(chan [2]uint64, 1)
	go func() {
		seq, backlog := p.HeartbeatStats()
		got <- [2]uint64{seq, uint64(backlog)}
	}()
	select {
	case v := <-got:
		if v != [2]uint64{2, 2} { // chain_reset at seq 1, the events batch at 2
			t.Fatalf("HeartbeatStats = %v, want [2 2]", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HeartbeatStats waited for the spool lock")
	}
}
