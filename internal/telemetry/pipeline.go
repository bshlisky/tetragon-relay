// Package telemetry is the agent's telemetry pipeline (architecture doc
// 8.10 and 10; ADR 0039): ingest from Tetragon's GetEvents, redact,
// enrich, batch, chain, spool, export to the collector.
//
// It is separated from the control path (architecture 10.2): it imports
// nothing from internal/apply, verify, guard, trust, controlclient, agent
// or tetra (enforced by depguard), and it gets everything it needs through
// the narrow interfaces below, connected by cmd/relayd.
package telemetry

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// EventSource is Tetragon's GetEvents with an allow-list (cmd/relayd adapts
// tetra.Client.StreamEvents to it). deliver may block.
type EventSource interface {
	StreamEvents(ctx context.Context, eventTypes []tetragonpb.EventType, deliver func(*tetragonpb.GetEventsResponse) bool) error
}

// Liveness is the agent's liveness registry (agent.LivenessRegistry).
type Liveness interface {
	Register(name string, maxInterval time.Duration)
	Touch(name string)
}

// Liveness component names and bounds. Each proves its own loop runs;
// none depends on the collector being reachable.
const (
	LivenessIngest   = "telemetry_ingest"
	LivenessBuilder  = "telemetry_builder"
	LivenessExporter = "telemetry_exporter"
	livenessMax      = 60 * time.Second
	touchEvery       = 5 * time.Second
)

// eventQueueDepth bounds the ingest -> builder channel. When it is full,
// ingest blocks inside GetEvents' deliver, so Tetragon is read no faster
// than the pipeline spools.
const eventQueueDepth = 1024

// EventTypeNames maps collector.event_types names to Tetragon's types.
var EventTypeNames = map[string]tetragonpb.EventType{
	"process_exec":       tetragonpb.EventType_PROCESS_EXEC,
	"process_exit":       tetragonpb.EventType_PROCESS_EXIT,
	"process_kprobe":     tetragonpb.EventType_PROCESS_KPROBE,
	"process_tracepoint": tetragonpb.EventType_PROCESS_TRACEPOINT,
	"process_uprobe":     tetragonpb.EventType_PROCESS_UPROBE,
	"process_lsm":        tetragonpb.EventType_PROCESS_LSM,
}

// ClassOf is an event's class (ADR 0039): kprobe, LSM, tracepoint and
// uprobe are security; exec and exit are non_security. Any other event
// is not spooled (ok false).
func ClassOf(ev *tetragonpb.GetEventsResponse) (class string, ok bool) {
	switch ev.GetEvent().(type) {
	case *tetragonpb.GetEventsResponse_ProcessKprobe, *tetragonpb.GetEventsResponse_ProcessLsm,
		*tetragonpb.GetEventsResponse_ProcessTracepoint, *tetragonpb.GetEventsResponse_ProcessUprobe:
		return batch.ClassSecurity, true
	case *tetragonpb.GetEventsResponse_ProcessExec, *tetragonpb.GetEventsResponse_ProcessExit:
		return batch.ClassNonSecurity, true
	}
	return "", false
}

// Config is New's input. Every field is required.
type Config struct {
	Source         EventSource
	EventTypes     []tetragonpb.EventType
	Redactor       *Redactor
	Spool          *Spool
	Dialer         Dialer
	BatchMaxEvents int
	BatchMaxAge    time.Duration
	Clock          func() time.Time
	Auditor        Auditor
	Liveness       Liveness
	// Backoff bounds the exporter's and ingest's reconnect backoff.
	// Zero values mean 1 s and 30 s.
	BackoffMin, BackoffMax time.Duration
	// SendTimeout and DialTimeout bound one Send and one Dial on the
	// collector stream. Zero values mean 20 s and 10 s; both must stay
	// well under the 60 s liveness bound.
	SendTimeout, DialTimeout time.Duration
}

// Pipeline runs the telemetry goroutines.
type Pipeline struct {
	cfg    Config
	events chan *tetragonpb.GetEventsResponse
	// counters
	tetragonDropped atomic.Uint64
	oversized       atomic.Uint64
	unclassified    atomic.Uint64
	lostOnWrite     atomic.Uint64
	protocolErrors  atomic.Uint64
}

// New validates cfg and returns a Pipeline.
func New(cfg Config) (*Pipeline, error) {
	switch {
	case cfg.Source == nil || cfg.Redactor == nil || cfg.Spool == nil || cfg.Dialer == nil:
		return nil, fmt.Errorf("telemetry: Source, Redactor, Spool and Dialer are required")
	case len(cfg.EventTypes) == 0:
		return nil, fmt.Errorf("telemetry: EventTypes is required")
	case cfg.BatchMaxEvents <= 0 || cfg.BatchMaxAge <= 0:
		return nil, fmt.Errorf("telemetry: BatchMaxEvents and BatchMaxAge must be positive")
	case cfg.Clock == nil || cfg.Auditor == nil || cfg.Liveness == nil:
		return nil, fmt.Errorf("telemetry: Clock, Auditor and Liveness are required")
	}
	if cfg.BackoffMin <= 0 {
		cfg.BackoffMin = time.Second
	}
	if cfg.BackoffMax < cfg.BackoffMin {
		cfg.BackoffMax = 30 * time.Second
	}
	if cfg.SendTimeout <= 0 {
		cfg.SendTimeout = defaultSendTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	return &Pipeline{cfg: cfg, events: make(chan *tetragonpb.GetEventsResponse, eventQueueDepth)}, nil
}

// HeartbeatStats is the heartbeat's view (Heartbeat.telemetry_last_seq and
// telemetry_backlog).
func (p *Pipeline) HeartbeatStats() (lastSeq uint64, backlog uint32) {
	st := p.cfg.Spool.Stats()
	b := st.Backlog
	if b > int(^uint32(0)) {
		b = int(^uint32(0))
	}
	return st.LastSeq, uint32(b) //nolint:gosec // G115: clamped above
}

// Counters returns the pipeline's own loss and error counters.
func (p *Pipeline) Counters() map[string]uint64 {
	return map[string]uint64{
		"tetragon_rate_limited": p.tetragonDropped.Load(),
		"oversized_events":      p.oversized.Load(),
		"unclassified_events":   p.unclassified.Load(),
		"events_lost_on_write":  p.lostOnWrite.Load(),
		"protocol_errors":       p.protocolErrors.Load(),
	}
}

// Run starts ingest, the builder and the exporter and returns when ctx is
// done and all three have stopped.
func (p *Pipeline) Run(ctx context.Context) {
	for _, n := range []string{LivenessIngest, LivenessBuilder, LivenessExporter} {
		p.cfg.Liveness.Register(n, livenessMax)
	}
	done := make(chan struct{}, 3)
	go func() { p.ingest(ctx); done <- struct{}{} }()
	go func() { p.build(ctx); done <- struct{}{} }()
	go func() { newExporter(p).run(ctx); done <- struct{}{} }()
	for i := 0; i < 3; i++ {
		<-done
	}
}

// sleep waits d (or until ctx is done), touching name meanwhile.
func (p *Pipeline) sleep(ctx context.Context, d time.Duration, name string) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	tick := time.NewTicker(touchEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		case <-tick.C:
			p.cfg.Liveness.Touch(name)
		}
	}
}

// ingest keeps one GetEvents stream open, reconnecting with backoff. Its
// loop touches liveness whether or not Tetragon has anything to send.
func (p *Pipeline) ingest(ctx context.Context) {
	backoff := p.cfg.BackoffMin
	for ctx.Err() == nil {
		p.cfg.Liveness.Touch(LivenessIngest)
		started := p.cfg.Clock()
		res := make(chan error, 1)
		go func() {
			res <- p.cfg.Source.StreamEvents(ctx, p.cfg.EventTypes, func(ev *tetragonpb.GetEventsResponse) bool {
				select {
				case p.events <- ev:
					return true
				case <-ctx.Done():
					return false
				}
			})
		}()
		tick := time.NewTicker(touchEvery)
		var err error
	wait:
		for {
			select {
			case err = <-res:
				break wait
			case <-tick.C:
				p.cfg.Liveness.Touch(LivenessIngest)
			}
		}
		tick.Stop()
		if ctx.Err() != nil {
			return
		}
		p.cfg.Auditor.Record("telemetry_ingest_stream_ended", "Tetragon GetEvents stream ended; reconnecting", err)
		if p.cfg.Clock().Sub(started) > p.cfg.BackoffMax {
			backoff = p.cfg.BackoffMin
		}
		if !p.sleep(ctx, backoff, LivenessIngest) {
			return
		}
		backoff = min(2*backoff, p.cfg.BackoffMax)
	}
}

type pending struct {
	records     [][]byte
	bytes       int
	first, last int64
	started     time.Time
}

// build redacts, marshals and batches events per class, and spools a
// batch at BatchMaxEvents, at limits.MaxTelemetryPayloadBytes, or after
// BatchMaxAge.
func (p *Pipeline) build(ctx context.Context) {
	cur := map[string]*pending{batch.ClassSecurity: {}, batch.ClassNonSecurity: {}}
	flush := func(class string) {
		b := cur[class]
		if len(b.records) == 0 {
			return
		}
		if _, err := p.cfg.Spool.AppendEvents(class, b.records, b.first, b.last); err != nil {
			p.lostOnWrite.Add(uint64(len(b.records)))
			p.cfg.Auditor.Record("telemetry_spool_write_failed", fmt.Sprintf("%d %s events not spooled", len(b.records), class), err)
		}
		cur[class] = &pending{}
	}
	tick := time.NewTicker(min(p.cfg.BatchMaxAge/4+time.Millisecond, touchEvery))
	defer tick.Stop()
	marshal := proto.MarshalOptions{Deterministic: true}
	for {
		select {
		case <-ctx.Done():
			flush(batch.ClassSecurity)
			flush(batch.ClassNonSecurity)
			return
		case ev := <-p.events:
			if rl := ev.GetRateLimitInfo(); rl != nil {
				p.tetragonDropped.Add(rl.GetNumberOfDroppedProcessEvents())
				p.cfg.Auditor.Record("telemetry_tetragon_rate_limited", fmt.Sprintf("Tetragon reports %d process events dropped by its rate limit", rl.GetNumberOfDroppedProcessEvents()), nil)
				continue
			}
			class, ok := ClassOf(ev)
			if !ok {
				p.unclassified.Add(1)
				continue
			}
			p.cfg.Redactor.Redact(ev)
			raw, err := marshal.Marshal(ev)
			if err != nil || len(raw) == 0 || len(raw) > limits.MaxTelemetryEventBytes {
				p.oversized.Add(1)
				continue
			}
			ts := p.cfg.Clock().UnixNano()
			if t := ev.GetTime(); t != nil {
				ts = t.AsTime().UnixNano()
			}
			b := cur[class]
			if len(b.records) > 0 && b.bytes+len(raw)+batch.RecordOverhead > limits.MaxTelemetryPayloadBytes {
				flush(class)
				b = cur[class]
			}
			if len(b.records) == 0 {
				b.first, b.last, b.started = ts, ts, p.cfg.Clock()
			}
			b.first, b.last = min(b.first, ts), max(b.last, ts)
			b.records = append(b.records, raw)
			b.bytes += len(raw) + batch.RecordOverhead
			if len(b.records) >= p.cfg.BatchMaxEvents {
				flush(class)
			}
		case <-tick.C:
			p.cfg.Liveness.Touch(LivenessBuilder)
			now := p.cfg.Clock()
			for class, b := range cur {
				if len(b.records) > 0 && now.Sub(b.started) >= p.cfg.BatchMaxAge {
					flush(class)
				}
			}
		}
	}
}
