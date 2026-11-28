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

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// EventSource is Tetragon's GetEvents with an allow-list (cmd/relayd adapts
// tetra.Client.StreamEvents to it). Each response is delivered as its
// undecoded wire bytes, which the pipeline then owns. deliver may block.
// excludeFields are field paths Tetragon is asked not to send
// (GetEventsRequest.field_filters, EXCLUDE): a saving, not a redaction.
type EventSource interface {
	StreamEvents(ctx context.Context, eventTypes []tetragonpb.EventType, excludeFields []string, deliver func(raw []byte) bool) error
}

// ExcludedFields are the fields telemetry asks Tetragon not to send (step
// 7b D1): the environment, which redaction removes anyway. Redaction still
// removes it, as defense in depth. Paths are relative to the event message
// (verified on the real v1.8.0 binary: TestIntegration_FieldFilters).
var ExcludedFields = []string{
	"process.environment_variables",
	"parent.environment_variables",
	"ancestors.environment_variables",
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

// rateLimitAuditEvery bounds how often admission drops are audited (each
// is declared in the chain regardless).
const rateLimitAuditEvery = time.Minute

// eventQueueDepth bounds the ingest -> builder queue (handoff.go). When it
// is full, ingest blocks inside GetEvents' deliver, so Tetragon is read no faster
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

// classOfField is ClassOf for the event field the rewriter saw.
func classOfField(n protowire.Number) (class string, ok bool) {
	switch n { //nolint:exhaustive // a set of field numbers, not an enum
	case fieldProcessKprobe, fieldProcessLsm, fieldProcessTracepoint, fieldProcessUprobe:
		return batch.ClassSecurity, true
	case fieldProcessExec, fieldProcessExit:
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
	// MaxEventRate is collector.max_event_rate: the admission budget for
	// non_security events, per second (step 7b D0), in
	// 1..limits.MaxCollectorEventRate.
	MaxEventRate int
	Clock        func() time.Time
	Auditor      Auditor
	Liveness     Liveness
	// Backoff bounds the exporter's and ingest's reconnect backoff.
	// Zero values mean 1 s and 30 s.
	BackoffMin, BackoffMax time.Duration
	// SendTimeout and DialTimeout bound one Send and one Dial on the
	// collector stream. Zero values mean 20 s and 10 s; both must stay
	// well under the 60 s liveness bound.
	SendTimeout, DialTimeout time.Duration
	// HandoffChunk is how many admitted events ingest hands the builder
	// per wake-up at most (handoff.go). Zero means defaultHandoffChunk;
	// 1 is one wake-up per event (the E3 A/B baseline).
	HandoffChunk int
}

// Pipeline runs the telemetry goroutines.
type Pipeline struct {
	cfg   Config
	h     *handoff
	drops rateDrops
	// admitRate is cfg.MaxEventRate; the benchmark sets it to +Inf.
	admitRate float64
	rw        *wireRewriter
	// counters
	rateLimited     atomic.Uint64
	malformed       atomic.Uint64
	tetragonDropped atomic.Uint64
	oversized       atomic.Uint64
	unclassified    atomic.Uint64
	unknownFields   atomic.Uint64
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
	case cfg.MaxEventRate <= 0 || cfg.MaxEventRate > limits.MaxCollectorEventRate:
		return nil, fmt.Errorf("telemetry: MaxEventRate %d outside 1..%d", cfg.MaxEventRate, limits.MaxCollectorEventRate)
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
	rw, err := newWireRewriter(cfg.Redactor)
	if err != nil {
		return nil, err
	}
	if cfg.HandoffChunk <= 0 {
		cfg.HandoffChunk = defaultHandoffChunk
	}
	h := newHandoff(min(cfg.HandoffChunk, eventQueueDepth), eventQueueDepth, handoffDrainDelay)
	return &Pipeline{cfg: cfg, h: h, admitRate: float64(cfg.MaxEventRate), rw: rw}, nil
}

// HeartbeatStats is the heartbeat's view (Heartbeat.telemetry_last_seq and
// telemetry_backlog).
//
// It takes no lock the telemetry goroutines hold (step 7b D0): the
// control loop calls it on every heartbeat, and a spool write in progress
// (compression, fsyncs) must not delay one.
func (p *Pipeline) HeartbeatStats() (lastSeq uint64, backlog uint32) {
	seq, b := p.cfg.Spool.HeartbeatView()
	b = max(0, min(b, int64(^uint32(0))))
	return seq, uint32(b) //nolint:gosec // G115: clamped above
}

// Counters returns the pipeline's own loss and error counters.
func (p *Pipeline) Counters() map[string]uint64 {
	return map[string]uint64{
		// Non-security events dropped over collector.max_event_rate,
		// before decode (declared in rate_limited dropped records).
		"rate_limited_events": p.rateLimited.Load(),
		// Responses admission let through that did not decode.
		"malformed_events":      p.malformed.Load(),
		"tetragon_rate_limited": p.tetragonDropped.Load(),
		"oversized_events":      p.oversized.Load(),
		"unclassified_events":   p.unclassified.Load(),
		// Events in which the redactor removed fields the vendored API
		// does not know (a newer Tetragon): they cannot be redacted.
		"events_with_unknown_fields": p.unknownFields.Load(),
		"events_lost_on_write":       p.lostOnWrite.Load(),
		"protocol_errors":            p.protocolErrors.Load(),
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
	bucket := newTokenBucket(p.admitRate, p.cfg.Clock())
	for ctx.Err() == nil {
		p.cfg.Liveness.Touch(LivenessIngest)
		started := p.cfg.Clock()
		res := make(chan error, 1)
		go func() {
			res <- p.cfg.Source.StreamEvents(ctx, p.cfg.EventTypes, ExcludedFields, func(raw []byte) bool {
				if peekAdmit(raw) == admitOther {
					if now := p.cfg.Clock(); !bucket.allow(now) {
						p.rateLimited.Add(1)
						p.drops.add(now.UnixNano())
						return true
					}
				}
				return p.h.put(ctx, raw)
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

// pending is one class's batch being built. Its payload buffer is reused
// for every batch of that class (the spool does not keep it), so the
// builder allocates nothing per event once the buffers have grown.
type pending struct {
	class       string
	payload     []byte
	count       uint64
	first, last int64
	started     time.Time
}

// build redacts, marshals and batches events per class, and spools a
// batch at BatchMaxEvents, at limits.MaxTelemetryPayloadBytes, or after
// BatchMaxAge.
func (p *Pipeline) build(ctx context.Context) {
	cur := [2]pending{{class: batch.ClassSecurity}, {class: batch.ClassNonSecurity}}
	flush := func(b *pending) {
		if b.count == 0 {
			return
		}
		if _, err := p.cfg.Spool.AppendEventsPayload(b.class, b.payload, b.count, b.first, b.last); err != nil {
			p.lostOnWrite.Add(b.count)
			p.cfg.Auditor.Record("telemetry_spool_write_failed", fmt.Sprintf("%d %s events not spooled", b.count, b.class), err)
		}
		b.payload, b.count = b.payload[:0], 0
	}
	tick := time.NewTicker(min(p.cfg.BatchMaxAge/4+time.Millisecond, touchEvery))
	defer tick.Stop()
	var scratch []byte
	var lastDecl, lastAudit time.Time
	declare := func(now time.Time) {
		n, first, last := p.drops.take()
		if n == 0 {
			return
		}
		if _, err := p.cfg.Spool.AppendRateLimited(n, first, last); err != nil {
			p.drops.putBack(n, first, last)
			p.cfg.Auditor.Record("telemetry_spool_write_failed", fmt.Sprintf("rate_limited record for %d events not spooled; retried", n), err)
			return
		}
		lastDecl = now
		if now.Sub(lastAudit) >= rateLimitAuditEvery {
			lastAudit = now
			p.cfg.Auditor.Record("telemetry_rate_limited", fmt.Sprintf("%d non_security events over collector.max_event_rate (%d/s) dropped before decode; declared in the chain", n, p.cfg.MaxEventRate), nil)
		}
	}
	handle := func(raw []byte) {
		// One pass over Tetragon's bytes: validated, redacted and
		// re-encoded (step 7b D1, wire.go).
		var meta wireMeta
		var err error
		scratch, meta, err = p.rw.rewrite(scratch[:0], raw)
		if err != nil {
			p.malformed.Add(1)
			return
		}
		if meta.event == fieldRateLimitInfo {
			var rl tetragonpb.RateLimitInfo
			if proto.Unmarshal(meta.rateLimitRaw, &rl) == nil {
				p.tetragonDropped.Add(rl.GetNumberOfDroppedProcessEvents())
				p.cfg.Auditor.Record("telemetry_tetragon_rate_limited", fmt.Sprintf("Tetragon reports %d process events dropped by its rate limit", rl.GetNumberOfDroppedProcessEvents()), nil)
			}
			return
		}
		class, ok := classOfField(meta.event)
		if !ok {
			p.unclassified.Add(1)
			return
		}
		if meta.unknown > 0 {
			p.unknownFields.Add(1)
		}
		if len(scratch) == 0 || len(scratch) > limits.MaxTelemetryEventBytes {
			p.oversized.Add(1)
			return
		}
		ts := p.cfg.Clock().UnixNano()
		if meta.hasTime {
			ts = time.Unix(meta.timeSec, int64(meta.timeNanos)).UnixNano()
		}
		b := &cur[1]
		if class == batch.ClassSecurity {
			b = &cur[0]
		}
		if b.count > 0 && len(b.payload)+len(scratch)+batch.RecordOverhead > limits.MaxTelemetryPayloadBytes {
			flush(b)
		}
		if b.count == 0 {
			b.first, b.last, b.started = ts, ts, p.cfg.Clock()
		}
		b.first, b.last = min(b.first, ts), max(b.last, ts)
		b.payload = batch.AppendRecord(b.payload, scratch)
		b.count++
		if b.count >= uint64(p.cfg.BatchMaxEvents) {
			flush(b)
		}
	}
	var spare [][]byte
	for {
		select {
		case <-ctx.Done():
			// step-07b-decisions-3.md F3: drain what ingest already
			// queued before the final flush, so admitted events are
			// spooled rather than lost at shutdown (take does not wait out
			// its delay once ctx is done).
			evs := p.h.take(ctx, spare)
			for _, raw := range evs {
				handle(raw)
			}
			clear(evs)
			flush(&cur[0])
			flush(&cur[1])
			declare(p.cfg.Clock())
			return
		case <-p.h.ready():
			evs := p.h.take(ctx, spare)
			for _, raw := range evs {
				handle(raw)
			}
			clear(evs) // the builder does not keep Tetragon's bytes
			spare = evs
		case <-tick.C:
			p.cfg.Liveness.Touch(LivenessBuilder)
			now := p.cfg.Clock()
			if now.Sub(lastDecl) >= p.cfg.BatchMaxAge {
				declare(now)
			}
			for i := range cur {
				if cur[i].count > 0 && now.Sub(cur[i].started) >= p.cfg.BatchMaxAge {
					flush(&cur[i])
				}
			}
		}
	}
}
