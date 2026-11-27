package telemetry

import (
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// Admission control at ingest (step 7b D0, ADR 0041). Telemetry and the
// control plane share relayd's CPU quota, and Go does not schedule by
// priority, so a flood of events must not be able to starve heartbeats,
// the apply worker's health window or the watchdog. Ingest therefore
// looks at each GetEventsResponse's wire bytes, without decoding them,
// and admits:
//
//   - every security event (kprobe, LSM, tracepoint, uprobe): their volume
//     is set by the signed policies, and the controller can see a policy
//     that floods;
//   - Tetragon's RateLimitInfo (loss reported by Tetragon itself);
//   - anything else only while the token bucket has a token. Events over
//     the budget are dropped before decode, counted, and declared in the
//     chain by rate_limited dropped records.
//
// Only what is positively identified as security bypasses the bucket: a
// response that is malformed, names no event, or names more than one
// distinct event field is treated as non_security here.

// admitKind is what admission sees in a response's wire bytes.
type admitKind uint8

const (
	admitOther admitKind = iota
	admitSecurity
	admitRateLimitInfo
)

// GetEventsResponse's oneof event field numbers (third_party/tetragon/
// v1.8.0/api/v1/tetragon/events.pb.go, GetEventsResponse_*).
const (
	fieldProcessExec       = 1
	fieldProcessExit       = 5
	fieldProcessKprobe     = 9
	fieldProcessTracepoint = 10
	fieldProcessLoader     = 11
	fieldProcessUprobe     = 12
	fieldProcessThrottle   = 27
	fieldProcessLsm        = 28
	fieldProcessUsdt       = 29
	fieldTest              = 40000
	fieldRateLimitInfo     = 40001
)

func isEventField(n protowire.Number) bool {
	switch n { //nolint:exhaustive // a set of field numbers, not an enum
	case fieldProcessExec, fieldProcessExit, fieldProcessKprobe, fieldProcessTracepoint,
		fieldProcessLoader, fieldProcessUprobe, fieldProcessThrottle, fieldProcessLsm,
		fieldProcessUsdt, fieldTest, fieldRateLimitInfo:
		return true
	}
	return false
}

// peekAdmit classifies raw for admission. It walks the top-level fields
// only; nested messages are skipped, not parsed.
func peekAdmit(raw []byte) admitKind {
	var event protowire.Number
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return admitOther
		}
		raw = raw[n:]
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			return admitOther
		}
		raw = raw[m:]
		if !isEventField(num) {
			continue
		}
		if typ != protowire.BytesType || (event != 0 && event != num) {
			return admitOther
		}
		event = num
	}
	switch event { //nolint:exhaustive // a set of field numbers, not an enum
	case fieldProcessKprobe, fieldProcessLsm, fieldProcessTracepoint, fieldProcessUprobe:
		return admitSecurity
	case fieldRateLimitInfo:
		return admitRateLimitInfo
	}
	return admitOther
}

// tokenBucket admits rate events per second on average, in bursts of up
// to burst. Only the ingest goroutine uses it.
type tokenBucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newTokenBucket(r float64, now time.Time) *tokenBucket {
	return &tokenBucket{rate: r, burst: r, tokens: r, last: now}
}

func (b *tokenBucket) allow(now time.Time) bool {
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(b.burst, b.tokens+d.Seconds()*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateDrops accumulates events dropped by admission until the builder
// declares them in a rate_limited dropped record.
type rateDrops struct {
	mu          sync.Mutex
	n           uint64
	first, last int64
}

func (d *rateDrops) add(ts int64) {
	d.mu.Lock()
	if d.n == 0 {
		d.first, d.last = ts, ts
	}
	d.first, d.last = min(d.first, ts), max(d.last, ts)
	d.n++
	d.mu.Unlock()
}

func (d *rateDrops) take() (n uint64, first, last int64) {
	d.mu.Lock()
	n, first, last = d.n, d.first, d.last
	d.n, d.first, d.last = 0, 0, 0
	d.mu.Unlock()
	return n, first, last
}

// putBack returns a count that could not be spooled, so the next record
// declares it.
func (d *rateDrops) putBack(n uint64, first, last int64) {
	d.mu.Lock()
	if d.n == 0 {
		d.first, d.last = first, last
	} else {
		d.first, d.last = min(d.first, first), max(d.last, last)
	}
	d.n += n
	d.mu.Unlock()
}
