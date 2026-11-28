package telemetry

import (
	"sync"
	"time"
)

// rateWindow is the heartbeat's telemetry_events_per_s window
// (step-07b-decisions.md D2: a 60 s average of events spooled, which is
// what operators size the spool from).
const rateWindow = 60 * time.Second

type rateSample struct {
	at    time.Time
	total uint64
}

// rateMeter keeps at most one sample per second over the last rateWindow.
// The builder samples; the heartbeat reads. Neither waits on the other
// for long: one small mutex, no spool lock (step 7b D0).
type rateMeter struct {
	mu      sync.Mutex
	samples []rateSample
}

func (r *rateMeter) sample(now time.Time, total uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := len(r.samples); n > 0 && now.Sub(r.samples[n-1].at) < time.Second {
		return
	}
	cut := 0
	for cut < len(r.samples) && now.Sub(r.samples[cut].at) > rateWindow {
		cut++
	}
	r.samples = append(r.samples[cut:], rateSample{now, total})
}

// perSecond is the average over the samples held: 0 until two samples
// are at least a second apart.
func (r *rateMeter) perSecond() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.samples) < 2 {
		return 0
	}
	a, b := r.samples[0], r.samples[len(r.samples)-1]
	dt := b.at.Sub(a.at).Seconds()
	if dt < 1 || b.total < a.total {
		return 0
	}
	v := float64(b.total-a.total) / dt
	if v > float64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v + 0.5)
}

// EventsPerSecond is Heartbeat.telemetry_events_per_s: the events spooled
// per second over the last minute (D2).
func (p *Pipeline) EventsPerSecond() uint32 { return p.rate.perSecond() }
