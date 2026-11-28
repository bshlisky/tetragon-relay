package telemetry

import (
	"testing"
	"time"
)

func TestRateMeter(t *testing.T) {
	var r rateMeter
	t0 := time.Unix(1700000000, 0)
	if r.perSecond() != 0 {
		t.Fatal("empty meter")
	}
	r.sample(t0, 0)
	r.sample(t0.Add(500*time.Millisecond), 999) // under a second: ignored
	if r.perSecond() != 0 {
		t.Fatal("one sample")
	}
	for i := 1; i <= 90; i++ {
		r.sample(t0.Add(time.Duration(i)*time.Second), uint64(i)*100)
	}
	if got := r.perSecond(); got != 100 {
		t.Fatalf("perSecond = %d, want 100", got)
	}
	if len(r.samples) > 62 {
		t.Fatalf("%d samples held, want at most one a second over 60 s", len(r.samples))
	}
	r.sample(t0.Add(200*time.Second), 5) // the old samples age out
	if len(r.samples) != 1 || r.perSecond() != 0 {
		t.Fatalf("after a gap: %d samples, rate %d", len(r.samples), r.perSecond())
	}
	r.sample(t0.Add(202*time.Second), 1) // counter went backwards: no rate
	if r.perSecond() != 0 {
		t.Fatal("negative rate")
	}
}
