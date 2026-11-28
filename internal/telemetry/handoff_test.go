package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestHandoff_OrderAndChunkSignal(t *testing.T) {
	h := newHandoff(4, 16, time.Hour)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if !h.put(ctx, []byte{byte(i)}) {
			t.Fatal("put failed")
		}
	}
	// The first put signaled; the queue is below a chunk.
	select {
	case <-h.ready():
	default:
		t.Fatal("no signal for the first event")
	}
	select {
	case <-h.ready():
		t.Fatal("signal before a full chunk")
	default:
	}
	// The fourth event completes a chunk: take must not wait out its
	// (hour-long) delay.
	done := make(chan [][]byte, 1)
	go func() { done <- h.take(ctx, nil) }()
	time.Sleep(20 * time.Millisecond)
	h.put(ctx, []byte{3})
	select {
	case evs := <-done:
		if len(evs) != 4 {
			t.Fatalf("took %d events, want 4", len(evs))
		}
		for i, e := range evs {
			if e[0] != byte(i) {
				t.Fatalf("event %d out of order: %v", i, e)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("take waited for its delay despite a full chunk")
	}
}

func TestHandoff_DelayThenTakesWhatArrived(t *testing.T) {
	h := newHandoff(64, 1024, 20*time.Millisecond)
	ctx := context.Background()
	h.put(ctx, []byte("a"))
	<-h.ready() // as the builder does before take
	start := time.Now()
	evs := h.take(ctx, make([][]byte, 0, 8))
	if len(evs) != 1 || string(evs[0]) != "a" {
		t.Fatalf("take = %q", evs)
	}
	if d := time.Since(start); d < 15*time.Millisecond {
		t.Fatalf("take returned after %v, before its drain delay", d)
	}
	if h.len() != 0 {
		t.Fatal("queue not empty after take")
	}
}

func TestHandoff_ChunkOneHasNoDelay(t *testing.T) {
	h := newHandoff(1, 8, time.Hour)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		h.put(ctx, []byte{byte(i)})
		<-h.ready() // every event signals
		if evs := h.take(ctx, nil); len(evs) != 1 {
			t.Fatalf("took %d, want 1", len(evs))
		}
	}
}

func TestHandoff_BackpressureAndCancel(t *testing.T) {
	h := newHandoff(64, 2, 0)
	ctx, cancel := context.WithCancel(context.Background())
	h.put(ctx, []byte("1"))
	h.put(ctx, []byte("2"))
	blocked := make(chan bool, 1)
	go func() { blocked <- h.put(ctx, []byte("3")) }()
	select {
	case <-blocked:
		t.Fatal("put did not block on a full queue")
	case <-time.After(30 * time.Millisecond):
	}
	// A take frees space: the blocked put completes.
	if evs := h.take(ctx, nil); len(evs) != 2 {
		t.Fatalf("took %d, want 2", len(evs))
	}
	if ok := <-blocked; !ok {
		t.Fatal("put failed after space was freed")
	}
	// Full again, then ctx ends: put returns false.
	h.put(ctx, []byte("4"))
	go func() { blocked <- h.put(ctx, []byte("5")) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if ok := <-blocked; ok {
		t.Fatal("put on a full queue returned true after cancel")
	}
	// take does not wait out its delay once ctx is done.
	h2 := newHandoff(64, 8, time.Hour)
	h2.put(context.Background(), []byte("x"))
	if evs := h2.take(ctx, nil); len(evs) != 1 {
		t.Fatalf("took %d after cancel, want 1", len(evs))
	}
}
