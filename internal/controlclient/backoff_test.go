package controlclient

import (
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

func TestDialBackoff_Bounds(t *testing.T) {
	if got := DialBackoff(0, 0); got != 0 {
		t.Fatalf("DialBackoff(0, 0) = %v, want 0", got)
	}
	if got := DialBackoff(0, 0.999999999); got >= limits.ControlDialBackoffBase {
		t.Fatalf("DialBackoff(0, ~1) = %v, want < base %v", got, limits.ControlDialBackoffBase)
	}
	if got := DialBackoff(20, 0.999999999); got > limits.ControlDialBackoffCap {
		t.Fatalf("DialBackoff(20, ~1) = %v, want <= cap %v", got, limits.ControlDialBackoffCap)
	}
}

func TestDialBackoff_Exponential(t *testing.T) {
	prev := DialBackoff(0, 0.5)
	for attempt := 1; attempt < 10; attempt++ {
		got := DialBackoff(attempt, 0.5)
		if got < prev {
			t.Fatalf("DialBackoff(%d, 0.5) = %v, want >= previous attempt's %v", attempt, got, prev)
		}
		prev = got
	}
}

func TestDialBackoff_ClampsOutOfRangeInputs(t *testing.T) {
	if got := DialBackoff(-1, -1); got != 0 {
		t.Fatalf("DialBackoff(-1, -1) = %v, want 0", got)
	}
	if got := DialBackoff(-1, 2); got > limits.ControlDialBackoffBase {
		t.Fatalf("DialBackoff(-1, 2) = %v, want <= base %v", got, limits.ControlDialBackoffBase)
	}
}
