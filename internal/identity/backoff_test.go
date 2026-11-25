package identity

import "testing"

func TestRenewalBackoff_Bounds(t *testing.T) {
	if got := RenewalBackoff(0, 0); got != 0 {
		t.Fatalf("RenewalBackoff(0, 0) = %v, want 0", got)
	}
	if got := RenewalBackoff(0, 0.999999999); got >= RenewalBackoffBase {
		t.Fatalf("RenewalBackoff(0, ~1) = %v, want < base %v", got, RenewalBackoffBase)
	}
	// After enough attempts, the max must saturate at the cap, never
	// exceed it regardless of r01.
	if got := RenewalBackoff(20, 0.999999999); got > RenewalBackoffCap {
		t.Fatalf("RenewalBackoff(20, ~1) = %v, want <= cap %v", got, RenewalBackoffCap)
	}
	if got := RenewalBackoff(20, 0.999999999); got < RenewalBackoffCap/2 {
		t.Fatalf("RenewalBackoff(20, ~1) = %v, want close to cap %v (saturated)", got, RenewalBackoffCap)
	}
}

func TestRenewalBackoff_Exponential(t *testing.T) {
	// At a fixed r01, delay should (weakly) increase with attempt until
	// the cap saturates it.
	prev := RenewalBackoff(0, 0.5)
	for attempt := 1; attempt < 10; attempt++ {
		got := RenewalBackoff(attempt, 0.5)
		if got < prev {
			t.Fatalf("RenewalBackoff(%d, 0.5) = %v, want >= previous attempt's %v", attempt, got, prev)
		}
		prev = got
	}
}

func TestRenewalBackoff_ClampsOutOfRangeInputs(t *testing.T) {
	if got := RenewalBackoff(-1, -1); got != 0 {
		t.Fatalf("RenewalBackoff(-1, -1) = %v, want 0", got)
	}
	if got := RenewalBackoff(-1, 2); got > RenewalBackoffBase {
		t.Fatalf("RenewalBackoff(-1, 2) = %v, want <= base %v", got, RenewalBackoffBase)
	}
}
