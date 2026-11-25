package controlclient

import (
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// DialBackoff computes a full-jitter exponential backoff delay for the
// attempt'th (0-indexed) reconnect attempt: a uniformly random duration
// in [0, min(cap, base*2^attempt)) (architecture doc 6.3 step 6: "full-
// jitter exponential backoff (1 s base, 5 min cap)"). r01 is a
// caller-supplied value in [0, 1) (production: rand.Float64()) rather
// than a hidden global random source, so this function is deterministic
// and testable.
func DialBackoff(attempt int, r01 float64) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if r01 < 0 {
		r01 = 0
	}
	if r01 >= 1 {
		r01 = 1 - 1e-9
	}
	limit := limits.ControlDialBackoffBase
	for i := 0; i < attempt && limit < limits.ControlDialBackoffCap; i++ {
		limit *= 2
		if limit > limits.ControlDialBackoffCap {
			limit = limits.ControlDialBackoffCap
			break
		}
	}
	return time.Duration(float64(limit) * r01)
}
