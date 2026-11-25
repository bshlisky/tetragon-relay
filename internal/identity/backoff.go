package identity

import "time"

// RenewalBackoffBase and RenewalBackoffCap are B2's renewal-retry backoff
// parameters (architecture doc 5.4: "base 10 s, cap 5 min, full jitter").
const (
	RenewalBackoffBase = 10 * time.Second
	RenewalBackoffCap  = 5 * time.Minute
)

// RenewalBackoff computes a full-jitter exponential backoff delay for the
// attempt'th (0-indexed) renewal retry: a uniformly random duration in
// [0, min(cap, base*2^attempt)). r01 is a caller-supplied value in [0, 1)
// (production: rand.Float64()) rather than a hidden global random source,
// so this function is deterministic and testable (the project's "no
// hidden... calls" rule).
func RenewalBackoff(attempt int, r01 float64) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if r01 < 0 {
		r01 = 0
	}
	if r01 >= 1 {
		r01 = 1 - 1e-9
	}
	limit := RenewalBackoffBase
	for i := 0; i < attempt && limit < RenewalBackoffCap; i++ {
		limit *= 2
		if limit > RenewalBackoffCap {
			limit = RenewalBackoffCap
			break
		}
	}
	return time.Duration(float64(limit) * r01)
}
