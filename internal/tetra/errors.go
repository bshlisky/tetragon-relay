package tetra

import (
	"errors"
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// Every rejection this package can produce has a distinct sentinel (or
// wraps one with %w), matching internal/policydoc and internal/guard's
// convention. Step 3 prompt Part B3 requires the client to distinguish
// these four classes for every call.
var (
	// ErrUnavailable means the dial or call failed to reach Tetragon at
	// all (connection refused/reset, socket verification failed, peer
	// credential mismatch).
	ErrUnavailable = errors.New("tetra: Tetragon is unavailable")

	// ErrRejectedByTetragon means Tetragon itself returned a non-OK gRPC
	// status for the call (the request reached it and was refused).
	ErrRejectedByTetragon = errors.New("tetra: rejected by Tetragon")

	// ErrTimeout means the call's context deadline (internal/tetra's own
	// timeout, not the caller's) was exceeded.
	ErrTimeout = errors.New("tetra: call timed out")

	// ErrProtocol means Tetragon responded, but not in a way this
	// package's typed allowlist/version gate can make sense of (wrong
	// version family, a stream message larger than
	// limits.MaxGetEventsResponseBytes, decode failure).
	ErrProtocol = errors.New("tetra: protocol error")

	// ErrSocketVerification means B2's pre-dial socket peer verification
	// failed. Distinct from ErrUnavailable so callers/tests can tell a
	// security check failure from an ordinary connection failure, though
	// both are treated identically by internal/apply (fail closed).
	ErrSocketVerification = errors.New("tetra: socket peer verification failed")

	// ErrUnsupportedVersion means GetVersion succeeded but did not match
	// limits.TetragonVersionPattern (Part B4).
	ErrUnsupportedVersion = errors.New("tetra: Tetragon version is not in the pinned v1.8.x family")
)

// truncateMessage implements Part B3's "Tetragon's message truncated to
// 512 bytes" rule, truncating on a rune boundary so the result is always
// valid UTF-8 (a raw byte truncation could split a multi-byte rune, which
// would corrupt the error text when logged/rendered).
func truncateMessage(s string) string {
	if len(s) <= limits.MaxTetragonErrorMessageBytes {
		return s
	}
	b := []byte(s)[:limits.MaxTetragonErrorMessageBytes]
	for len(b) > 0 {
		r := []rune(string(b))
		if string(r) == string(b) {
			break
		}
		b = b[:len(b)-1]
	}
	return string(b) + "...(truncated)"
}

// rejectedError wraps ErrRejectedByTetragon with a truncated copy of
// Tetragon's own message, never the full (potentially attacker/operator
// controlled, definitely unbounded) string.
func rejectedError(rpc string, msg string) error {
	return fmt.Errorf("%w: %s: %s", ErrRejectedByTetragon, rpc, truncateMessage(msg))
}
