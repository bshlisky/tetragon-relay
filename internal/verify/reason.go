package verify

import (
	"strings"
	"unicode/utf8"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// boundReason truncates s to at most limits.MaxReasonBytes bytes (on a valid
// UTF-8 boundary) and replaces any non-printable rune with '?'. It exists so
// a Result.Reason can safely include a small amount of context (e.g. a
// field name) without ever becoming a vector for log injection or an
// unbounded-size rejection message built from attacker-controlled data.
func boundReason(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || r < 0x20 {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > limits.MaxReasonBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
