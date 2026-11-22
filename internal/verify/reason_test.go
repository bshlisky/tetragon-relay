package verify

import (
	"strings"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

func TestBoundReason_ShortStringUnchanged(t *testing.T) {
	if got := boundReason("short reason"); got != "short reason" {
		t.Fatalf("got %q", got)
	}
}

func TestBoundReason_TruncatesLongStrings(t *testing.T) {
	long := strings.Repeat("a", limits.MaxReasonBytes*2)
	got := boundReason(long)
	if len(got) > limits.MaxReasonBytes {
		t.Fatalf("len(got) = %d, want <= %d", len(got), limits.MaxReasonBytes)
	}
	if got != strings.Repeat("a", limits.MaxReasonBytes) {
		t.Fatalf("truncation did not preserve the leading bytes")
	}
}

func TestBoundReason_EscapesControlCharacters(t *testing.T) {
	got := boundReason("line1\nline2\x00end")
	if strings.ContainsAny(got, "\n\x00") {
		t.Fatalf("control characters were not escaped: %q", got)
	}
}

func TestBoundReason_ReplacesInvalidUTF8(t *testing.T) {
	got := boundReason(string([]byte{0xff, 0xfe}) + "tail")
	if !strings.Contains(got, "tail") {
		t.Fatalf("expected tail to survive, got %q", got)
	}
}
