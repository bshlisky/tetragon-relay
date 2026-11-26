package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestNewJSONAuditor_RejectsNilOutOrClock(t *testing.T) {
	if _, err := NewJSONAuditor(nil, fixedClock(time.Unix(0, 0))); err == nil {
		t.Fatal("NewJSONAuditor(nil out, ...) = nil error, want an error")
	}
	if _, err := NewJSONAuditor(&bytes.Buffer{}, nil); err == nil {
		t.Fatal("NewJSONAuditor(..., nil clock) = nil error, want an error")
	}
}

func TestJSONAuditor_RecordWritesOneJSONLine(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("test", 3600))
	a, err := NewJSONAuditor(&buf, fixedClock(now))
	if err != nil {
		t.Fatalf("NewJSONAuditor: %v", err)
	}
	a.Record(Event{Step: "watchdog_withheld", Detail: `component "session_runner" stale`, Err: "boom", Domain: "prod-web", Policy: "foo-v1"})

	lines := splitLines(t, buf.String())
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %q", len(lines), buf.String())
	}
	var got jsonLine
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v (line: %q)", err, lines[0])
	}
	want := jsonLine{
		Time:   now.UTC().Format(time.RFC3339Nano),
		Step:   "watchdog_withheld",
		Detail: `component "session_runner" stale`,
		Err:    "boom",
		Domain: "prod-web",
		Policy: "foo-v1",
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if !strings.Contains(lines[0], `"time":"`+now.UTC().Format(time.RFC3339Nano)) {
		t.Fatalf("line does not use UTC, clock-provided time: %q", lines[0])
	}
}

func TestJSONAuditor_RecordOmitsEmptyOptionalFields(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewJSONAuditor(&buf, fixedClock(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("NewJSONAuditor: %v", err)
	}
	a.Record(Event{Step: "crypto_self_test"})
	line := strings.TrimSpace(buf.String())
	for _, key := range []string{`"detail"`, `"err"`, `"domain"`, `"policy"`} {
		if strings.Contains(line, key) {
			t.Fatalf("line %q unexpectedly contains empty-field key %s", line, key)
		}
	}
}

func TestJSONAuditor_TruncatesOversizedFields(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewJSONAuditor(&buf, fixedClock(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("NewJSONAuditor: %v", err)
	}
	huge := strings.Repeat("x", limits.MaxAuditFieldBytes*4)
	a.Record(Event{Step: "oversized", Detail: huge})

	var got jsonLine
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Detail) != limits.MaxAuditFieldBytes {
		t.Fatalf("Detail length = %d, want exactly %d (truncated, not dropped)", len(got.Detail), limits.MaxAuditFieldBytes)
	}
}

// TestJSONAuditor_WriteFailureIsCountedNotPropagated proves Record never
// blocks the caller or panics when the sink's Write fails (e.g. a full
// disk / closed pipe downstream of systemd's own journal forwarding) --
// it only increments WriteFailures.
func TestJSONAuditor_WriteFailureIsCountedNotPropagated(t *testing.T) {
	a, err := NewJSONAuditor(failingWriter{}, fixedClock(time.Unix(0, 0)))
	if err != nil {
		t.Fatalf("NewJSONAuditor: %v", err)
	}
	a.Record(Event{Step: "x"})
	a.Record(Event{Step: "y"})
	if got := a.WriteFailures(); got != 2 {
		t.Fatalf("WriteFailures() = %d, want 2", got)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write: broken pipe") }

// TestEvent_FieldsAreAllPlainStrings is this package's own defensive
// invariant against a future regression: Event must never grow a field
// that could carry a raw payload (an envelope, policy YAML, or key
// material) -- only plain strings, which this package's own truncate/
// json.Marshal path treats uniformly and boundedly. A reviewer adding a
// non-string field to Event will see this test fail and have to justify
// it explicitly.
func TestEvent_FieldsAreAllPlainStrings(t *testing.T) {
	typ := reflect.TypeOf(Event{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.String {
			t.Fatalf("Event.%s has kind %s, want string (audit.Event must only ever carry plain, bounded strings)", f.Name, f.Type.Kind())
		}
	}
}

// TestJSONLine_FieldsAreAllPlainStrings is the same invariant for the
// wire shape Record actually marshals.
func TestJSONLine_FieldsAreAllPlainStrings(t *testing.T) {
	typ := reflect.TypeOf(jsonLine{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.String {
			t.Fatalf("jsonLine.%s has kind %s, want string", f.Name, f.Type.Kind())
		}
	}
}

func splitLines(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if sc.Text() != "" {
			out = append(out, sc.Text())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}
