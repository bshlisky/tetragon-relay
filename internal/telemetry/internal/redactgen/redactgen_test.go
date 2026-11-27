package redactgen

import (
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite internal/telemetry/redact_gen.go")

// genPath is redact_gen.go, relative to this package's directory.
const genPath = "../../redact_gen.go"

// TestRedactGenUpToDate fails if redact_gen.go is not what the vendored
// API's descriptors generate (go generate ./internal/telemetry runs this
// test with -update to rewrite it).
func TestRedactGenUpToDate(t *testing.T) {
	want, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(genPath, want, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("redact_gen.go is stale: run go generate ./internal/telemetry")
	}
	if n := len(Messages()); n < 50 {
		t.Fatalf("generated redactor covers %d messages; expected every message reachable from GetEventsResponse", n)
	}
}
