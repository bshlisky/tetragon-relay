//go:build integration

// Step 7b D1: GetEventsRequest.field_filters on the real Tetragon v1.8.0
// (the integration job's daemon), verified rather than assumed:
//   - does Tetragon accept an EXCLUDE filter, and keep sending events?
//   - are paths relative to the event message ("process.cwd")?
//   - what does excluding the environment save per event?
//
// Each case opens its own GetEvents stream for PROCESS_EXEC, runs a marker
// binary (a private copy of /usr/bin/true) with a marker environment
// variable, and inspects the marker's exec events as received (raw bytes,
// then decoded for the checks). The byte counts are printed for the
// report.
package tetra

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

const integrationSocket = "/var/run/tetragon/tetragon.sock"

func dialIntegration(t *testing.T) *Client {
	t.Helper()
	bin, err := exec.LookPath("tetragon")
	if err != nil {
		if b := os.Getenv("TETRAGON_BIN"); b != "" {
			bin = b
		} else {
			t.Fatalf("tetragon binary not found: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, Config{SocketPath: integrationSocket, TetragonBinaryPath: bin, RelayGroupName: "tetragon-relay", AllowSELinuxDisabled: true})
	if err != nil {
		t.Fatalf("Dial(real Tetragon): %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type markerEvents struct {
	n     int
	bytes int
	evs   []*tetragonpb.ProcessExec
}

// collect streams PROCESS_EXEC with exclude, runs marker 20 times, and
// returns the marker's exec events.
func collect(t *testing.T, c *Client, marker string, exclude []string) (markerEvents, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var got markerEvents
	errc := make(chan error, 1)
	go func() {
		errc <- c.StreamEvents(ctx, []tetragonpb.EventType{tetragonpb.EventType_PROCESS_EXEC}, exclude, func(raw []byte) bool {
			var ev tetragonpb.GetEventsResponse
			if proto.Unmarshal(raw, &ev) != nil {
				return true
			}
			if e := ev.GetProcessExec(); e != nil && e.GetProcess().GetBinary() == marker {
				mu.Lock()
				got.n++
				got.bytes += len(raw)
				got.evs = append(got.evs, e)
				mu.Unlock()
			}
			return true
		})
	}()
	time.Sleep(2 * time.Second) // the stream is open before the execs
	for i := 0; i < 20; i++ {
		cmd := exec.Command(marker, "--marker-arg", "x")
		cmd.Env = []string{"E3_FIELD_FILTER_MARKER=visible-if-tetragon-sends-env", "PATH=/usr/bin"}
		cmd.Dir = "/tmp"
		if err := cmd.Run(); err != nil {
			t.Fatalf("marker run: %v", err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := got.n
		mu.Unlock()
		if n >= 20 {
			break
		}
		select {
		case err := <-errc:
			return got, err
		case <-time.After(100 * time.Millisecond):
		}
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	return got, nil
}

func TestIntegration_FieldFilters(t *testing.T) {
	c := dialIntegration(t)
	marker := filepath.Join(t.TempDir(), "ff-marker-true")
	raw, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, raw, 0o755); err != nil { //nolint:gosec // G306: an executable test copy
		t.Fatal(err)
	}
	envPaths := []string{"process.environment_variables", "parent.environment_variables", "ancestors.environment_variables"}
	cases := []struct {
		name    string
		exclude []string
	}{
		{"none", nil},
		{"environment", envPaths},
		{"cwd", []string{"process.cwd"}},
		{"arguments+cwd", []string{"process.arguments", "process.cwd"}},
	}
	per := map[string]float64{}
	for _, tc := range cases {
		got, err := collect(t, c, marker, tc.exclude)
		if err != nil {
			t.Fatalf("%s: GetEvents with field filter %v: %v", tc.name, tc.exclude, err)
		}
		if got.n == 0 {
			t.Fatalf("%s: no marker exec events with field filter %v", tc.name, tc.exclude)
		}
		e := got.evs[0]
		per[tc.name] = float64(got.bytes) / float64(got.n)
		t.Logf("FIELD-FILTER %s: exclude=%v events=%d bytes/event=%.0f binary=%q args=%q cwd=%q env=%d parent=%v",
			tc.name, tc.exclude, got.n, per[tc.name], e.GetProcess().GetBinary(), e.GetProcess().GetArguments(),
			e.GetProcess().GetCwd(), len(e.GetProcess().GetEnvironmentVariables()), e.GetParent() != nil)
		switch tc.name {
		case "none":
			if e.GetProcess().GetCwd() == "" || !strings.Contains(e.GetProcess().GetArguments(), "--marker-arg") {
				t.Fatalf("unfiltered event lacks cwd or arguments: %v", e)
			}
		case "environment":
			if len(e.GetProcess().GetEnvironmentVariables()) != 0 {
				t.Fatalf("environment excluded but present: %v", e.GetProcess().GetEnvironmentVariables())
			}
			if e.GetProcess().GetCwd() == "" {
				t.Fatal("excluding the environment removed cwd")
			}
		case "cwd":
			// Paths are relative to the event message: process.cwd is gone,
			// the rest of the process stays.
			if e.GetProcess().GetCwd() != "" || e.GetProcess().GetBinary() != marker {
				t.Fatalf("process.cwd filter: cwd=%q binary=%q", e.GetProcess().GetCwd(), e.GetProcess().GetBinary())
			}
		case "arguments+cwd":
			if e.GetProcess().GetCwd() != "" || e.GetProcess().GetArguments() != "" {
				t.Fatalf("two-path filter: cwd=%q args=%q", e.GetProcess().GetCwd(), e.GetProcess().GetArguments())
			}
		}
	}
	t.Logf("FIELD-FILTER bytes/event: none=%.0f environment=%.0f cwd=%.0f arguments+cwd=%.0f",
		per["none"], per["environment"], per["cwd"], per["arguments+cwd"])
}
