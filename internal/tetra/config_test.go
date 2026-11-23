package tetra

import (
	"log/slog"
	"os"
	"os/user"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

func TestConfig_TimeoutDefault(t *testing.T) {
	var c Config
	if got := c.timeout(); got != limits.DefaultTetragonRPCTimeout {
		t.Fatalf("timeout() = %v, want default %v", got, limits.DefaultTetragonRPCTimeout)
	}
	c.Timeout = 3 * time.Second
	if got := c.timeout(); got != 3*time.Second {
		t.Fatalf("timeout() = %v, want 3s", got)
	}
}

func TestConfig_LoggerDefault(t *testing.T) {
	var c Config
	if c.logger() != slog.Default() {
		t.Fatal("logger() did not default to slog.Default()")
	}
	custom := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c.Logger = custom
	if c.logger() != custom {
		t.Fatal("logger() did not return the configured Logger")
	}
}

func TestConfig_RelayGID(t *testing.T) {
	// Use the current user's primary group, which is guaranteed to exist
	// and be resolvable by name on every platform this test runs on,
	// without requiring root or a fixed group name.
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("LookupGroupId: %v", err)
	}
	c := Config{RelayGroupName: g.Name}
	gid, err := c.relayGID()
	if err != nil {
		t.Fatalf("relayGID: %v", err)
	}
	if gid == 0 && g.Gid != "0" {
		t.Fatalf("relayGID() = 0, want %s", g.Gid)
	}

	bad := Config{RelayGroupName: "this-group-should-not-exist-tetragon-relay"}
	if _, err := bad.relayGID(); err == nil {
		t.Fatal("relayGID() for a nonexistent group returned no error")
	}
}
