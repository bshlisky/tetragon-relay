package agent

import (
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

// BuildTPMComponents takes an already-open transport.TPM, so it can be
// exercised against a real software TPM (swtpm) dialed over TCP, the same
// real-TPM testing approach internal/tpm's own test suite uses
// (docs/decisions/0027-tpm-library-and-software-tpm.md) -- skipped, not
// failed, if swtpm is not on PATH.
func startSWTPMForAgentTest(t *testing.T) transport.TPM {
	t.Helper()
	swtpmPath, err := exec.LookPath("swtpm")
	if err != nil {
		t.Skip("swtpm not found on PATH; skipping real-TPM test")
	}
	stateDir := t.TempDir()
	cmdPort := mustFreePortForAgentTest(t)
	ctrlPort := mustFreePortForAgentTest(t)
	cmd := exec.Command(swtpmPath, "socket",
		"--tpmstate", "dir="+stateDir,
		"--ctrl", "type=tcp,port="+strconv.Itoa(ctrlPort),
		"--server", "type=tcp,port="+strconv.Itoa(cmdPort),
		"--tpm2",
		"--flags", "not-need-init",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	cmdAddr := "localhost:" + strconv.Itoa(cmdPort)
	ctrlAddr := "localhost:" + strconv.Itoa(ctrlPort)
	var tt *tcp.TPM
	deadline := time.Now().Add(10 * time.Second)
	for {
		tt, err = tcp.Open(tcp.Config{CommandAddress: cmdAddr, PlatformAddress: ctrlAddr})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect to swtpm: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Cleanup(func() { _ = tt.Close() })
	_ = tt.PowerOn()
	su := tpm2.Startup{StartupType: tpm2.TPMSUClear}
	if _, err := su.Execute(tt); err != nil {
		t.Fatalf("TPM2_Startup: %v", err)
	}
	return tt
}

func mustFreePortForAgentTest(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func TestBuildTPMComponents_Success(t *testing.T) {
	rtpm := startSWTPMForAgentTest(t)
	if err := tpm.ProvisionCounter(rtpm, tpm.DefaultCounterHandle); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	dir := t.TempDir()
	comp, err := BuildTPMComponents(rtpm, filepath.Join(dir, "sealed.json"))
	if err != nil {
		t.Fatalf("BuildTPMComponents: %v", err)
	}
	if comp.Sealer == nil || comp.Counter == nil {
		t.Fatalf("BuildTPMComponents returned a nil Sealer or Counter")
	}
	key, err := comp.Sealer.Unseal()
	if err != nil {
		t.Fatalf("Sealer.Unseal: %v", err)
	}
	if len(key) == 0 {
		t.Fatalf("Unseal returned an empty key")
	}
	if _, err := comp.Counter.Increment(); err != nil {
		t.Fatalf("Counter.Increment: %v", err)
	}
}

func TestBuildTPMComponents_CounterNotProvisionedIsErrTPMRequired(t *testing.T) {
	rtpm := startSWTPMForAgentTest(t)
	dir := t.TempDir()
	if _, err := BuildTPMComponents(rtpm, filepath.Join(dir, "sealed.json")); !errors.Is(err, ErrTPMRequired) {
		t.Fatalf("err = %v, want ErrTPMRequired", err)
	}
}

func TestBuildTPMComponents_SealerFailureIsErrTPMRequired(t *testing.T) {
	rtpm := startSWTPMForAgentTest(t)
	// A sealed-key blob path under a nonexistent parent directory makes
	// tpm.NewKeySealer's first-boot write fail.
	bad := filepath.Join(t.TempDir(), "no-such-subdir", "sealed.json")
	if _, err := BuildTPMComponents(rtpm, bad); !errors.Is(err, ErrTPMRequired) {
		t.Fatalf("err = %v, want ErrTPMRequired", err)
	}
}
