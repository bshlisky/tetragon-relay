package tpm

import (
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

// This file provides a real TPM 2.0 implementation for this package's
// tests to run against: a swtpm (software TPM) subprocess per test, with
// its own fresh, isolated NV/persistent-object state in a t.TempDir().
// docs/prompts/step-05a.md C1: "Tests must run against a real TPM 2.0
// implementation... at least one CI job must exercise the real TPM
// command flows." Every test in this package that needs a TPM does,
// exercising the actual command encoding/decoding this package sends,
// not a mock of it.
//
// If the swtpm binary is not on PATH, these tests are skipped (not
// failed): this lets `go test ./...` stay green on a machine without
// swtpm installed (e.g. this project's own macOS development machine
// before `brew install swtpm`), while docs/workflows/ci-tpm.yml's CI job
// installs swtpm and so actually exercises every test here on every push
// (the "at least one CI job" requirement).

// startSWTPM launches a fresh swtpm instance with its own temp state
// directory and two free, dynamically-chosen TCP ports (command and
// platform/control, matching the de-facto TPM-over-TCP protocol
// github.com/google/go-tpm/tpm2/transport/tcp implements). It registers
// cleanup to kill the process on test completion. Returns an already
// power-on, started (TPM2_Startup(CLEAR)) transport.TPM.
func startSWTPM(t *testing.T) transport.TPM {
	t.Helper()
	swtpmPath, err := exec.LookPath("swtpm")
	if err != nil {
		t.Skip("swtpm not found on PATH; skipping real-TPM test (see docs/decisions/0027-tpm-library-and-software-tpm.md)")
	}

	stateDir := t.TempDir()
	cmdPort := mustFreePort(t)
	ctrlPort := mustFreePort(t)

	cmd := exec.Command(swtpmPath, "socket",
		"--tpmstate", "dir="+stateDir,
		"--ctrl", "type=tcp,port="+cmdPortStr(ctrlPort),
		"--server", "type=tcp,port="+cmdPortStr(cmdPort),
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

	cmdAddr := "localhost:" + cmdPortStr(cmdPort)
	ctrlAddr := "localhost:" + cmdPortStr(ctrlPort)
	var tt *tcp.TPM
	// swtpm needs a moment to start listening; retry briefly rather than
	// sleeping a fixed amount (flaky on slow CI runners otherwise).
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

	// swtpm with --flags not-need-init starts already powered on; ignore
	// a platform PowerOn failure for that reason (observed: NV_ON
	// returns an already-on error in that mode) and proceed straight to
	// TPM2_Startup, which is always required regardless.
	_ = tt.PowerOn()
	su := tpm2.Startup{StartupType: tpm2.TPMSUClear}
	if _, err := su.Execute(tt); err != nil {
		t.Fatalf("TPM2_Startup: %v", err)
	}
	return tt
}

func mustFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func cmdPortStr(p int) string {
	return strconv.Itoa(p)
}
