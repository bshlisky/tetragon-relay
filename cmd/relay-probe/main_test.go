package main

import (
	"os"
	"runtime"
	"testing"
)

func collectIsImplemented() bool { return runtime.GOOS == "linux" }

// TestRun_ReportMode exercises --report end to end. On non-linux
// development machines collect() always errors (see collect_other.go), so
// this only asserts run() propagates that failure with exit code 1 rather
// than panicking; the real success path is exercised on linux CI (step 3
// prompt Part E3/C5) where collect() is the real implementation.
//
// --tetragon-binary is pointed at this test binary's own executable
// (guaranteed to exist and be readable, unlike the default
// "/usr/local/bin/tetragon") rather than left at its default: the plain
// "ci" job's runner has no Tetragon installed at all (only the
// "integration" job installs one), so collect()'s sha256File step would
// otherwise fail for a reason that has nothing to do with the rest of
// collect_linux.go actually working.
func TestRun_ReportMode(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	code := run([]string{"--report", "--tetragon-binary", self}, devNull, devNull)
	if collectIsImplemented() {
		if code != 0 {
			t.Fatalf("run(--report) = %d, want 0", code)
		}
	} else if code != 1 {
		t.Fatalf("run(--report) on a platform without collect() = %d, want 1", code)
	}
}

func TestRun_BadFlag(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	if code := run([]string{"--not-a-real-flag"}, devNull, devNull); code != 2 {
		t.Fatalf("run with an unknown flag = %d, want 2", code)
	}
}

// TestRun_ProvisionTPM_MissingDeviceFails covers --provision-tpm's own
// flag-wiring and error path (run() returns 1, not a panic, and never
// falls through to collect()/the facts-file path): the TPM success path
// itself is internal/tpm.ProvisionCounter's own test suite's job
// (internal/tpm/counter_test.go, against a real software TPM), since
// provisionTPMCounter needs a real "/dev/tpmrm0"-shaped device file this
// test environment cannot provide.
func TestRun_ProvisionTPM_MissingDeviceFails(t *testing.T) {
	dir := t.TempDir()
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	code := run([]string{
		"--provision-tpm",
		"--tpm-device", dir + "/no-such-tpmrm0",
	}, devNull, devNull)
	if code != 1 {
		t.Fatalf("run(--provision-tpm) with a missing device = %d, want 1", code)
	}
}

func TestRun_UnresolvableGroup(t *testing.T) {
	if !collectIsImplemented() {
		t.Skip("collect() is not implemented on this platform; nothing to test past flag parsing")
	}
	dir := t.TempDir()
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	code := run([]string{
		"--relay-group", "this-group-should-not-exist-tetragon-relay",
		"--facts-path", dir + "/host-facts.json",
	}, devNull, devNull)
	if code != 1 {
		t.Fatalf("run with an unresolvable group = %d, want 1", code)
	}
}
