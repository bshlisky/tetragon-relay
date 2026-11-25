//go:build tpm_e2e

package tpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
)

// TestTPMRealDeviceRoundTrip is run ONLY by scripts/e2e-rhel9.sh (build
// tag tpm_e2e, never part of `go test ./...`, `make ci`, or any CI job
// -- it requires real hardware or a vTPM, docs/prompts/step-05a.md D3)
// against a real TPM 2.0 device at TPM_E2E_DEVICE (default
// "/dev/tpmrm0"): the same KeySealer/Counter/store round trip
// TestStoreRoundTrip_RealSealerAndCounterSurviveSimulatedRestart proves
// against swtpm, here proving it against the real device path
// (OpenDevice/linuxtpm.Open) that every other test in this package's
// suite cannot exercise.
//
// This uses tpm.DefaultCounterHandle for real: running it against a
// production host's TPM would permanently advance that host's actual
// rollback-protection counter, which is why this is gated behind a
// build tag that only scripts/e2e-rhel9.sh's own documented "customer's
// TEST server" (not production) use case ever sets.
func TestTPMRealDeviceRoundTrip(t *testing.T) {
	devicePath := os.Getenv("TPM_E2E_DEVICE")
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}
	dev, err := OpenDevice(devicePath)
	if err != nil {
		t.Fatalf("OpenDevice(%s): %v (is a real TPM 2.0 device, or vTPM, present and accessible?)", devicePath, err)
	}
	defer func() { _ = dev.Close() }()

	if _, err := ProvisionSRK(dev, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	if err := ProvisionCounter(dev, DefaultCounterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	blobPath := filepath.Join(dir, "sealed-hmac-key.json")

	openStore := func() *store.Store {
		t.Helper()
		sealer, err := NewKeySealer(dev, blobPath)
		if err != nil {
			t.Fatalf("NewKeySealer: %v", err)
		}
		counter, err := OpenCounter(dev, DefaultCounterHandle)
		if err != nil {
			t.Fatalf("OpenCounter: %v", err)
		}
		st, err := store.Open(dir, sealer, counter)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		return st
	}

	st := openStore()
	rootRaw := []byte("fake-root-metadata-bytes-for-e2e-real-device-roundtrip")
	if err := st.PersistTrustRoot(rootRaw, 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	if err := st.Put(apply.RelayDomain, apply.LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2 := openStore()
	defer func() { _ = st2.Close() }()
	if _, _, ok, err := st2.TrustRoot(); err != nil || !ok {
		t.Fatalf("TrustRoot after restart: ok=%v err=%v", ok, err)
	}
	if _, ok := st2.Get(apply.RelayDomain); !ok {
		t.Fatalf("Get after restart: ok = false")
	}

	t.Logf("TestTPMRealDeviceRoundTrip: PASS against device %s", devicePath)
}

// TestHostSignerRealDeviceCurveDetection records which curve the real
// device actually supports (docs/prompts/step-05a.md D3: "supported ECC
// curves" is one of the facts e2e-rhel9.sh's TPM section must print).
func TestHostSignerRealDeviceCurveDetection(t *testing.T) {
	devicePath := os.Getenv("TPM_E2E_DEVICE")
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}
	dev, err := OpenDevice(devicePath)
	if err != nil {
		t.Fatalf("OpenDevice(%s): %v", devicePath, err)
	}
	defer func() { _ = dev.Close() }()

	curve, err := detectSigningCurve(dev)
	if err != nil {
		t.Fatalf("detectSigningCurve: %v", err)
	}
	t.Logf("TestHostSignerRealDeviceCurveDetection: this TPM's HostSigner curve = %s", curve)
}
