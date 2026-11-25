package tpm

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func TestOpenDevice_MissingPathIsError(t *testing.T) {
	if _, err := OpenDevice(filepath.Join(t.TempDir(), "no-such-tpm-device")); err == nil {
		t.Fatalf("OpenDevice on a nonexistent path unexpectedly succeeded")
	}
}

func TestWriteFileAtomic_NonexistentDirIsError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "no-such-subdir", "file")
	if err := writeFileAtomic(bad, []byte("x"), 0o600); err == nil {
		t.Fatalf("writeFileAtomic into a nonexistent directory unexpectedly succeeded")
	}
}

func TestProvisionSRK_CreatePrimaryFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCCreatePrimary), failOnCall: 1}
	if _, err := ProvisionSRK(f, nil); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("err = %v, want ErrTPMCommand", err)
	}
}

func TestKeySealer_SRKNotProvisionedIsError(t *testing.T) {
	// relayd never creates or persists the SRK itself (ADR 0029): a
	// KeySealer opened before relay-probe --provision-tpm has run must
	// fail closed, not fall back to creating one under the owner
	// hierarchy the way step 5a's code did.
	rtpm := startSWTPM(t)
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed.json")
	if _, err := NewKeySealer(rtpm, blobPath); !errors.Is(err, ErrSRKNotProvisioned) {
		t.Fatalf("err = %v, want ErrSRKNotProvisioned", err)
	}
}

func TestKeySealer_SealFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if _, err := ProvisionSRK(rtpm, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCCreate), failOnCall: 1}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed.json")
	if _, err := NewKeySealer(f, blobPath); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("err = %v, want ErrTPMCommand", err)
	}
}

func TestKeySealer_LoadFailureIsErrUnsealFailed(t *testing.T) {
	rtpm := startSWTPM(t)
	if _, err := ProvisionSRK(rtpm, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed.json")
	if _, err := NewKeySealer(rtpm, blobPath); err != nil {
		t.Fatalf("NewKeySealer: %v", err)
	}
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCLoad), failOnCall: 1}
	k := &KeySealer{t: f, blobPath: blobPath}
	if _, err := k.Unseal(); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("err = %v, want ErrUnsealFailed", err)
	}
}

func TestKeySealer_UnsealCommandFailureIsErrUnsealFailed(t *testing.T) {
	rtpm := startSWTPM(t)
	if _, err := ProvisionSRK(rtpm, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed.json")
	if _, err := NewKeySealer(rtpm, blobPath); err != nil {
		t.Fatalf("NewKeySealer: %v", err)
	}
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCUnseal), failOnCall: 1}
	k := &KeySealer{t: f, blobPath: blobPath}
	if _, err := k.Unseal(); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("err = %v, want ErrUnsealFailed", err)
	}
}

func TestProvisionCounter_DefineSpaceFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCNVDefineSpace), failOnCall: 1}
	if err := ProvisionCounter(f, testCounterHandle, nil); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("err = %v, want ErrTPMCommand", err)
	}
}

func TestCounter_ReadPublicFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if err := ProvisionCounter(rtpm, testCounterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCNVReadPublic), failOnCall: 1}
	c, err := OpenCounter(rtpm, testCounterHandle)
	if err != nil {
		t.Fatalf("OpenCounter: %v", err)
	}
	c.t = f
	if _, err := c.Read(); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("Read: err = %v, want ErrTPMCommand", err)
	}
}

func TestCounter_IncrementCommandFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if err := ProvisionCounter(rtpm, testCounterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	c, err := OpenCounter(rtpm, testCounterHandle)
	if err != nil {
		t.Fatalf("OpenCounter: %v", err)
	}
	c.t = &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCNVIncrement), failOnCall: 1}
	if _, err := c.Increment(); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("Increment: err = %v, want ErrTPMCommand", err)
	}
}

func TestCounter_ReadAfterIncrementFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if err := ProvisionCounter(rtpm, testCounterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	c, err := OpenCounter(rtpm, testCounterHandle)
	if err != nil {
		t.Fatalf("OpenCounter: %v", err)
	}
	// Fail the SECOND NVReadPublic call: the first is Increment's own
	// pre-read (to get the index Name), the second is the post-increment
	// read-back this test targets.
	c.t = &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCNVReadPublic), failOnCall: 2}
	if _, err := c.Increment(); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("Increment: err = %v, want ErrTPMCommand", err)
	}
}

func TestCounter_NVReadFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if err := ProvisionCounter(rtpm, testCounterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	c, err := OpenCounter(rtpm, testCounterHandle)
	if err != nil {
		t.Fatalf("OpenCounter: %v", err)
	}
	if _, err := c.Increment(); err != nil {
		t.Fatalf("Increment (seed a written value): %v", err)
	}
	c.t = &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCNVRead), failOnCall: 1}
	if _, err := c.Read(); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("Read: err = %v, want ErrTPMCommand", err)
	}
}

func TestDetectSigningCurve_FallsBackToP256WhenP384Unavailable(t *testing.T) {
	rtpm := startSWTPM(t)
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCTestParms), failOnCall: 1}
	curve, err := detectSigningCurve(f)
	if err != nil {
		t.Fatalf("detectSigningCurve: %v", err)
	}
	if curve != CurveP256 {
		t.Fatalf("curve = %q, want %q (P-384 TestParms was forced to fail)", curve, CurveP256)
	}
}

func TestDetectSigningCurve_NoCurveSupportedIsError(t *testing.T) {
	rtpm := startSWTPM(t)
	alwaysFail := &alwaysFailCommand{inner: rtpm, failCommand: cc(tpm2.TPMCCTestParms)}
	if _, err := detectSigningCurve(alwaysFail); !errors.Is(err, ErrNoSupportedSigningCurve) {
		t.Fatalf("err = %v, want ErrNoSupportedSigningCurve", err)
	}
}

func TestSign_LoadFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if _, err := ProvisionSRK(rtpm, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	hs, err := NewOrLoadHostSigner(rtpm, blobPath)
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner: %v", err)
	}
	hs.t = &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCLoad), failOnCall: 1}
	digest := make([]byte, 48)
	if _, err := hs.Sign(nil, digest, nil); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("Sign: err = %v, want ErrTPMCommand", err)
	}
}

func TestSign_SignCommandFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if _, err := ProvisionSRK(rtpm, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	hs, err := NewOrLoadHostSigner(rtpm, blobPath)
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner: %v", err)
	}
	hs.t = &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCSign), failOnCall: 1}
	digest := make([]byte, 48)
	if _, err := hs.Sign(nil, digest, nil); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("Sign: err = %v, want ErrTPMCommand", err)
	}
}

func TestSign_WrongDigestLengthIsError(t *testing.T) {
	rtpm := startSWTPM(t)
	if _, err := ProvisionSRK(rtpm, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	hs, err := NewOrLoadHostSigner(rtpm, blobPath)
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner: %v", err)
	}
	if _, err := hs.Sign(nil, make([]byte, 32), nil); err == nil {
		t.Fatalf("Sign with a wrong-length digest for a P-384 key unexpectedly succeeded")
	}
}

// alwaysFailCommand fails every occurrence of failCommand, unlike
// faultTPM which only fails one specific occurrence. Used for "no curve
// supported at all" (both P-384 and P-256 TestParms calls must fail).
type alwaysFailCommand struct {
	inner       transport.TPM
	failCommand uint32
}

func (a *alwaysFailCommand) Send(cmd []byte) ([]byte, error) {
	if len(cmd) >= 10 {
		var ccVal uint32
		for i := 0; i < 4; i++ {
			ccVal = ccVal<<8 | uint32(cmd[6+i])
		}
		if ccVal == a.failCommand {
			return nil, errFaultInjected
		}
	}
	return a.inner.Send(cmd)
}
