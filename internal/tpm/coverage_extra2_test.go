package tpm

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestReadNVPublic_GenericFailureIsErrTPMCommand(t *testing.T) {
	rtpm := startSWTPM(t)
	f := &alwaysFailCommand{inner: rtpm, failCommand: cc(tpm2.TPMCCNVReadPublic)}
	if _, _, _, err := readNVPublic(f, testCounterHandle); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("err = %v, want ErrTPMCommand", err)
	}
}

func TestProvisionCounter_ReadPublicGenericFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	f := &alwaysFailCommand{inner: rtpm, failCommand: cc(tpm2.TPMCCNVReadPublic)}
	if err := ProvisionCounter(f, testCounterHandle); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("err = %v, want ErrTPMCommand", err)
	}
}

func TestOpenCounter_ReadPublicGenericFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if err := ProvisionCounter(rtpm, testCounterHandle); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	f := &alwaysFailCommand{inner: rtpm, failCommand: cc(tpm2.TPMCCNVReadPublic)}
	if _, err := OpenCounter(f, testCounterHandle); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("err = %v, want ErrTPMCommand", err)
	}
}

func TestCounter_Read_NotProvisionedSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	// Construct a Counter directly (bypassing OpenCounter's own
	// provisioning check) against a handle that was never provisioned.
	c := &Counter{t: rtpm, handle: tpm2.TPMHandle(0x01500099)}
	if _, err := c.Read(); !errors.Is(err, ErrCounterNotProvisioned) {
		t.Fatalf("err = %v, want ErrCounterNotProvisioned", err)
	}
}

func TestCounter_Read_AttributeMismatchAfterOpenSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	// Define an index with the WRONG attributes directly, then construct
	// a Counter against it without going through OpenCounter's own
	// validation (simulating the index having been tampered with /
	// collided between an earlier OpenCounter and a later Read -- the
	// defense-in-depth case).
	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B[tpm2.TPMSNVPublic](tpm2.TPMSNVPublic{
			NVIndex:    testCounterHandle,
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, NT: tpm2.TPMNTOrdinary, NoDA: true},
			DataSize:   counterDataSize,
		}),
	}
	if _, err := def.Execute(rtpm); err != nil {
		t.Fatalf("NVDefineSpace: %v", err)
	}
	c := &Counter{t: rtpm, handle: testCounterHandle}
	if _, err := c.Read(); !errors.Is(err, ErrNVIndexAttributeMismatch) {
		t.Fatalf("err = %v, want ErrNVIndexAttributeMismatch", err)
	}
}

func TestCounter_Increment_NotProvisionedSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	c := &Counter{t: rtpm, handle: tpm2.TPMHandle(0x01500099)}
	if _, err := c.Increment(); !errors.Is(err, ErrCounterNotProvisioned) {
		t.Fatalf("err = %v, want ErrCounterNotProvisioned", err)
	}
}

func TestCounter_Increment_PreReadGenericFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if err := ProvisionCounter(rtpm, testCounterHandle); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	c := &Counter{t: &alwaysFailCommand{inner: rtpm, failCommand: cc(tpm2.TPMCCNVReadPublic)}, handle: testCounterHandle}
	if _, err := c.Increment(); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("err = %v, want ErrTPMCommand", err)
	}
}
