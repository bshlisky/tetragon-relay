package tpm

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

const testCounterHandle = tpm2.TPMHandle(0x01500030)

func TestCounter_ProvisionOpenReadIncrement(t *testing.T) {
	tt := startSWTPM(t)

	if _, _, ok, err := readNVPublic(tt, testCounterHandle); err != nil {
		t.Fatalf("readNVPublic: %v", err)
	} else if ok {
		t.Fatalf("index unexpectedly already exists before provisioning")
	}

	if _, err := OpenCounter(tt, testCounterHandle); !errors.Is(err, ErrCounterNotProvisioned) {
		t.Fatalf("OpenCounter before provisioning: err = %v, want ErrCounterNotProvisioned", err)
	}

	if err := ProvisionCounter(tt, testCounterHandle); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	// Idempotent: provisioning an already-correct index is a no-op, not
	// an error.
	if err := ProvisionCounter(tt, testCounterHandle); err != nil {
		t.Fatalf("ProvisionCounter (second call): %v", err)
	}

	c, err := OpenCounter(tt, testCounterHandle)
	if err != nil {
		t.Fatalf("OpenCounter: %v", err)
	}

	// Factory value: never written, reads as 0 (matching
	// internal/store's firstBoot expectation), even though a raw
	// TPM2_NV_Read against an unwritten counter would itself fail.
	v, err := c.Read()
	if err != nil {
		t.Fatalf("Read (factory): %v", err)
	}
	if v != 0 {
		t.Fatalf("Read (factory) = %d, want 0", v)
	}

	v1, err := c.Increment()
	if err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if v1 == 0 {
		t.Fatalf("Increment returned 0, want a nonzero counter value")
	}
	v2, err := c.Read()
	if err != nil {
		t.Fatalf("Read after increment: %v", err)
	}
	if v2 != v1 {
		t.Fatalf("Read after Increment = %d, want %d", v2, v1)
	}
	v3, err := c.Increment()
	if err != nil {
		t.Fatalf("Increment (second): %v", err)
	}
	if v3 <= v2 {
		t.Fatalf("second Increment = %d, want > %d", v3, v2)
	}
}

func TestCounter_DeleteAndRedefineNeverGoesBackward(t *testing.T) {
	// TPM 2.0 spec NV counter semantics (cited in
	// docs/decisions/0027-tpm-library-and-software-tpm.md and
	// docs/reports/step-05a.md section 12): "An NV counter is a 64-bit
	// value that can only increment. At the beginning of the first
	// increment command, it's initialized to the largest value that any
	// counter has ever had on the TPM. This includes counter indexes
	// currently defined and counters that were defined in the past but
	// are no longer on the TPM. Thus a counter can never roll back, even
	// by deleting and re-creating the index." (Arthur, Challener,
	// Goldman, "A Practical Guide to TPM 2.0", ch. 11 "NV Indexes";
	// consistent with TCG TPM Library Spec Part 1, Architecture, NV
	// counter behavior). This test proves it against a real TPM 2.0
	// implementation, not just cites it.
	tt := startSWTPM(t)
	handle := testCounterHandle

	if err := ProvisionCounter(tt, handle); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	c, err := OpenCounter(tt, handle)
	if err != nil {
		t.Fatalf("OpenCounter: %v", err)
	}
	var last uint64
	for i := 0; i < 3; i++ {
		last, err = c.Increment()
		if err != nil {
			t.Fatalf("Increment: %v", err)
		}
	}

	// Undefine (requires owner authorization, same as define -- this
	// simulates relay-probe re-provisioning after some operational
	// event, e.g. a factory reset of ONLY this index, never the whole
	// TPM) and redefine.
	_, name, ok, err := readNVPublic(tt, handle)
	if err != nil {
		t.Fatalf("readNVPublic: %v", err)
	}
	if !ok {
		t.Fatalf("index missing before undefine")
	}
	undef := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex:    tpm2.NamedHandle{Handle: handle, Name: name},
	}
	if _, err := undef.Execute(tt); err != nil {
		t.Fatalf("NVUndefineSpace: %v", err)
	}
	if err := ProvisionCounter(tt, handle); err != nil {
		t.Fatalf("ProvisionCounter (redefine): %v", err)
	}
	c2, err := OpenCounter(tt, handle)
	if err != nil {
		t.Fatalf("OpenCounter (after redefine): %v", err)
	}
	next, err := c2.Increment()
	if err != nil {
		t.Fatalf("Increment (after redefine): %v", err)
	}
	if next <= last {
		t.Fatalf("ROLLBACK: counter after delete+redefine+increment = %d, want > %d (last value before delete)", next, last)
	}
}

func TestProvisionCounter_RefusesIndexWithWrongAttributes(t *testing.T) {
	tt := startSWTPM(t)
	handle := testCounterHandle

	// Define an index at the SAME handle, but as an ordinary (non-
	// counter) index -- simulating either a genuine handle collision
	// with something else, or an attacker's attempt to redefine the
	// counter index with weaker semantics.
	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B[tpm2.TPMSNVPublic](tpm2.TPMSNVPublic{
			NVIndex:    handle,
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, NT: tpm2.TPMNTOrdinary, NoDA: true},
			DataSize:   counterDataSize,
		}),
	}
	if _, err := def.Execute(tt); err != nil {
		t.Fatalf("NVDefineSpace (wrong type): %v", err)
	}

	if err := ProvisionCounter(tt, handle); !errors.Is(err, ErrNVIndexAttributeMismatch) {
		t.Fatalf("ProvisionCounter: err = %v, want ErrNVIndexAttributeMismatch", err)
	}
	if _, err := OpenCounter(tt, handle); !errors.Is(err, ErrNVIndexAttributeMismatch) {
		t.Fatalf("OpenCounter: err = %v, want ErrNVIndexAttributeMismatch", err)
	}
}
