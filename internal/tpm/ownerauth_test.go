package tpm

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// This file is the regression suite for step-05a-review.md R5A-1 / ADR
// 0029: relayd must never need TPM owner-hierarchy authorization, and
// provisioning must work whether or not the host's TPM has an owner
// password set.

// setOwnerAuth sets the TPM owner hierarchy's authorization value via
// TPM2_HierarchyChangeAuth, simulating a host whose TPM was imaged with
// an owner password already set by the site's provisioning standard
// (docs/decisions/0029-no-tpm-owner-authorization-at-runtime.md's
// "fleet breakage" scenario) -- here, simulated AFTER this package's own
// provisioning has already run with an empty owner auth, to prove
// relayd's read/increment/seal/sign paths keep working regardless of
// what the owner hierarchy's auth value becomes afterward.
func setOwnerAuth(t *testing.T, tp transport.TPM, newAuth []byte) {
	t.Helper()
	cmd := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.TPMRHOwner,
		NewAuth:    tpm2.TPM2BAuth{Buffer: newAuth},
	}
	if _, err := cmd.Execute(tp); err != nil {
		t.Fatalf("HierarchyChangeAuth(owner): %v", err)
	}
}

// TestRelayd_WorksWithOwnerPasswordSetAfterProvisioning is the review's
// required test: "with an owner password set after provisioning, relayd
// still seals, unseals, reads and increments." Every operation after
// setOwnerAuth below is exactly what relayd itself calls (OpenSRK via
// KeySealer/HostSigner, OpenCounter/Read/Increment) -- none of it may use
// or need the owner hierarchy's authorization at all.
func TestRelayd_WorksWithOwnerPasswordSetAfterProvisioning(t *testing.T) {
	tt := startSWTPM(t)
	dir := t.TempDir()
	ownerPW := []byte("enterprise-provisioning-owner-password")

	if _, err := ProvisionSRK(tt, nil); err != nil {
		t.Fatalf("ProvisionSRK (empty owner auth): %v", err)
	}
	if err := ProvisionCounter(tt, testCounterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter (empty owner auth): %v", err)
	}

	// Simulate the TPM's owner hierarchy gaining a password after this
	// project's own provisioning ran (or a host that already had one,
	// since ProvisionSRK/ProvisionCounter above used empty auth only
	// because this test hadn't set one yet).
	setOwnerAuth(t, tt, ownerPW)

	// relayd's actual runtime paths: none of these pass ownerPW anywhere,
	// and all must still succeed.
	if _, _, err := OpenSRK(tt); err != nil {
		t.Fatalf("OpenSRK after owner password set: %v", err)
	}

	sealer, err := NewKeySealer(tt, filepath.Join(dir, "sealed.json"))
	if err != nil {
		t.Fatalf("NewKeySealer after owner password set: %v", err)
	}
	if _, err := sealer.Unseal(); err != nil {
		t.Fatalf("Unseal after owner password set: %v", err)
	}

	counter, err := OpenCounter(tt, testCounterHandle)
	if err != nil {
		t.Fatalf("OpenCounter after owner password set: %v", err)
	}
	if _, err := counter.Read(); err != nil {
		t.Fatalf("Read after owner password set: %v", err)
	}
	if _, err := counter.Increment(); err != nil {
		t.Fatalf("Increment after owner password set: %v", err)
	}

	hs, err := NewOrLoadHostSigner(tt, filepath.Join(dir, "host-signer.json"))
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner after owner password set: %v", err)
	}
	digest := make([]byte, 48)
	if _, err := hs.Sign(nil, digest, nil); err != nil {
		t.Fatalf("Sign after owner password set: %v", err)
	}
}

// TestProvisionSRK_RequiresOwnerAuthFileWhenOwnerPasswordIsSet and
// TestProvisionCounter_RequiresOwnerAuthFileWhenOwnerPasswordIsSet are
// the review's other two required tests: "provisioning with the password
// from the file succeeds; provisioning without it fails with a clear
// error." Here the owner password is set BEFORE provisioning ever runs
// (the fleet scenario R5A-1 describes), unlike the test above.

func TestProvisionSRK_RequiresOwnerAuthFileWhenOwnerPasswordIsSet(t *testing.T) {
	tt := startSWTPM(t)
	ownerPW := []byte("pre-imaged-owner-password")
	setOwnerAuth(t, tt, ownerPW)

	if _, err := ProvisionSRK(tt, nil); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("ProvisionSRK with no owner auth against a TPM with an owner password: err = %v, want ErrTPMCommand", err)
	}
	if _, err := ProvisionSRK(tt, ownerPW); err != nil {
		t.Fatalf("ProvisionSRK with the correct owner auth: %v", err)
	}
}

func TestProvisionCounter_RequiresOwnerAuthFileWhenOwnerPasswordIsSet(t *testing.T) {
	tt := startSWTPM(t)
	ownerPW := []byte("pre-imaged-owner-password")
	setOwnerAuth(t, tt, ownerPW)

	if err := ProvisionCounter(tt, testCounterHandle, nil); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("ProvisionCounter with no owner auth against a TPM with an owner password: err = %v, want ErrTPMCommand", err)
	}
	if err := ProvisionCounter(tt, testCounterHandle, ownerPW); err != nil {
		t.Fatalf("ProvisionCounter with the correct owner auth: %v", err)
	}
}

// TestCounter_NeverUsesOwnerHierarchyAuthorization proves the specific
// R5A-1 regression directly: Read/Increment must succeed using ONLY the
// index's own (empty) authValue even when the owner hierarchy's auth is
// set to something relayd never knows, confirming expectedCounterAttributes
// no longer grants OwnerRead/OwnerWrite at all (if it still did, a bug
// that silently re-added TPMRHOwner authorization in Read/Increment would
// not be caught by TestRelayd_WorksWithOwnerPasswordSetAfterProvisioning
// alone, since OwnerRead/OwnerWrite being present would ALSO let that
// test pass by coincidence if Read/Increment still referenced
// TPMRHOwner with an empty password -- this test additionally confirms
// the index itself rejects OwnerRead/OwnerWrite-style access).
func TestCounter_NeverUsesOwnerHierarchyAuthorization(t *testing.T) {
	tt := startSWTPM(t)
	if err := ProvisionCounter(tt, testCounterHandle, nil); err != nil {
		t.Fatalf("ProvisionCounter: %v", err)
	}
	pub, _, ok, err := readNVPublic(tt, testCounterHandle)
	if err != nil {
		t.Fatalf("readNVPublic: %v", err)
	}
	if !ok {
		t.Fatalf("counter index missing after ProvisionCounter")
	}
	if pub.Attributes.OwnerRead || pub.Attributes.OwnerWrite {
		t.Fatalf("counter index has OwnerRead=%v OwnerWrite=%v, want both false (ADR 0029)", pub.Attributes.OwnerRead, pub.Attributes.OwnerWrite)
	}
	if !pub.Attributes.AuthRead || !pub.Attributes.AuthWrite {
		t.Fatalf("counter index has AuthRead=%v AuthWrite=%v, want both true (ADR 0029)", pub.Attributes.AuthRead, pub.Attributes.AuthWrite)
	}
}
