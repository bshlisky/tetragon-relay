package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SRKTemplate is this project's fixed, documented Storage Root Key
// template (docs/decisions/0027-tpm-library-and-software-tpm.md): an ECC
// P-256 restricted decryption primary key under the owner hierarchy,
// following the TCG "EK Credential Profile" family's SRK template shape.
// ECC P-256 (not P-384) is used here deliberately: this key only ever
// wraps Create's sensitive-area encryption, never signs or is used
// off-TPM, so FIPS 186-4/5 curve strength requirements that apply to this
// project's actual signatures (architecture doc 5.1: ECDSA P-384) do not
// apply to it, and P-256 is the template every TPM 2.0 implementation
// (including software ones) is guaranteed to support (TCG PC Client
// Platform TPM Profile mandates P-256 support; P-384 support is optional).
//
// Because SensitiveDataOrigin is set and the template is fixed, every
// TPM2_CreatePrimary call against this exact template under the owner
// hierarchy derives the SAME key deterministically from the hierarchy's
// primary seed (TCG TPM library spec Part 1, "Primary Object Creation"):
// no persistent handle, and no provisioning step, is needed. CreateSRK
// recreates it fresh on every call.
var SRKTemplate = tpm2.New2B(tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		Restricted:          true,
		Decrypt:             true,
		NoDA:                true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Symmetric: tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgAES,
			KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
			Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
	Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
	}),
})

// CreateSRK creates this project's Storage Root Key from SRKTemplate under
// the owner hierarchy with an empty (null) authorization -- there is no
// separate "owner password" in this design, matching how the TPM is used
// everywhere else in this project (the NV counter's owner-hierarchy
// authorization, Part C3, is likewise empty; the access boundary between
// relayd and relay-probe is enforced at the OS/systemd layer, architecture
// doc section 8.7, not by a TPM hierarchy secret). The returned handle is
// transient; callers must FlushSRK it when done.
func CreateSRK(t transport.TPM) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	cmd := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: SRKTemplate}
	rsp, err := cmd.Execute(t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("%w: create SRK: %w", ErrTPMCommand, err)
	}
	return rsp.ObjectHandle, rsp.Name, nil
}

// FlushSRK flushes a transient SRK handle returned by CreateSRK. Errors are
// returned, not swallowed, so a caller can audit a leaked handle, but a
// flush failure never changes whether the operation that used the SRK
// itself succeeded (handled by each caller, matching the "errors handled
// but not every line needs try/catch" style elsewhere in this project).
func FlushSRK(t transport.TPM, h tpm2.TPMHandle) error {
	cmd := tpm2.FlushContext{FlushHandle: h}
	if _, err := cmd.Execute(t); err != nil {
		return fmt.Errorf("%w: flush SRK: %w", ErrTPMCommand, err)
	}
	return nil
}
