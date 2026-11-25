package tpm

import "errors"

var (
	// ErrTPMCommand wraps any failure executing a TPM 2.0 command (the
	// underlying error from the go-tpm library, which itself wraps the
	// TPM's own TPM_RC response code where applicable).
	ErrTPMCommand = errors.New("tpm: command failed")

	// ErrUnsealFailed is returned by KeySealer.Unseal when the TPM is
	// reachable but the seal/load/unseal sequence itself failed (e.g.
	// the sealed blob does not load under the SRK recreated from
	// SRKTemplate, or TPM2_Unseal is refused). This is deliberately
	// distinct from a store-level ErrTampered: it means "TPM or seal
	// problem," not "store contents altered," so an operator can tell
	// the two apart, even though internal/store/internal/agent still
	// treat either as fail-closed, TAMPERED-equivalent behavior
	// (docs/prompts/step-05a.md C2).
	ErrUnsealFailed = errors.New("tpm: unseal failed")

	// ErrSealedBlobMissing is returned when KeySealer.Unseal is called
	// against a store directory with no sealed-key blob file at all
	// (distinct from ErrUnsealFailed: this is "never provisioned," not
	// "provisioned but broken").
	ErrSealedBlobMissing = errors.New("tpm: sealed key blob not found")

	// ErrNVIndexAttributeMismatch is returned by ProvisionCounter or
	// OpenCounter when an NV index already exists at the project's fixed
	// counter handle but its attributes (type, hierarchy, access
	// controls) do not match what this package defines -- a collision
	// with something else using that handle, or evidence of tampering
	// with the index itself. This package never adopts or reuses an
	// index it did not define with the expected attributes.
	ErrNVIndexAttributeMismatch = errors.New("tpm: NV index exists with unexpected attributes")

	// ErrCounterNotProvisioned is returned by OpenCounter when no NV
	// index exists at the project's fixed counter handle at all.
	// Provisioning (TPM2_NV_DefineSpace) is relay-probe's job, run with
	// owner authorization before relayd ever starts (docs/prompts/step-05a.md
	// C3); relayd itself only reads and increments, and must fail
	// closed, never silently define the index itself, if provisioning
	// was skipped.
	ErrCounterNotProvisioned = errors.New("tpm: counter NV index not provisioned")

	// ErrNoSupportedSigningCurve is returned when the TPM supports
	// neither ECC P-384 nor ECC P-256 for a signing key (TestParms
	// reports both unavailable). This project never falls back to a
	// software key (docs/prompts/step-05a.md C4).
	ErrNoSupportedSigningCurve = errors.New("tpm: no supported signing curve (P-384 or P-256) available")
)
