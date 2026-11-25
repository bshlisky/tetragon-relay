// Package tpm implements the host TPM 2.0 primitives docs/prompts/step-05a.md
// Part C requires: the store's sealed HMAC key (store.KeySealer), the
// rollback-protection monotonic counter (store.MonotonicCounter), and a
// non-exportable host signing key (crypto.Signer) for the mTLS client built
// in a later step.
//
// This package talks to a TPM 2.0 implementation through
// github.com/google/go-tpm/tpm2 (the "TPMDirect" API; see
// docs/decisions/0027-tpm-library-and-software-tpm.md) over a
// transport.TPM: in production, the kernel resource manager device
// (/dev/tpmrm0, architecture doc section 8.6 -- never /dev/tpm0 directly),
// opened via OpenDevice; in tests, a software TPM (swtpm) dialed over TCP,
// which speaks the identical TPM 2.0 command/response wire format, so the
// exact same command-building code in this package runs against both.
//
// Security responsibility: this package is the only place private key
// material (the store HMAC key, the host identity signing key) ever
// exists outside the TPM for the HMAC key's case (a KeySealer is a sealing,
// not an identity, primitive -- the unsealed bytes necessarily live in
// process memory while in use) and never for the signing key, which is
// created with fixedTPM so its private key handle can never leave the TPM
// at all. The HMAC key is zeroed from memory after use wherever Go allows
// (internal/tpm/seal.go); the signing key's private part is never read out
// of the TPM in the first place.
package tpm
