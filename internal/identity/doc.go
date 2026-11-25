// Package identity implements docs/prompts/step-05b.md Part B: the host's
// SPIFFE identity, built against an Enroller interface rather than a
// concrete enrollment system (SPIRE with TPM attestation or IdM/FreeIPA
// with certmonger, architecture doc section 5.2/5.3, are both explicitly
// out of scope for this step -- see docs/decisions/0023-reenrollment-
// interface.md for this project's established pattern of building an
// interface and its tests ahead of the component that implements it for
// real).
//
// CertManager (certmanager.go) builds a CSR from a crypto.Signer (in
// production, a *tpm.HostSigner, architecture doc section 5.1: ECDSA
// P-384, non-exportable), exchanges it for a certificate chain through an
// Enroller, and validates every property of the returned chain itself --
// it never trusts an Enroller's own judgment about whether a chain is
// well-formed. See docs/decisions/0030-enroller-must-certify-tpm-held-
// key.md for why the Enroller interface itself (CSR in, chain out, never
// a private key) is a security boundary, not just an API shape.
//
// TestCA (testca.go, build tag testca) is a small in-process certificate
// authority used only by this package's own tests and
// internal/controlclient's integration tests; it is never compiled into
// a production build.
package identity
