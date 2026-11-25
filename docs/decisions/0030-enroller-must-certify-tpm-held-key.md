# ADR 0030: Every Enroller implementation must certify a TPM-held key from a CSR

## Status

Accepted.

## Context

`docs/prompts/step-05b.md` Part B1 defines the enrollment boundary this step builds against:

```go
type Enroller interface {
    // Enroll exchanges proof of identity plus a CSR signed by the TPM HostSigner
    // for a certificate chain. It never receives or generates a private key.
    Enroll(ctx context.Context, csr []byte) (chain []*x509.Certificate, err error)
}
```

The prompt requires recording, as a constraint that decides how SPIRE or IdM are integrated
later (both out of scope for this step; see architecture doc 5.2/5.3), that "any enrollment
design that would issue a software-generated private key (for example a stock SPIRE Workload
API SVID) is out of bounds."

The reason this matters now, before either real enroller exists: SPIRE's default workload
attestation flow (the SPIRE Workload API, `spiffe-helper`, and most off-the-shelf SPIRE
agent plugins) generates the SVID's private key in software inside the SPIRE agent process
and returns both the key and the signed certificate to the workload together. That flow is
exactly what architecture doc P4 ("hardware-bound credentials... private key non-exportable
in the TPM") and section 5.1/5.2 (an attested, TPM-resident TLS key, proven non-exportable by
the attestation sequence itself) forbid for this project's host identity: a software-generated
key defeats the entire point of TPM attestation, no matter how the certificate that wraps it
was issued.

## Decision

`Enroller.Enroll`'s signature is the enforcement mechanism, not just documentation: it takes
only a CSR (`[]byte`, already signed by the caller's own `crypto.Signer`) and returns only a
certificate chain. There is no code path through which an `Enroller` implementation can hand
back a private key, because the interface has no return value capable of carrying one. Any
future `Enroller` built against this interface is therefore structurally unable to replicate
the stock SPIRE Workload API's software-key flow: at most it can decline to certify the key
the CSR already proves possession of (standard CSR semantics: the CSR is itself signed by the
private key corresponding to the public key it carries, so a caller cannot submit a CSR for a
key it does not hold).

Consequences for later integration:

- **If step 5's recommended path (SPIRE with TPM node attestation, architecture 5.2) is built
  later**, it must NOT use the stock SPIRE Workload API to obtain the host's own SVID (that
  API is designed to hand a workload its private key). Instead, the TPM-held `HostSigner`
  must build its own CSR (as `internal/identity.CertManager` does in this step) and the SPIRE
  integration must use whatever SPIRE server-side mechanism accepts an externally-generated
  CSR/public key for a node SVID (e.g. SPIRE's upstream-authority / CA-signing path invoked
  directly, or a custom `NodeAttestor` plugin that forwards the CSR) rather than SPIRE's
  normal agent-generates-the-key flow. This is a real constraint on the SPIRE integration
  design, which this ADR records now so that decision is not made by accident later by
  whoever reaches for the obvious (but wrong, for this project) SPIRE API.
- **If the fallback path (IdM/FreeIPA with certmonger, architecture 5.3) is built instead**,
  certmonger already supports exactly this shape: it can request a certificate for a
  CSR built from an existing (here, TPM-resident) key via its PKCS#11 key-storage mode
  (architecture 5.3: "Private key stored via PKCS#11 on the TPM (`tpm2-pkcs11`) where
  available"), so no equivalent warning is needed there — this is noted for completeness,
  not because IdM/certmonger poses the same risk.
- `internal/identity.CertManager` (this step) is the only caller that ever constructs a CSR
  from the TPM `HostSigner`; no code path in this project ever asks an `Enroller` for a key.

## Consequences

- No test enforces this at compile time beyond the interface signature itself (Go's type
  system already makes "an `Enroller` that returns a private key" inexpressible without
  changing the interface, which would itself require a new ADR to justify).
- This ADR is a design constraint for a NOT-YET-BUILT component (the real SPIRE or IdM
  enroller); docs/decisions/0023-reenrollment-interface.md is the precedent for recording
  constraints on later steps' interfaces ahead of their implementation.
</content>
