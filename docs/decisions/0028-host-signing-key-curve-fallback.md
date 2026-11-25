# ADR 0028: Host signing key curve -- ECC P-384 preferred, P-256 fallback

## Status

Accepted.

## Context

Architecture doc section 5.1 fixes the identity PKI's certificate profile at ECDSA P-384
(FIPS 186-4/5 approved) for every SPIFFE identity in this system, hosts included. `docs/
prompts/step-05a.md` Part C4 requires the host's TPM-backed mTLS signing key to detect
whether the TPM supports P-384 at all (not every TPM 2.0 implementation does — P-384 is an
optional algorithm under the TCG PC Client Platform TPM Profile, unlike P-256, which is
mandatory), and asks: if the TPM lacks P-384, fall back to P-256 and record that fact in
host facts, "documented in an ADR," rather than silently either failing to enroll the host at
all or falling back to a software key.

## Decision

`internal/tpm.HostSigner` detects curve support with `TPM2_TestParms` (`detectSigningCurve`,
`signer.go`) against an ECDSA scheme on each curve, in this fixed preference order:

1. **ECC P-384** (`internal/tpm.CurveP384`), the architecture-mandated curve (5.1), used
   whenever the TPM reports support for it.
2. **ECC P-256** (`internal/tpm.CurveP256`), used only if P-384 is unavailable.
3. **Neither available**: `ErrNoSupportedSigningCurve`. The host does not enroll with a
   software-backed key under any circumstance — architecture doc P4 ("hardware-bound
   credentials... private key non-exportable in the TPM") is a property of the TLS client
   identity, not an optional hardening layer, so a TPM that can sign with neither curve
   simply cannot run this agent in production; this is a hard stop, reported up through
   `internal/agent`'s startup sequence (Part C5), not a silently degraded mode.

**Why P-256 is an acceptable fallback specifically here, and not elsewhere in this project**:
TLS client authentication is re-negotiated on every connection within the SVID's own TTL
(architecture doc 5.1: host SVID TTL 4h, renewed at 50%) — it is a real-time, continuously
re-verified property, not a long-lived artifact like a signed policy bundle or a trust-root
rotation. A P-256 signature is still FIPS 186-4/5 approved and still backed by a non-
exportable TPM key; the only difference from the architecture's stated preference is curve
strength margin, which matters far more for an artifact whose validity is relied upon for
months (trust-root metadata, 365-day validity, architecture doc 7.6) than for a credential
re-verified every few hours. This is why `internal/trust`'s production roles still require
`ecdsa-p384` only (step 4 prompt Part B5) and are NOT affected by this ADR: policy-signing
and trust-root keys are held by the signer/HSM and the management-plane PKI, never by a
host's TPM, and this ADR changes nothing about them.

**Recording the fallback**: `HostSigner.Curve()` returns which curve is actually in use
("P-384" or "P-256"); the caller (a future `internal/hostprobe`/`Hello` facts extension,
step 5b, since SPIRE/SVID wiring itself is out of scope for this step) is responsible for
including it in host facts, so an operator can see which hosts are running on TPMs without
P-384 support and plan hardware refreshes accordingly. This step (5a) only builds the
primitive and the detection; wiring it into `Hello` facts is explicitly step 5b's job
(the mTLS client itself).

**Never falls back further.** If a future TPM generation drops P-256 support entirely
(unlikely; it is the TCG-mandated minimum), this package does not add a third fallback tier
or a software-key path: `ErrNoSupportedSigningCurve` is permanent until the host's TPM is
replaced or a future ADR revisits this decision.

## Consequences

- `internal/tpm.HostSigner`'s on-disk blob (`hostSignerBlobFile`) records which curve was
  used (`Curve` field) alongside the TPM2B_PUBLIC/TPM2B_PRIVATE pair, so a later `Load` does
  not need to re-run curve detection or guess which curve the stored public point is on.
- `RotateHostSigner` re-runs curve detection on every rotation (not just first boot): a TPM
  firmware update between rotations could in principle change which curves are reported
  supported, and a rotation should reflect the TPM's current capabilities, not whatever was
  detected at first enrollment.
- No change to `internal/trust`'s crypto-agility model (ADR 0022) or to any trust-root role's
  `require_keytypes`: this ADR is scoped entirely to the host's OWN TLS client identity key,
  never to policy-signing or trust-root keys.
