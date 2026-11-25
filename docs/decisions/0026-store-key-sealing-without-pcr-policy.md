# ADR 0026: Store key sealing without a PCR policy

## Status

Accepted.

## Context

Architecture doc section 8.11 ("Self-protection and tamper evidence") states: "Store files
are HMAC'd with a key sealed to the TPM under PCR 7 policy, so offline edits (e.g. from
rescue media) are detected at next start." `docs/prompts/step-04b.md` Part C4 already
anticipated this, describing `KeySealer`'s eventual real implementation as "a TPM-sealed key
bound to PCR 7 in step 5."

This step (5a) is the first one that actually builds the TPM-backed `KeySealer`, which
requires deciding exactly what the HMAC key is sealed to. On investigation, binding to PCR 7
specifically does not achieve what the architecture doc's own sentence claims:

- **PCR 7 measures the Secure Boot *policy* (the UEFI Secure Boot state: enabled/disabled,
  and the hash of the enrolled key databases — PK, KEK, db, dbx), not which OS or kernel
  booted.** A vendor-signed rescue image (e.g. the distribution's own installer/rescue ISO,
  or a RHEL 9 rescue environment on signed shim/grub) boots with Secure Boot enabled and the
  same key databases as the production host, so it produces the **same PCR 7 value** as a
  normal boot. The specific "offline edits from rescue media" attack the architecture doc's
  sentence names is therefore not stopped by a PCR 7 policy at all: an attacker who can boot
  rescue media that chains to the same Secure Boot key databases unseals the key exactly as
  normal production boot would.
- **Routine Secure Boot database maintenance changes PCR 7 by design.** `dbx` (the UEFI
  revocation database) is updated by RHEL's own `fwupd`/`mokutil` tooling to revoke
  compromised bootloaders and shims (e.g. the BootHole-class advisories), and these updates
  are expected, routine, host-security-positive events, not compromise indicators. Each one
  changes PCR 7. A PCR-7-sealed key would become permanently unreadable on every host the
  moment it applies a normal `dbx` update, turning a routine security patch into a
  fleet-wide "every host's local HMAC key is gone, every store looks tampered" incident, with
  no in-band way to recover (TAMPERED state intentionally has no auto-heal; `internal/store`
  C6, ADR 0023's `Reenroller` is the only path out, and a `dbx` rollout across a whole fleet
  on the same day would trigger it on every host simultaneously).

In short, PCR 7 binding fails open against the threat it was meant to stop (a vendor-signed
rescue boot) and fails closed against routine, desirable maintenance (a `dbx` update) —
exactly backwards from what a PCR policy should do.

## Decision

Seal the store's HMAC key to this host's TPM as a plain object under the Storage Root Key
(SRK), with **no PCR policy at all** (an unrestricted `TPM2_Unseal`-able object, gated only
by TPM object hierarchy/auth, not `TPM2_PolicyPCR`).

- **What this still provides.** The key is non-exportable from this specific TPM: a copied
  disk/VM image, or the sealed blob alone, is useless on any other TPM (the SRK a sealed
  object is created under is deterministic per-TPM but not extractable — see `internal/tpm`'s
  C2, this step). This is the property architecture doc 8.2's `store` module actually
  depends on today: "files HMAC'd with a key sealed to the TPM" protects against offline
  tampering by copying the store elsewhere, forging an HMAC with a stolen/guessed key, and
  copying it back — not against an attacker with arbitrary code execution on the live,
  booted host (out of scope everywhere else in this design; see below).
- **What actually prevents rollback/offline-edit attacks.** The TPM NV monotonic counter
  (architecture doc 8.2's `store` module, `internal/store` C5, implemented for real in this
  step's Part C3) is the actual defense against an attacker restoring an older, valid
  (HMAC-correct, signature-correct) copy of the store: the counter cannot be rewound without
  TPM owner authorization, and a generation behind the counter's recorded value is
  `ErrTampered` regardless of whether the HMAC key used to seal/unseal is PCR-bound to
  anything. Sealing without a PCR policy does not weaken this: the counter's protection is
  independent of the sealing object's policy.
- **Root-on-the-running-host is out of scope for sealing, as everywhere else in this
  design.** Threat model T-02/T-04 (architecture doc section 4.2, ADV2: "attacker with root
  on one host") already assumes a rooted host can read any process's memory, including an
  unsealed HMAC key while the agent holds it, and that containment for that case is the
  N9300 DPU (P6: "assume the host can be rooted... containment enforced by the DPU, not by
  the host"), not anything `internal/store`'s key sealing does. A PCR policy that only
  constrains *which boot state* may unseal the key would not change this: once booted into
  that same state, root can still read the key from agent memory. Sealing without a PCR
  policy loses nothing against this adversary that a PCR-7 policy would have provided.
- **This ADR supersedes architecture doc section 8.11's PCR 7 clause.** The architecture
  document itself is not edited (per this project's working agreement: architecture changes
  are proposed in an ADR, not by silently rewriting the source of truth); this ADR is the
  authoritative statement of the sealing design going forward. A future ADR would be needed
  to reintroduce any PCR policy, and should name a specific PCR set and golden-value
  management story that survives routine `dbx`/firmware updates before doing so (e.g.
  PCR 0/2/4 kernel-and-initrd measurement with a documented re-sealing procedure on every
  signed kernel update, which this ADR does not attempt to design, since it is not needed
  for the property this project actually relies on).

## Consequences

- `internal/tpm`'s `KeySealer` implementation (Part C2, this step) creates the SRK from a
  fixed, documented ECC template (no persistent handle; recreated deterministically on every
  open) and seals the HMAC key under it with an empty authorization policy — no
  `TPM2_PolicyPCR`, no `TPM2_StartAuthSession` of a policy session tied to PCR values.
- No change to `internal/store`'s HMAC verification logic, its `ErrTampered` paths, or the
  `MonotonicCounter` interface/contract (ADR unaffected): this ADR is scoped entirely to what
  the sealing *object*'s authorization policy is, not to how the sealed key is used once
  unsealed.
- Host firmware/Secure Boot database maintenance (`dbx` updates, firmware updates) no longer
  has any effect on whether a host's store can be opened after the update — eliminating the
  fleet-wide-TAMPERED-after-routine-maintenance failure mode described in Context.
- The residual risk this ADR accepts (rooted host reads the key from agent memory; rescue
  media with the same Secure Boot chain can unseal it) is not new: it is the same residual
  risk the architecture document's own threat model (T-02/T-04, ADV2) already accepts for a
  rooted host, made explicit here rather than appearing to be mitigated by a PCR policy that
  does not actually mitigate it.
