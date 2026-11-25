# Architect review: step 5a (origin/main @ 94ab501)

Reviewer: architect · Date: 2026-11-25 · Verdict: **Step 5a accepted**, with one design
follow-up (R5A-1) and one documentation follow-up (R5A-2), both carried into step 5b as
Part A. ADRs 0026–0028 are Accepted. R4C-1 and R4C-2 are closed.

Review method: code reading, plus Devin's ci and integration runs on 94ab501, which include
a CI job running internal/tpm against swtpm.

## Verified by reading

- R4C-1: a missing raw envelope or root version is tamper. R4C-2: `ProvenanceVerifier`
  ignores only metadata expiry, and an AST test pins its single call site.
- Sealing (ADR 0026): TPM-bound, no PCR policy, with the reasoning recorded.
- Host signing key: fixedTPM, fixedParent, sensitiveDataOrigin, sign-only, unrestricted
  ECDSA. Non-exportability is proven by `TPM2_Duplicate` failing. `Sign` rejects digests
  whose size differs from the curve's coordinate size, and the hash follows the curve
  (SHA-384 for P-384, SHA-256 for P-256), matching TLS 1.3's ECDSA schemes.
- NV counter: fixed attributes are checked on every open (collision or tampering is a
  refusal). `TestCounter_DeleteAndRedefineNeverGoesBackward` passes on swtpm. Deletion
  and redefinition make the counter jump AHEAD of the store generation, which the store
  treats as tamper: a fail-closed denial of service, never a rollback.
- No capabilities; TPM access only through `/dev/tpmrm0` (`DeviceAllow`, group `tss`);
  provisioning only in root `ExecStartPre=+`.

## R5A-1 [MEDIUM] relayd depends on TPM owner authorization at runtime

The counter index is `OwnerWrite`/`OwnerRead`, and the SRK is recreated under the owner
hierarchy on every open. relayd can therefore only increment the counter, read it and
unseal the store key if the TPM owner authorization is empty. Consequences:

1. **Fleet breakage:** any host whose TPM has an owner password set (common in enterprise
   provisioning standards) cannot commit store changes or unseal at all, so the agent
   never accepts a bundle.
2. **Excess authority:** an unprivileged daemon routinely exercising owner-hierarchy
   authorization runs against the least-privilege design. relayd should hold exactly the
   authority it uses.

Required (write the ADR first as Proposed; stop and ask if anything conflicts):
- Provisioning (root `relay-probe --provision-tpm`, using owner authorization once,
  read from a root-only file when set; document the operator procedure):
  - Create the SRK as a persistent object at a fixed documented handle (use the TCG
    standard SRK handle 0x81000001 only if an existing object there has exactly the
    expected template; otherwise use a project-owned persistent handle and document it).
  - Define the NV counter with `AuthWrite` and `AuthRead` and an index authValue (empty
    or a fixed documented value, explaining why the choice does not matter for the
    threat model: rollback is prevented by monotonicity, not secrecy), with no
    `OwnerWrite`/`OwnerRead`.
- relayd: loads the persistent SRK and uses the counter index's own authorization. It
  never uses owner-hierarchy authorization.
- Tests (swtpm): with an owner password set after provisioning, relayd still seals,
  unseals, reads and increments; provisioning with the password from the file succeeds;
  provisioning without it fails with a clear error.

## R5A-2 [LOW] Cite the TPM specification, not a book

The counter-monotonicity citation in step-05a.md §12 is a secondary source. Replace it with
the TCG TPM 2.0 Library Specification section that defines NV counter initialization
(Part 1, NV counter semantics), with version and section number. If the exact text cannot
be confirmed, say so. The swtpm test result stands; real-hardware confirmation comes from
the e2e-rhel9.sh TPM section on the customer's test server.

## Customer action (not blocking)

Run `scripts/e2e-rhel9.sh` (including its TPM section) on the RHEL 9 test server when it
is available, and send back the TPM manufacturer, firmware version and supported ECC
curves.
