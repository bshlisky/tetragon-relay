# tetragon-relay — new session: Step 5a (TPM primitives: sealed key, monotonic counter, host signing key)

You are continuing an existing, security-critical project for an enterprise customer.
You have no memory of earlier sessions; the repository is the source of truth.

Repo: https://github.com/bshlisky/tetragon-relay (branch main). Clone it fresh.

## Binding context
- The working agreement, environment rules and "Read these before writing any code" list
  in docs/prompts/step-04b.md (Part 0) apply unchanged, including the session-size rule.
- Read docs/architecture.md sections 5 (identity and PKI), 8.2, 8.4, 8.6 and 8.10;
  docs/reports/step-04c.md; ADRs 0023–0025; and the attached review.
- Current state: steps 1–4 are accepted at 742bfa3. internal/store uses two fake
  interfaces that this step makes real: `KeySealer` (HMAC key) and `MonotonicCounter`
  (rollback protection).
- Step 5 is split. 5a (this session) covers the TPM primitives. 5b (a later session)
  covers SPIRE node attestation, X.509-SVID enrollment and the mTLS client.

## First actions
1. Two files are ATTACHED: this prompt and step-04c-review.md. Commit them verbatim in one
   commit ("docs: add step 4c review and step 5a prompt"):
   - docs/reviews/step-04c-review.md
   - docs/prompts/step-05a.md
2. Run `make ci` from a clean clone; confirm green.
3. Acknowledge with ≤ 12 bullets, including which TPM implementation you will use in CI
   and why (see C1).

## Part A — Step 4c review follow-ups (first; one commit each; regression tests)
A1. R4C-1: an LKG without a raw envelope (or with RootVersion 0) is tamper; remove the
    "pre-R4B-2" branch.
A2. R4C-2: add a provenance verifier that checks signatures regardless of root metadata
    expiry; reverifyDomainLKG uses it; expiry no longer skips the signature check.
A3. Update ADR 0025 to Accepted, with the R4C amendments. Mark ADR 0024 Accepted.

## Part B — Architect decision on sealing (record in an ADR as Accepted)
Architecture 8.10 says the store HMAC key is sealed to the TPM "under PCR 7 policy". That
decision is revised:
- Seal the HMAC key to this host's TPM (an object under the Storage Root Key) WITHOUT a
  PCR policy.
- Reason: PCR 7 measures the Secure Boot policy, not the booted OS. A vendor-signed rescue
  image boots with the same PCR 7, so the binding does not stop the offline-edit attack it
  was meant for. Meanwhile, routine Secure Boot database updates (dbx revocations) change
  PCR 7 and would make every host's store permanently unreadable, forcing fleet-wide
  re-enrollment.
- What sealing still provides: the HMAC key cannot be used off this TPM (a copied disk
  image is useless). Rollback is prevented by the TPM NV counter (Part C3), which is the
  real defense. A root attacker on the running host is out of scope for sealing, as
  everywhere else in this design (T-02, T-04).
- Write ADR "Store key sealing without PCR policy" (Accepted), referencing 8.10 and this
  reasoning. Do not edit docs/architecture.md; the ADR supersedes 8.10's PCR clause.

## Part C — TPM primitives (new package internal/tpm)
C1. TPM access and test environment
    - Library: github.com/google/go-tpm (the tpm2 package), vendored, with an ADR.
      Anything else needs an ADR with reasons.
    - Device: /dev/tpmrm0 only (the kernel resource manager), never /dev/tpm0. relayd
      reaches it through `SupplementaryGroups=tss` and `DeviceAllow=/dev/tpmrm0 rw`, as
      architecture 8.6 already specifies. Update the unit only if it does not already
      match 8.6, and update the R3-3 unit-file test to match 8.6 exactly. No capabilities.
    - Tests must run against a real TPM 2.0 implementation in CI: a software TPM
      (swtpm, or the go-tpm-tools simulator if you justify the cgo trade-off). Choose one,
      explain it in an ADR, and run the TPM test suite in GitHub Actions. Unit tests use an
      interface, but at least one CI job must exercise the real TPM command flows.
C2. KeySealer (implements store.KeySealer)
    - First boot: generate a 48-byte HMAC key with crypto/rand. Seal it under an SRK
      created from a fixed, documented ECC template (owner hierarchy, recreated
      deterministically; no persistent handle). Store the sealed blob (TPM2B_PUBLIC plus
      TPM2B_PRIVATE) in the store directory; it is not secret.
    - Unseal on every open. Unseal failure is distinct from tamper: a typed
      ErrUnsealFailed, so the agent enters TAMPERED-equivalent fail-closed behavior but
      operators can tell "TPM or seal problem" apart from "store contents altered".
    - Zero the key from memory after use where Go allows, and keep it in one place only.
C3. MonotonicCounter (implements store.MonotonicCounter)
    - A TPM NV counter index (TPMA_NV_COUNTER), in the owner range, at a fixed documented
      handle. Detect and refuse a pre-existing index at that handle with unexpected
      attributes (collision or tampering).
    - Provisioning (defining the index) requires owner authorization, so it is done by the
      root-run relay-probe (`relay-probe --provision-tpm`, called from the unit's
      ExecStartPre=+ only when the index is absent). relayd only reads and increments.
    - Cite the TPM 2.0 specification on what happens when a counter index is deleted and
      redefined (counter initialization behavior), and test that deleting and redefining
      the index never lets the counter go backwards relative to the store's generation.
      If the spec does not guarantee this, stop and report.
C4. Host signing key (a crypto.Signer backed by the TPM, for the mTLS client in step 5b)
    - Non-exportable signing key (fixedTPM, fixedParent, sensitiveDataOrigin, sign only),
      ECC P-384 if the TPM supports it. Detect support and record it in host facts.
    - If the TPM lacks P-384, use P-256 and record that in host facts (TLS client
      authentication is real-time, so P-256 is acceptable here; document it in an ADR).
      Never fall back to a software key.
    - Rotation primitive: create a new key, keep the old one until told to retire it.
      SPIRE wiring is step 5b.
    - Unit and swtpm tests: sign and verify; the key cannot be exported (attempting
      duplication fails); the attributes are as specified.
C5. Wiring: agent startup (internal/agent) uses the real KeySealer and MonotonicCounter
    when the TPM is present. When it is absent, the agent refuses to start in production
    mode. A test-only build tag may keep the fakes; there must be no runtime flag that
    selects them.

## Part D — Tests and evidence
D1. CI: a TPM job (or a step in integration) runs internal/tpm against the chosen
    software TPM, plus a store round-trip that uses the real sealer and counter across
    a simulated restart.
D2. Fault tests: TPM unavailable at open; unseal fails; counter read fails; counter index
    with wrong attributes; counter behind the store generation (rollback); counter
    ahead by more than 1.
D3. scripts/e2e-rhel9.sh gains a TPM section (real TPM or vTPM on the customer's test
    server) that prints TPM manufacturer, firmware version, supported ECC curves, and runs
    the D1 round-trip. CI does not run it; the report says whether it was run.
D4. Coverage ≥ 90% for internal/tpm (paths that only run against a real TPM in CI may be
    excluded via build tag; state how much).

## Out of scope
SPIRE, SVIDs, the mTLS client and controller connection (5b); TPM-based remote attestation
(PCR quotes) (5b or later); PQC (see ADR 0022's "not yet agile" list).

## Definition of done
ci and integration (plus the TPM job) green on GitHub for the final commit.

## Report: docs/reports/step-05a.md (also paste it in your final message)
Sections 1–10 as in previous steps, plus:
11. The TPM implementation used in CI and the TPM facts it reported.
12. The NV-counter deletion/redefinition citation and test result (C3).
13. Whether e2e-rhel9.sh's TPM section was run, and on what hardware.
