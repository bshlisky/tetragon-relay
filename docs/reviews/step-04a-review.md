# Architect review: step 4a (origin/main @ e1a4bfb)

Reviewer: architect · Date: 2026-11-24 · Verdict: **Step 4a accepted.** Three follow-ups
(R4A-1 to R4A-3) are carried into step 4b as Part A. Step 3 review items R3B-1 to R3B-4
are closed.

Review method note: the architect's environment cannot fetch a Go 1.27 toolchain, so this
review is by code reading. Behavior is evidenced by Devin's CI runs (ci and integration
green on e1a4bfb), not re-executed by the architect.

## Verified by reading

- **R3B-1 closed.** `AllowSELinuxDisabled` has a secure zero value. `HostSELinuxMode == ""`
  (unknown) falls through to the disabled path, which refuses unless
  `AllowSELinuxDisabled` is set. An AppArmor-style label is a hard failure when host facts
  say enforcing or permissive.
- **R3B-2 closed.** Timeouts count as the window's end only within the 2 s tolerance.
- **R3B-3 closed.** 99 of 99 triggers matched, by kernel timestamp, with the first at
  543 µs. The earlier 778 ms was event-delivery latency, not an enforcement gap. Recorded
  as delivery latency only.
- **R3B-4 closed.** ADR 0019's reasoning is corrected, and there is a restart-read superset test.
- **B1/B2 sound.** Key parsing checks the SPKI algorithm OID against the declared keytype
  independently of crypto/mldsa. ECDSA requires the named curve P-384. ML-DSA-87 requires
  absent parameters and the exact public key size. Verification dispatches on the
  trusted key's type, uses pure ML-DSA-87 with an empty context, and has no HashML-DSA
  path.
- **B4.** The size arithmetic is documented in ADR 0002's amendment, and the 256 KiB root cap is
  reasonable.

## R4A-1 [MEDIUM] `require_keytypes` is optional, so a role can silently lose its hybrid guarantee

`internal/trust/root.go` `validateRole`: an omitted `require_keytypes` is accepted as "no
algorithm requirement". The step 4 prompt (B3) required the field to be non-empty, and the
working agreement says ambiguity resolves to the interpretation that rejects more. With the
field omitted, a role holding both an ECDSA and an ML-DSA key with threshold 1 accepts
either signature alone. That is exactly the downgrade hybrid signing exists to prevent, and
nothing flags it. Omission is easy to make in a future root rotation.

Required:
- `require_keytypes` is mandatory on every role (root, targets, log). Absent = malformed
  metadata. Present-but-empty stays malformed.
- Regenerate vectors. Add vectors: a role without the field (reject), and a rotation whose
  new root omits it (reject).
- Update ADR 0022.

## R4A-2 [LOW] Require canonical SPKI encoding (one key = one key ID)

Key IDs are SHA-256 of the provided DER. Two encodings of the same key would yield two key
IDs, which would let one key count twice toward a threshold and slip past the A6
disjointness rule (root, targets and log keys must differ). Go's DER parsing is strict and
probably rejects alternate encodings already, but the guarantee should not depend on
library internals.

Required: after parsing, re-encode the key (`x509.MarshalPKIXPublicKey` for ECDSA; an
explicitly built SPKI with the RFC 9881 OID and absent parameters for ML-DSA-87) and
require byte equality with the provided DER, else malformed metadata. Test with a
hand-built non-canonical encoding if one exists that the parser accepts; if none can be
constructed, say so and keep the check as a defensive invariant.

## R4A-3 [LOW] "ML-DSA unavailable" can be reported as "bad signature"

`dsse.VerifyMLDSA87` maps every `mldsa.Verify` error to `(false, nil)`. If the build's
crypto module refuses ML-DSA at verify time rather than at key construction, the failure
is reported as an invalid signature, not `ErrMLDSAUnavailable`. That still fails closed,
but operators would chase a nonexistent signing problem.

Required: at agent startup (internal/agent in step 4b), run a self-test: verify an embedded
known-good ML-DSA-87 test vector (and an ECDSA P-384 one). Record availability in a
capability flag. When ML-DSA is unavailable, any role requiring `mldsa-87` yields a typed
rejection whose reason names "ML-DSA unavailable in this build", and an audit record is
emitted. Tests cover both cases with an injected verifier.

## Process notes

- Good: the split into 4a and 4b worked. The trust format was reviewed before the store
  persists it.
- Good: the keytype/SPKI check is independent of crypto/mldsa, so metadata parsing never
  depends on ML-DSA being available in the build.
