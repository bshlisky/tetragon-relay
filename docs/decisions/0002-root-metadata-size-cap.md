# ADR 0002: Root metadata envelope size cap

## Status

Accepted.

## Context

Architecture doc section 7.4 step 1 specifies a 1 MiB cap on policy bundle
envelopes, but does not specify a cap for trust-root metadata envelopes
(section 7.6). Root metadata is structurally much smaller: a handful of
ECDSA P-384 public keys (DER-encoded SubjectPublicKeyInfo is ~120 bytes each)
and three short role definitions.

## Decision

`internal/limits.MaxRootMetadataBytes` is set to 64 KiB. At realistic scale
(tens of keys, three roles), a root metadata envelope is on the order of a
few KiB; 64 KiB leaves generous headroom (hundreds of keys) while still
bounding the work an attacker-supplied `TrustUpdate` message can force before
any parsing happens, independent of the bundle envelope cap.

## Consequences

- If the real deployment ever needs more than roughly 150-200 keys in a
  single root metadata document, this constant will need to be revisited.
- This is listed as an open question for the architect in
  docs/reports/step-01.md, since the number is this project's choice, not
  one specified in the architecture doc.

## Amendment (step 4 Part B4): raised to 256 KiB for ML-DSA-87

ML-DSA-87 (FIPS 204) keys and signatures are far larger than ECDSA P-384's:

| Item | ECDSA P-384 | ML-DSA-87 |
| --- | --- | --- |
| Raw public key | ~97 bytes (P-384 point) | 2592 bytes (`crypto/mldsa.MLDSA87PublicKeySize`) |
| SPKI DER (measured, `go1.27.4`) | ~120 bytes | 2614 bytes |
| SPKI DER, base64 | ~160 bytes | 3488 bytes |
| Raw signature | ≤104 bytes (ASN.1 DER, worst case) | 4627 bytes (`crypto/mldsa.MLDSA87SignatureSize`) |
| Signature, base64 | ~140 bytes | 6172 bytes |

Worst-case arithmetic for a single root metadata envelope, using
`limits.MaxSignaturesPerEnvelope` (16, unchanged) all ML-DSA-87, and a
generously-sized hybrid key set (18 keys across the three roles, split 9
ML-DSA-87 / 9 ECDSA P-384, headroom over any real deployment's expected
key count):

- Signatures: 16 × (94 bytes JSON overhead per `{"keyid":...,"sig":...}`
  entry + 6172 bytes base64 signature) ≈ **97.9 KiB**.
- Keys: 9 × (~3608 bytes per ML-DSA-87 key entry, including its
  `sha256:`-prefixed map key and `keytype`/`public_key_der_b64` JSON
  overhead) + 9 × (~280 bytes per ECDSA P-384 key entry) ≈ **34.2 KiB**.
- Role definitions (`keyids`, `threshold`, `require_keytypes` for three
  roles) ≈ **1.6 KiB**.
- Payload JSON (keys + roles + schema/version/expires/require_log_proof)
  ≈ 36 KiB raw, base64-encoded into the envelope's `payload` field ≈
  **48 KiB**.
- Envelope wrapper (`payloadType`, braces) ≈ 0.1 KiB.

Total: 48 (payload, base64) + 97.9 (signatures) + 0.1 (wrapper) ≈
**146 KiB** worst case.

`internal/limits.MaxRootMetadataBytes` is raised from 64 KiB to **256
KiB**: comfortably above the ~146 KiB worst case (≈75% headroom), while
still bounding the parsing work an attacker-supplied `TrustUpdate` can
force before any signature is checked. `MaxSignaturesPerEnvelope` stays
16 (step 4 Part B4: unchanged). The ML-DSA-87 worst-case verify benchmark
(`docs/reports/step-04a.md`) confirms this size increase does not push
verification time anywhere near the 50 ms budget.
