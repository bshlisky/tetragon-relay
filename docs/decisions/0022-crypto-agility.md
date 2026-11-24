# ADR 0022: Crypto-agile trust root and bundle formats (ML-DSA-87)

## Status

Accepted.

## Context

Step 4 Part B requires the trust-root and DSSE formats to accept more than one signature
algorithm, so ML-DSA-87 (FIPS 204, a NIST post-quantum signature scheme) can be added to
production later without a data migration, while production behavior today stays ECDSA
P-384 only. The formats are unreleased (no prior version has shipped to a real host), so
this step changes them in place rather than carrying a v1/v2 compatibility shim.

## Decision

### Typed keys (Part B1)

Root metadata key entries become `{"keytype": "ecdsa-p384" | "mldsa-87", "public": "<base64
SubjectPublicKeyInfo DER>"}` (field name unchanged, `public_key_der_b64`). `KeyID` stays
`"sha256:" + lowercase hex SHA-256 of the SPKI DER`, computed identically for every key
type (`trust.DeriveKeyIDFromDER`) — the hash does not care what the DER encodes.

`internal/trust.TrustedKey` (`keytype.go`) is the parsed, type-tagged form: exactly one of
an `*ecdsa.PublicKey` or a raw ML-DSA-87 public key encoding is set, matching `Type`.
Crucially, **constructing a `*mldsa.PublicKey` is deferred to the one place that actually
verifies a signature with it**, never done while just parsing/validating root metadata
structure. This is the key design choice the rest of this ADR follows from — see "What
ML-DSA unavailability means" below.

The keytype/SPKI agreement check (`parseTrustedKey`) reads the SPKI's `AlgorithmIdentifier`
OID directly via `encoding/asn1` (RFC 9881 section 4's OID
`2.16.840.1.101.3.4.3.19` for ML-DSA-87, confirmed to match `go1.27.4`'s own
`crypto/x509/x509.go:532`; RFC 5480's OIDs for ECDSA/P-384), rather than through
`crypto/x509.ParsePKIXPublicKey` for the ML-DSA case — that function internally calls
`mldsa.NewPublicKey` (`crypto/x509/parser.go:374`) and would itself be unavailable under a
build lacking ML-DSA (ADR 0021), which would make even checking *which algorithm a key
declares* impossible under that build if routed through it. ECDSA keys are still fully
parsed via `x509.ParsePKIXPublicKey`, since that has no such constraint.

A keytype that is not one of the two known values is malformed metadata (`ErrUnknownKeyType`),
never ignored. A keytype whose SPKI OID (or, for ecdsa-p384, curve; or, for mldsa-87, raw
key length) does not match is also malformed metadata (`ErrKeytypeSPKIMismatch`) — these are
deliberately separate typed errors (not both folded into the old, pre-Part-B
`ErrUnsupportedKeyType`, which is kept only for `DeriveKeyID`'s own narrower ECDSA-only
contract) so a reviewer or operator can tell "we don't know this algorithm at all" apart
from "this entry's two fields disagree with each other".

### Dispatch on the key's keytype, never the signature's (Part B2)

`TrustedKey.verifySignature` switches on `k.Type` — a property of the TRUSTED key from
root metadata — never on anything the envelope's signature itself carries. There is no
"signature algorithm" field in the wire format at all; an attacker who controls only the
envelope (not the trust root) cannot influence which verification algorithm is used for a
given keyid.

- `ecdsa-p384`: unchanged, `dsse.VerifyECDSAP384` (ASN.1 DER ECDSA over SHA-384 of the DSSE
  PAE).
- `mldsa-87`: `dsse.VerifyMLDSA87` (`internal/dsse/mldsa.go`), pure (non-pre-hashed)
  ML-DSA-87 over the DSSE PAE, empty context string, via `crypto/mldsa.Verify` — Go
  `1.27.4`'s `crypto/mldsa/mldsa_fips140v1.26.go:293-305` (the package-level `Verify`
  function `dsse.VerifyMLDSA87` calls). HashML-DSA (pre-hash, "External-mu") is never
  reachable through this call: that function always invokes the internal pure verification
  path with no hash-mode branch at all (unlike `(*mldsa.PrivateKey).Sign`, which accepts
  `crypto.SignerOpts` and switches on `opts.HashFunc()` to support External-mu signing —
  confirmed by reading `mldsa_fips140v1.26.go`'s `Sign` alongside its `Verify`).
  `internal/dsse/mldsa_test.go`'s `TestVerifyMLDSA87_ExternalMuSignatureNeverVerifies`
  demonstrates this concretely: a signature produced via External-mu signing does not
  verify via `VerifyMLDSA87` against the original message.

### What ML-DSA unavailability means (Part B2)

Under the FIPS 140-3 Go Cryptographic Module v1.0.0 (ADR 0021), `crypto/mldsa.NewPublicKey`
and `.Verify` always return an error. Because root-metadata PARSING never calls either (the
previous section), a root containing an `mldsa-87` key entry still loads successfully and
is structurally valid even on a build that cannot evaluate that key at all. Only the moment
a signature attributed to that key is actually checked — `dsse.VerifyMLDSA87`, called from
`TrustedKey.verifySignature` — invokes `mldsa.NewPublicKey`, and only then does
unavailability surface, as `trust.ErrMLDSAUnavailable` wrapping the underlying error's text
(which names the real cause, e.g. "mldsa: unavailable in FIPS 140-3 Go Cryptographic Module
v1.0.0"). That signature is never counted toward a role's threshold or `require_keytypes`,
so a role depending on an unavailable key type simply cannot be satisfied — fail closed,
never silently skip.

`internal/dsse/mldsa_test.go`'s `TestVerifyMLDSA87_UnavailableOrMalformedKey_FailsClosed`
exercises this exact code path (construction failure in `mldsa.NewPublicKey`) with a
malformed key encoding, since this development environment is not built against the
FIPS-restricted module; the error path exercised is identical regardless of which of the
two causes (genuine unavailability vs. a malformed key that somehow passed
`parseTrustedKey`'s own validation) produced it.

### Role algorithm requirements (Part B3)

`Role.RequireKeyTypes []KeyType` (wire: `"require_keytypes"`). `verifyRoleThreshold`
(`internal/trust/root.go`) tracks, per verified signature, which key type produced it; a
role is satisfied only if (a) the existing distinct-key `Threshold` is met, counting any
mix of key types, AND (b) for every keytype in `RequireKeyTypes`, at least one distinct key
of that type is among the verified set. Both conditions are evaluated against the same
verified-signature set from the same pass over the envelope — there is no way to satisfy
(b) with a signature that was not independently counted toward (a).

`require_keytypes` is validated at parse time (`parseAndValidatePayload`): it must be
either omitted entirely (no requirement) or present with at least one entry
(`ErrInvalidRequireKeyTypes` if present-but-empty), every entry must be a known keytype
with no duplicates, and every listed type must have at least one key actually in that
role's `keyids` — a `require_keytypes` entry naming a type the role has no key for could
never be satisfied and is rejected as malformed rather than accepted as an unreachable
(and therefore misleading) requirement.

Root rotation (`(*Root).Update`) checks the OLD root role against its own (already-loaded)
`RequireKeyTypes` and the NEW root role against its own (candidate) `RequireKeyTypes`
independently — the same `verifyRoleThreshold` function, called twice, once per side, the
same way Update already checked the old/new distinct-key thresholds before this step. A
rotation from an ECDSA-only root role to a hybrid one is therefore evaluated correctly on
both sides without any special-case code.

The A6 disjointness rule (root, targets and log keys pairwise disjoint,
`requireDisjointRoles`) operates purely on `KeyID`s and is unaffected by key type: it
already applies to every key type a role might list.

### Limits (Part B4)

`internal/limits.MaxRootMetadataBytes` is raised from 64 KiB to 256 KiB; see
`docs/decisions/0002-root-metadata-size-cap.md`'s amendment for the full worst-case
arithmetic. `MaxSignaturesPerEnvelope` is unchanged at 16. The ML-DSA-87 worst-case verify
benchmark (`internal/verify/bench_test.go`'s `BenchmarkVerify_WorstCaseMLDSA` /
`TestVerify_WorstCaseMLDSAPerformance`) confirms the budget stays well under 50 ms (measured
~8.6 ms best-of-7 on this development machine; see `docs/reports/step-04a.md` for the
GitHub Actions figure).

### Production default (Part B5)

The production root generator (`cmd/bundlesign-test`'s `buildStandardRoot`,
`buildHybridRoot`, and the standard (non-hybrid) vectors) sets `require_keytypes:
["ecdsa-p384"]` or leaves it unset — never requires `mldsa-87` in a role actually shipped
today. `TrustedKey`'s ML-DSA-87 verification path is complete and exercised by both direct
unit tests and vectors, but is reachable in production only once a future trust-root update
adds `mldsa-87` to a role's `require_keytypes`.

## Consequences

- No new third-party dependency: `crypto/mldsa` is standard library (ADR 0021).
- Every format change in this ADR is a breaking change to the unreleased root-metadata and
  envelope formats; every committed vector in `testdata/vectors/` was regenerated with
  `cmd/bundlesign-test`, and the new vectors required by Part B6 were added alongside them.
- `FuzzRootV2` (`internal/trust/fuzz_test.go`) gives the new ASN.1 SPKI-parsing and
  `require_keytypes` code paths dedicated fuzz coverage beyond `FuzzRootUpdate`'s
  pre-existing ECDSA-only corpus.
- `internal/verify` needed NO changes: it only ever calls `in.Trust.Verify(env)` through the
  `trust.Verifier` interface, which already hid every algorithm-specific detail behind the
  interface boundary.

## What is NOT yet crypto-agile

Per this step's explicit scope:

- **Hash algorithm.** SHA-256 is used unconditionally for every digest and key ID
  (`DeriveKeyIDFromDER`, bundle policy hashes, blob content-addressing in later steps) and
  for the DSSE PAE's own pre-hash step for ECDSA (SHA-384, tied to the P-384 curve's
  security strength; ML-DSA-87 has no separate pre-hash at all in the pure mode this
  project uses). Introducing a second hash algorithm would need its own agility mechanism
  (e.g. a digest-type prefix) not built here.
- **TLS key exchange.** Architecture doc section 6.1's cipher suite and group list
  (`secp384r1`/`secp256r1`, hybrid ML-KEM "when the RHEL crypto stack supports it") is step
  5/6 scope (the control-channel mTLS implementation), untouched by this step.
- **TPM keys.** Host identity keys are hardware-bound (TPM 2.0, architecture doc section
  5.2); their algorithm agility, if any, is dictated by the TPM's own supported algorithm
  list and is step 5 scope (TPM integration), not this step's DSSE/trust-root formats.
- **WebAuthn approvals.** Policy-approval signatures (architecture doc section 7.2 step 3)
  use the authenticator's own algorithm negotiation (WebAuthn's own `pubKeyCredParams`),
  entirely outside this project's DSSE/trust-root code; not touched here.
