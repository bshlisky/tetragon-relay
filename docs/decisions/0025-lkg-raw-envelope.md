# ADR 0025: Persist the LKG as the raw signed envelope, re-verified at startup (R4B-2)

## Status

Proposed.

## Context

Architecture doc sections 8.2 and 7.7 specify that the agent's LKG store keeps the raw
signed DSSE envelope, not a parsed/re-encoded form: "last-known-good bundle envelope per
relay domain as raw DSSE bytes (never re-encoded), plus its digest" (8.2), "staging slot of
the LKG store" persisted by `fsync` before the add-before-remove apply sequence runs (7.7).

Step 4b's `apply.LKGStore` interface (step 3, already accepted) only ever hands
`internal/store` the apply engine's already-verified, already-parsed `LKGSet` (policy name,
version, canonical JSON per policy, plus mode) — never the raw envelope, which the apply
engine does not retain past `verify.Verify`'s return. `internal/store` therefore
content-addressed the canonical JSON of `LKGSet` as its blob instead
(`docs/reports/step-04b.md`'s Deviations section 1), so after a restart the only thing
protecting a re-applied LKG set's integrity is the store's own HMAC — not an independently
re-verifiable signature chain back to a trust root.

`docs/reviews/step-04b-review.md` R4B-2 requires this fixed: the LKG must be the raw
envelope, re-verified against its recorded root version at every startup, with a mismatch
between the re-parsed payload and the still-cached parsed set treated as tamper. The review
explicitly calls this a case where "an architecture-specified artifact... must never be
altered through a 'deviation'" — hence this ADR, written *before* implementation, with this
session's working agreement requiring a stop-and-ask if anything here conflicts with what is
actually in the code (nothing did: the design below was confirmed against the real
`verify.Result`/`apply.LKGStore`/`internal/store` shapes before being written).

## Decision

### 1. `verify.Result` and `verify.Input` carry the raw envelope and root version

- `Input` gains `RootVersion uint64`: the version of the trust root `Input.Trust` (the
  `Verifier` the caller already built via `(*trust.Root).TargetsVerifier`) was derived
  from. The caller already knows this — it is the same `*trust.Root` it called
  `TargetsVerifier` on — so this is purely plumbing, not a new verification decision
  `Verify` itself makes.
- `Result` gains `RawEnvelope []byte` and `RootVersion uint64`, populated by `Verify` from
  `Input.Envelope`/`Input.RootVersion` on `CodeAccept` (set alongside `Bundle`, never
  independently). `Verify` performs no new checks; it only threads these two values through
  from input to output, in the same place every other `Result.Bundle` field is already
  sourced from `Input`/the parsed payload.

### 2. `apply.LKGSet` carries the raw envelope and root version, alongside the parsed set

- `LKGSet` gains `RawEnvelope []byte` and `RootVersion uint64`. This is an **additive**
  change to the struct (not a method-signature change to `LKGStore.Get`/`Put`, which are
  unaffected): every existing caller of `LKGStore` continues to compile, and `FakeLKGStore`
  needs no change at all.
- `apply.Engine.Apply` now reads `result.RawEnvelope`/`result.RootVersion` (not just
  `result.Bundle`) when it calls `e.lkg.Put` after a successful apply, carrying them into
  the persisted `LKGSet` unchanged.
- The existing `Policies`/`Mode` fields are **not removed**: they remain the parsed,
  already-rewritten (mode-rewrite, name-rewrite source) representation the apply engine
  operationally needs for add-before-remove diffing and `Reconcile`, exactly as today.
  `RawEnvelope` is the integrity-bearing artifact section 8.2 requires be persisted
  unaltered; `Policies`/`Mode` remain a derived, operational cache the apply engine already
  depended on before this step and that re-parsing the envelope on every `Get()` call would
  be wasteful to reconstruct (`Get` is called by `Reconcile` on every drift check, not just
  at startup).

### 3. `internal/store` persists the raw envelope as the LKG blob, and keeps every referenced root version's blob alive

- `lkgBlob`'s on-disk schema (`store.go`) gains `raw_envelope` (base64, the exact bytes) and
  `root_version` (uint64) fields, alongside the existing `schema`/`mode`/`policies`.
  `toLKGBlob`/`(lkgBlob).toLKGSet` are extended to round-trip them.
- `writeBlobIfMissing`'s content-addressing is now over the `lkgBlob` JSON as a whole
  (unchanged mechanism — only the struct being content-addressed gained fields), so the raw
  envelope bytes are themselves immutable and hash-verified on every read exactly as every
  other blob already is (Part C4). This is a pragmatic choice over content-addressing the
  raw envelope as its OWN separate blob file: it keeps the "one domain -> one blob
  reference" index shape (`lkgEntry{BlobDigest, Mode}`) unchanged, and still satisfies every
  property section 8.2 asks for (an immutable, hash-verified copy of the exact signed
  bytes) — the raw envelope is simply one field of the thing being content-addressed,
  rather than content-addressed completely independently. Splitting it into its own blob
  file would add a second blob reference per domain for no additional integrity property.
- **Root blob retention.** Today, `gcBlobs` only keeps the blob referenced by the single
  current `indexPayload.TrustRoot` entry; every older root version's blob is removed the
  next time anything commits. Since an LKG's `RootVersion` may now be older than the
  current trust root (a root rotation does not retroactively re-verify every domain's
  existing LKG), `indexPayload` gains `TrustRootHistory map[uint64]trustRootEntry` (version
  -> blob reference) recording every root version ever persisted via `PersistTrustRoot`.
  `gcBlobs`'s referenced set now includes every history entry whose version is still
  referenced by any domain's current `LKG[domain].RootVersion`, plus the current
  `TrustRoot.Version` itself (kept even if no LKG references it yet, matching today's
  behavior of always keeping the current root). A root version no longer referenced by the
  current `TrustRoot` AND no longer referenced by any LKG entry is garbage-collected, same
  as today. `MaxStoreRootHistoryVersions` (new, `internal/limits`) bounds
  `TrustRootHistory`'s size (Part C8 cardinality-cap discipline): exceeding it is
  `ErrLimitExceeded`, never a silent truncation — in practice bounded by how many distinct
  root versions could simultaneously still be referenced by live LKGs across every domain,
  which is bounded by `MaxStoreDomains`.
- `internal/store` still has **no** dependency on `internal/trust` (the step-04b report's
  deviation 2 / this review's Q3 answer: "keep internal/store free of an internal/trust
  dependency... internal/agent's re-verification with LoadInitialRoot at every startup is
  the right layer"). `internal/store` never parses the envelope or the root blob's content;
  it only stores and content-hash-verifies bytes and tracks which version-keyed blob is
  still "live."
- New method `(*Store) Domains() ([]string, error)`: returns every domain currently in
  `LKG`, for `internal/agent`'s startup re-verification loop (section 4) to iterate over.
  Not part of `apply.LKGStore` (the apply engine itself never needs to enumerate domains;
  it always operates on one domain/scope at a time) — a new, store-specific method,
  analogous to `FirstBoot()`/`Generation()`/`Tampered()`.
- New method `(*Store) RootAtVersion(version uint64) (raw []byte, ok bool, err error)`:
  returns a historical root version's raw bytes from `TrustRootHistory`, for
  `internal/agent` to re-verify an LKG's `RootVersion` against the exact root that verified
  it, which may not be the current one.

### 4. `internal/agent.Startup` re-verifies every persisted LKG

- After `establishTrustRoot` (so the current root — needed only to confirm
  `RootAtVersion`'s result still exists and is itself trustworthy metadata — is available),
  `Startup` calls a new `reverifyLKG(st, now, auditor) error` step:
  1. `st.Domains()` lists every domain with a persisted LKG.
  2. For each domain, `st.Get(domain)` returns the cached `LKGSet` (as today); its
     `RawEnvelope`/`RootVersion` are the fields this ADR adds.
  3. `st.RootAtVersion(set.RootVersion)` retrieves that exact historical root's raw bytes;
     missing (should be impossible given section 3's retention rule; treated as
     `store.ErrTampered` if it happens anyway, since it means the retention invariant was
     violated) is fail-closed, never "skip this domain."
  4. `trust.LoadInitialRoot(rootBytes)` parses that historical root (self-verifying,
     exactly as `establishTrustRoot` already does for the persisted/current root), then
     `root.TargetsVerifier(now)` (expiry-checked as of now — the review's "expiry ...
     checks excluded, since this is not a new acceptance" refers to epoch/expiry checks
     from `verify.Verify`'s own algorithm being skipped here, not to `TargetsVerifier`'s own
     `ErrRootMetadataExpired` guard, which exists purely to keep that method's one
     documented precondition; this is addressed explicitly in `reverifyLKG`'s own tests:
     expiry of the root metadata used to re-verify an old LKG does not, by itself, treat the
     LKG as tampered — see the implementation note below).
  5. `dsse.ParseEnvelope` + the verifier's `Verify(env)` re-checks the signature threshold
     exactly as `verify.Verify` step 3 does, but with NO epoch, expiry, target, or scope
     checks (the review: "expiry and epoch checks excluded, since this is not a new
     acceptance" — this is re-confirming provenance of an already-accepted artifact, not
     re-running acceptance).
  6. The envelope's payload is re-parsed into the same bundle-policy shape `LKGSet` stores
     (name, version, canonical JSON per policy, mode) and compared field-for-field against
     the cached `set.Policies`/`set.Mode`. Any mismatch (signature failure, parse failure,
     or parsed-content mismatch) is `store.ErrTampered`, surfaced the same way every other
     `Startup` tamper path is (store already open, error returned, caller must not retry
     expecting self-heal).
  - Implementation note on expired root metadata: if `TargetsVerifier(now)` itself refuses
    (the historical root's OWN 365-day validity has elapsed — plausible for a very old LKG
    on a host that has not re-applied that domain in a long time), this is logged via
    `Auditor` and does NOT mark the store tampered (an expired root is an operational
    staleness condition the architecture doc already treats as "stop accepting NEW bundles,
    keep LKG enforcing" at the targets-verification layer, not evidence the LKG itself was
    forged) — `reverifyLKG` treats this one specific outcome as "skip re-verification for
    this domain, audit it" rather than `ErrTampered`. Every other failure mode in step 5/6
    above (bad signature, mismatched content) IS `ErrTampered`: those can only happen if
    the stored bytes were altered or forged, never from ordinary time passing.

## Consequences

- **Store schema version.** `indexSchema` bumps from `relay.store.index.v1` string constant
  value unchanged (the schema STRING doesn't need to change, since `strictjson`'s decoder
  already rejects unknown fields on the OLD side only if `TrustRootHistory`/the new
  `lkgBlob` fields were present in bytes an old binary tries to read — a downgrade
  scenario this project does not support mid-fleet-rollout per existing precedent, e.g.
  ADR 0022's crypto-agility changes also didn't version-gate the wire format). A fresh
  install or a store with no existing LKG/root history is unaffected either way
  (`TrustRootHistory` defaults to an empty map).
- **Coverage/test additions required** (Part E, this step): `TestReverifyLKG_TamperedEnvelopeWithMatchingHMACIsDetected`
  (an LKG whose envelope is byte-altered after the HMAC was computed over the containing
  index — simulating a compromised HMAC key, since a correct HMAC key would never let this
  happen through this package's own write path) and
  `TestReverifyLKG_VerifiedUnderOldRootVersionStillLoadsAfterRotation` (exactly the two
  tests the review names), plus a retention test proving an old root version's blob
  survives a rotation while any LKG still references it, and is GC'd once nothing does.
- **`internal/apply`'s existing tests** (`FakeLKGStore`, `engine_test.go`) continue to pass
  with zero changes to `LKGSet{}`-literal construction sites that omit the two new fields
  (they default to `nil`/`0`), except wherever a test specifically asserts a round-trip of
  the new fields, which this step adds.
- **No change** to `apply.LKGStore`'s method set, `internal/store`'s dependency graph
  (still no `internal/trust` import), or any Accepted ADR.
