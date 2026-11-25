# Architect review: step 4c (origin/main @ 742bfa3)

Reviewer: architect · Date: 2026-11-25 · Verdict: **Step 4 accepted**, with two follow-ups
(R4C-1, R4C-2) that are carried into step 5a as Part A. ADR 0024 is Accepted. ADR 0025 is
Accepted with the amendments in R4C-1 and R4C-2 (update its status and text).

Review method: code reading (the architect's environment cannot fetch Go 1.27), plus
Devin's ci and integration runs, including E7 on real Tetragon (run 45554200234; final
commit 742bfa3 green).

## Verified by reading

- R4B-1 (forward root chaining), R4B-3, R4B-4, R4B-5, R4B-6 and the Q3 test: closed.
- R4B-2 design (ADR 0025) is sound: the raw envelope is content-addressed inside the LKG
  blob, historical root versions are retained while any LKG references them, and startup
  re-verification checks the signature under the recorded root version and compares the
  re-parsed payload field by field with the cached set.
- E3, E4, E5 and E7 are done. E7 is the first end-to-end evidence that persisted epochs
  block replays against real Tetragon.

## R4C-1 [HIGH] A missing raw envelope skips re-verification

`internal/agent/reverify.go`: when `len(set.RawEnvelope) == 0`, re-verification is skipped
with an audit record ("pre-R4B-2 record"), and the cached policy set is trusted.

There are no pre-R4B-2 records anywhere: the store was introduced in step 4b and has never
been deployed. And this is precisely the attack R4B-2 defends against: an attacker who can
produce a valid index HMAC (a compromised HMAC key) rewrites the LKG blob with altered
policies and simply omits `raw_envelope`. Re-verification is then skipped and the altered
set is trusted. The defense is bypassed by deleting one field.

Required:
- An LKG entry without a raw envelope (or with `RootVersion == 0`) is `ErrTampered`.
- Remove the "pre-R4B-2" branch and its comment. Test: a store whose LKG blob lacks
  `raw_envelope` but carries a valid HMAC is tamper.

## R4C-2 [MEDIUM] An expired historical root skips signature verification entirely

When the recorded root version's metadata has expired (`TargetsVerifier` returns
`ErrRootMetadataExpired`), re-verification is skipped and the cached set is trusted. Expiry
is a rule about accepting NEW bundles, but a signature's validity does not change with
time. Within a year of normal operation every older retained root will have expired. An
attacker with the HMAC key can then point an altered LKG at an expired retained root
version and bypass the check, just as in R4C-1.

Required:
- Add a trust-layer constructor for provenance checks that verifies signatures and role
  thresholds (including `require_keytypes`) under a root regardless of its metadata
  expiry, named so it cannot be mistaken for acceptance, e.g.
  `(*Root).ProvenanceVerifier()`. Document that it must never be used to accept new
  bundles. Add a test or lint rule that only internal/agent's re-verification calls it.
- `reverifyDomainLKG` uses it, so expiry never skips the signature check. An expired root
  is still audited (as operational staleness) but does not change the outcome.
- Tests: an LKG under an expired root with a valid signature loads; an LKG under an
  expired root with an altered payload or signature is tamper.

## Process note

Both findings are fail-open branches that were justified in comments as avoiding a "new
requirement". The working agreement's rule is that ambiguity resolves to the
interpretation that rejects more. A branch that skips a security check needs an explicit
architect decision, not a comment.
