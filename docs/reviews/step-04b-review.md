# Architect review: step 4b (origin/main @ 75d523e)

Reviewer: architect · Date: 2026-11-24 · Verdict: **Accepted as partial.** Parts A, C, D,
E1, E2 and E6 are accepted. E3, E4, E5 and E7 are incomplete, and six follow-ups
(R4B-1 to R4B-6) are open. Both are finished in step 4c, before step 5.

Review method: code reading (the architect's environment cannot fetch Go 1.27), plus
Devin's ci and integration runs (45486062711 on 5edaafd; 45488366600 on 75d523e).

## Verified by reading

- **R4A-1 closed.** `require_keytypes` is mandatory on every role, with reject vectors.
- **R4A-2 closed, with a real find.** A trailing DER element spliced into an ECDSA key's
  AlgorithmIdentifier is accepted by `encoding/asn1` and `crypto/x509`, letting one key map
  to two key IDs. The canonical re-encoding check now rejects it. Good work: this is
  exactly why the check was required rather than assumed.
- **Store open logic.** A missing index with a nonzero monotonic counter is tamper, so
  deleting the index cannot force first-boot re-initialization. The generation must equal
  the counter, with the counter+1 crash window accepted exactly once. Symlinks, wrong
  modes and an unreadable index are tamper.
- **Persisted root re-verified at startup.** `trust.LoadInitialRoot` runs on the persisted
  bytes, and a failure is treated as tamper. Expiry is enforced at verification time, not
  at load, so an expired root does not stop the agent from starting (it keeps enforcing
  LKG), which is correct.

## Answers to the open questions

1. **Integration evidence:** agreed, the current integration suite does not exercise the
   store. E7 is required before step 5 (step 4c).
2. **LKG blob as parsed JSON instead of raw DSSE bytes:** not acceptable as is; see
   R4B-2. This deviation changed an architecture-specified artifact, so under the working
   agreement it needed a stop-and-ask, not a deviation note.
3. **Store parsing roots:** keep internal/store free of an internal/trust dependency. The
   agent's re-verification with `LoadInitialRoot` at every startup is the right layer.
   Add a test asserting that Startup rejects (as tamper) a persisted root whose bytes
   carry a valid HMAC but fail trust verification.
4. **Remaining E items:** finish E3, E4, E5 and E7 in step 4c, before step 5. E7 is the
   only end-to-end evidence that persisted epochs actually stop replays.

## R4B-1 [MEDIUM] Hosts more than one root version behind can never catch up

Self-review 1 is right, and the outcome is worse than a runbook note can fix: the RPM ships
a single `root.json`, and `Update` accepts only N+1. A host that missed one RPM release is
stuck on its old root forever. Once that root expires, the host stops accepting bundles
fleet-wide for that cohort.

Required:
- The RPM ships every root version since the first one, as
  `/etc/tetragon-relay/trust/roots/<version>.root.json` (keep `root.json` as the initial
  root for first boot, or derive it as the lowest version present; pick one and document
  it in an ADR).
- At startup, walk forward from the persisted version through every available version
  in order, each verified by `trust.Update` against its predecessor. Stop at the first
  failure, keep the last good one, and write an audit record.
- File-name versions must match the metadata version inside, else ignore that file and
  audit. Bound the number of files read (limits constant).
- Tests: two versions behind (accept both steps); a gap in the chain (stop at the gap);
  a misnamed file; a malicious file claiming a higher version that does not chain.

## R4B-2 [MEDIUM] Persist the LKG as the raw signed envelope

Architecture 8.2 and 7.7 specify that the LKG store keeps the raw DSSE envelope. The step 4b
implementation stores the apply engine's parsed canonical set, so after a restart the
agent re-applies policies whose only integrity protection is the store HMAC. A raw
envelope can be re-verified independently, and it proves where the policy came from.

Required:
- Change `apply.LKGStore` to carry the raw envelope bytes, plus the trust-root version
  that verified it, alongside the parsed set. Plumb them from `verify.Verify`'s input
  through the apply engine. Write an ADR for the interface change.
- The store persists the raw envelope and keeps the root blob of that version referenced
  for as long as the LKG references it.
- At startup, re-verify the LKG: the envelope signature must verify under the recorded
  root version (expiry and epoch checks excluded, since this is not a new acceptance),
  and the parsed set must equal what re-parsing the envelope's payload produces. Any
  mismatch is tamper.
- Tests: an LKG whose envelope is altered but whose HMAC still matches (simulates a
  compromised HMAC key) is detected as tamper; an LKG verified under an old root version
  still loads after a root rotation.

## R4B-3 [LOW] Ownership check must fail closed on unknown platforms

`checkOwnerAndMode` returns nil when `fi.Sys()` is not `*syscall.Stat_t`. It should return
an error (refuse to open). Test with an injected FileInfo.

## R4B-4 [LOW] fsync in the blob "already present" path

`writeBlobIfMissing` skips fsync when the blob already exists. fsync the existing file and
the blobs directory anyway, so durability never depends on an earlier writer. This is cheap.

## R4B-5 [LOW] Make "committed but counter not incremented" explicit

When the index rename succeeds but `counter.Increment()` fails, the write is durable but
the call returns an error. Return a distinct typed error (`ErrCommittedCounterLag`) and
document the required caller behavior: treat the operation as committed, enter DEGRADED,
and re-open the store, whose counter+1 rule completes the increment. Add a test through
the agent/apply wiring proving that the apply engine does not roll Tetragon back because
of this error.

## R4B-6 [LOW] ML-DSA availability at startup

- During forward root chaining (R4B-1), refuse to adopt a new root whose
  `require_keytypes` includes `mldsa-87` when the self-test reports ML-DSA unavailable.
  Keep the previous root and audit it. Adopting it would make every future bundle
  unverifiable on this host.
- If the persisted root already requires `mldsa-87` on such a build, Startup succeeds
  (LKG keeps enforcing) but reports a DEGRADED condition with the reason "trust root
  requires ML-DSA, unavailable in this build", so it surfaces immediately rather than at
  the first bundle.

## Process notes

- Good: stopping at a coherent point with green CI, and an honest list of what was not
  done.
- Good: self-review items 1, 4 and 5 were real issues. The self-review is doing its job.
- Change: an architecture-specified artifact (R4B-2) must never be altered through a
  "deviation". Stop and ask.
