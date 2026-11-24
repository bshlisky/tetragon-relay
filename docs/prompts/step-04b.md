# tetragon-relay — new session: Step 4b (persistent state store)

You are continuing an existing, security-critical project for an enterprise customer.
You have no memory of earlier sessions; the repository is the source of truth. Do not
rely on anything not written in it.

Repo: https://github.com/bshlisky/tetragon-relay (branch main). Clone it fresh.

---------------------------------------------------------------------------------------
## Part 0 — Pick-up

### First actions (in this order)
1. Two files are ATTACHED to this message: this prompt and step-04a-review.md. Commit them
   verbatim, in one commit ("docs: add step 4a review and step 4b prompt"):
   - docs/reviews/step-04a-review.md
   - docs/prompts/step-04b.md (this prompt)
   From now on, every session prompt is committed under docs/prompts/ so the repo holds
   the full instruction history.
2. Run `make ci` from a clean clone and confirm green before any change.
3. Acknowledge with ≤ 15 bullets: the trust/verify/apply architecture as it stands, the
   three review items (Part A), and your plan for Parts C–E.

### Read these before writing any code
1. docs/architecture.md: security architecture, the source of truth. Do not edit it;
   propose changes in an ADR with status Proposed.
2. docs/reviews/: architect reviews; every instruction in them is binding.
3. docs/reports/step-01.md … step-04a.md: what has been built and why.
4. docs/decisions/: ADRs; Accepted ADRs are constraints (especially 0016–0022).
5. The code this step extends: internal/trust (typed keys, RequireKeyTypes),
   internal/dsse, internal/verify (EpochSource), internal/guard (PolicyHistory),
   internal/apply (LKGStore, Reconcile, PersistDir), internal/limits.

### Current state (verify each claim yourself)
- Steps 1–3 and 4a are complete and accepted at e1a4bfb (ci and integration green on
  GitHub). The trust and bundle formats are crypto-agile (ecdsa-p384 and mldsa-87 key
  types, per-role require_keytypes); production roles require ecdsa-p384 only.
- go.mod is at go 1.27.0 / toolchain go1.27.4 (ADR 0021).
- Still in-memory fakes, made persistent by THIS step: verify.EpochSource,
  guard.PolicyHistory, apply.LKGStore, and trust-root state.
- Tetragon pinned to v1.8.0.

### Environment
Linux-only paths are verified through the GitHub Actions ci and integration workflows:
push, read the run results yourself, fix forward. If you cannot read Actions results from
your environment, say so at the start.

### Working agreement (applies to every step)
- Scope discipline: implement only what this prompt or the reviews ask. If something
  seems needed but is out of scope, list it under "Open questions"; do not build it.
- Ambiguity: implement the interpretation that rejects more, and record it in the
  report. Never guess a fact about Go, Linux, Tetragon, RHEL or the TPM; cite the source
  (file:line or URL) or ask.
- Security-relevant config (capabilities, writable paths, permissions, network
  allowances) is never widened to make a test pass. If a test needs more privilege than
  production has, the design or the test is wrong: stop and report.
- Secure zero values: any field whose zero value would disable a security check is a bug.
- When a finding changes the design, stop and ask before implementing.
- No silent fallbacks; no time.Now, os.Getenv, globals or init side effects in
  internal/; no panics on any input; typed errors for every rejection; a test for each.
- Do not change Accepted ADRs, the proto (buf breaking runs in CI) or existing vector
  expectations unless this prompt says so (Part A does, for vectors).
- New third-party dependencies need an ADR with justification.
- Small commits (≤ ~400 changed lines excluding generated code and vectors), one logical
  change each, conventional messages.
- Report facts must be pasted command output, not written from memory.
- Definition of done: push, then confirm BOTH ci and integration are green on GitHub for
  the final commit; record run numbers in the report.
- Session size: if the work clearly will not fit one session, finish a coherent part,
  get CI green, write the report for what is done, and stop. Never stop mid-item.

---------------------------------------------------------------------------------------
## Part A — Step 4a review follow-ups (first; one commit each; regression tests each)

Full details are in docs/reviews/step-04a-review.md.

A1. R4A-1: `require_keytypes` is mandatory on every role (root, targets, log); absent =
    malformed metadata. Regenerate vectors; add "role without the field" and "rotation
    whose new root omits it" vectors (both reject). Update ADR 0022.
A2. R4A-2: after parsing a key, re-encode it and require byte equality with the provided
    SPKI DER (canonical encoding, so one key = one key ID). Add a non-canonical-encoding
    test if one can be constructed that the parser accepts; otherwise state that and keep
    the check as a defensive invariant.
A3. R4A-3: implemented in Part D2 (the startup crypto self-test); listed here for
    traceability.

---------------------------------------------------------------------------------------
## Part C — Persistent state store (new package internal/store)

Read architecture sections 7.6, 7.7, 8.2 (`store` module), 8.4 and 8.10.

C1. Location and permissions: everything lives under /var/lib/tetragon-relay/ (already
    in ReadWritePaths). Directory 0700, files 0600, owned by tetragon-relay. Verify the
    directory's ownership and mode at open and refuse if wrong. No new writable paths, no
    capabilities.
C2. Contents (one logical state, versioned schema):
    - per-scope epochs (verify.EpochSource)
    - per-scope monitor history: policy names seen in monitor-mode bundles
      (guard.PolicyHistory)
    - LKG: the last-known-good bundle envelope per relay domain as raw DSSE bytes (never
      re-encoded), plus its digest (apply.LKGStore)
    - the current trust root as its raw signed bytes plus its version
    - a monotonically increasing state generation number
C3. Layout and crash safety: large blobs (envelopes, root metadata) are content-addressed
    files (name = sha256 of the bytes) under blobs/. A single small index file references
    them. Write sequence: write new blobs and fsync each, write index.tmp and fsync,
    rename to index, fsync the directory, then garbage-collect unreferenced blobs. A crash
    at any point leaves either the old or the new state readable, never a mix.
C4. Integrity: the index carries an HMAC-SHA-384 over its canonical bytes (including the
    generation and the blob digests). The HMAC key comes from a KeySealer interface
    (Unseal() ([]byte, error)); a fake now, a TPM-sealed key bound to PCR 7 in step 5
    (architecture 8.10). Blobs are verified against their content hash on every read.
C5. Rollback protection: the generation is mirrored in a MonotonicCounter interface
    (Read() (uint64, error); Increment() (uint64, error)); a fake now, a TPM NV counter
    in step 5. At open, index.generation must equal counter.Read(); a lower generation
    (an old copy restored) is tamper. Increment after the index rename. Handle the crash
    window between rename and Increment: index.generation == counter + 1 is accepted
    exactly once, followed by an Increment. Test it.
C6. Tamper or corruption (fail closed, never reset): HMAC failure, blob hash mismatch,
    generation mismatch, unparseable index or wrong permissions put the store in a
    TAMPERED state:
    - reject every bundle and every trust update (no epoch information is trustworthy,
      so accepting anything could allow a replay)
    - never unload or change what Tetragon currently has loaded
    - return a typed error and write an audit record (Alert{TAMPER} is wired in step 6)
    - never silently re-initialize; recovery is an explicit operator action
      (re-enrollment: specify the interface and an ADR now, implement later)
    First boot (an empty store directory) is distinct from tamper: it initializes a fresh
    store at generation 1 from the RPM-shipped initial root. An index that is present but
    unreadable is never treated as first boot.
C7. Trust-root persistence and downgrade protection: the persisted root is
    authoritative. The RPM-shipped root (/etc/tetragon-relay/trust/root.json) is used only
    at first boot or to move FORWARD: a higher version must chain from the persisted root
    through trust.Update one version at a time (the RPM may ship intermediate versions).
    A lower or equal RPM root is ignored and logged. Never accept a downgrade.
C8. Size bounds: cap the index size, scope count, history names per scope and total
    blob bytes. Exceeding a cap is a typed error, never a silent truncation. Constants go
    in internal/limits with rationale.
C9. Concurrency: one writer (in-process mutex plus an exclusive flock on a lock file in
    the store directory, to detect a second relayd instance). Reads see a consistent
    snapshot.

---------------------------------------------------------------------------------------
## Part D — Wiring

D1. Implement verify.EpochSource, guard.PolicyHistory and apply.LKGStore on
    internal/store. Persist a scope's epoch only after a successful apply (APPLIED);
    record monitor history only after a successful monitor-mode apply. Document the
    ordering of "Tetragon state changed" relative to "store committed", and what reconcile
    does after a crash between them.
D2. Startup sequence in a new internal/agent package (relayd's main stays minimal; it is
    wired in step 6):
    1. crypto self-test (R4A-3): verify embedded known-good ECDSA P-384 and ML-DSA-87
       test vectors. Set a capability flag. If ML-DSA is unavailable, any role requiring
       mldsa-87 yields a typed rejection naming "ML-DSA unavailable in this build", and an
       audit record is written. If the ECDSA self-test fails, refuse to start.
    2. open the store
    3. trust root (C7)
    4. TAMPERED / first-boot decisions
    5. hand the components to the apply engine
    Unit tests for every branch.
D3. No networking, TPM, control stream, telemetry or packaging changes.

---------------------------------------------------------------------------------------
## Part E — Tests

E1. Fault-injection filesystem layer for internal/store (an interface around the os
    calls used). Crash at every single filesystem operation of every write path, re-open,
    and assert the state is exactly old or exactly new and open succeeds without tamper.
E2. Tamper tests: flip a byte in the index; flip a byte in each blob; delete a blob;
    restore an older index plus blobs (rollback); wrong permissions; a symlink instead of
    the directory or a file; index generation ahead by 2; an unreadable index. Each must
    end in TAMPERED, never in first-boot initialization.
E3. Trust-root tests (C7): RPM newer and chaining (accept); RPM newer and not chaining
    (reject, keep persisted); RPM older (ignore); first boot; a hybrid rotation persisted
    and reloaded.
E4. Property test: random sequences of apply / epoch / history / trust operations with
    random crash points and reopens never violate monotonic epochs or monotonic root
    versions.
E5. Fuzz: FuzzStoreIndex (index parser), added to CI smoke and nightly workflows.
E6. Coverage ≥ 95% for internal/store, internal/trust, internal/verify, internal/dsse;
    ≥ 90% for internal/agent.
E7. Integration: existing scenarios stay green. Add one: apply a bundle, re-open the
    store (simulated agent restart), confirm the epoch and LKG persisted, and that a
    replay of the same bundle is rejected with REJECTED_EPOCH.

---------------------------------------------------------------------------------------
## Out of scope
TPM implementation (step 5), identity and mTLS (5), control stream and relayd wiring (6),
telemetry (7), SELinux module, RPM and final packaging (8), TLS PQC key exchange (5/6),
the operator re-enrollment command (interface and ADR only).

## Report: docs/reports/step-04b.md (also paste it in your final message)
1. Summary (≤ 10 bullets)
2. File tree of what was added or changed
3. Command output: `make ci` tail, per-package coverage, fuzz exec counts, benchmarks,
   lint and govulncheck, GitHub run numbers for ci and integration on the final commit
4. Mapping: each A/C/D/E item → functions → tests → vectors
5. Invariants and threats addressed (INV-1, T-07, T-13, T-24, plus state rollback) with how
6. Deviations from this prompt or the architecture, with reasons
7. Dependencies added, with ADR references
8. Known limitations; everything still behind fake interfaces
9. Open questions for the architect, numbered
10. Self-review: the 5 places a reviewer is most likely to find a bug, and why
11. The crash-point matrix from E1 (operation × outcome)
