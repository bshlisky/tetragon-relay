# ADR 0024: Forward trust-root chaining across multiple RPM-shipped versions (R4B-1)

## Status

Accepted.

## Context

`docs/reviews/step-04b-review.md` R4B-1 found that step 4b's `internal/agent.Startup` only
ever considered a single RPM-shipped root (`/etc/tetragon-relay/trust/root.json`) as a
forward-chain candidate, accepted only if it chained exactly one version ahead of the
persisted root (`(*trust.Root).Update`'s own "exactly `r.Version + 1`" rule, architecture
doc section 7.6). A host that missed one RPM release — and so never saw the intermediate
root version — could never catch up: once its root's 365-day validity expired
(architecture doc 7.6), it would stop accepting bundles fleet-wide for its cohort, with no
path back except manual intervention.

The fix requires two things: (1) the RPM must ship every root version since the first one,
not just the latest, so a host behind by more than one version has something to chain
through; (2) `internal/agent` must walk that set forward one version at a time instead of
only ever trying a single candidate.

Full RPM packaging is step 8 scope (`docs/prompts/step-04b.md`'s "Out of scope": "RPM and
final packaging (8)"), so this ADR fixes the packaging layout and the
`internal/agent.Config` shape the eventual packaging/step-6 caller must honor, without
actually building the RPM spec or relayd's `main()` wiring.

## Decision

1. **RPM layout.** The RPM ships every root version it carries under
   `/etc/tetragon-relay/trust/roots/<version>.root.json` (e.g. `roots/2.root.json`,
   `roots/3.root.json`, ...). `root.json` (the existing, single pinned path) is **kept** as
   the lowest version the RPM carries (today, always version 1) and used only at first
   boot — it is not removed or renamed, so this is backward compatible with every existing
   first-boot path and test. (The review offered a second option — deriving `root.json`
   from the lowest file in `roots/` — which is equivalent in content but adds an extra
   indirection the packaging step gains nothing from; kept simple.)
2. **`internal/agent.Config` gains `AvailableRPMRoots map[uint64][]byte`**, keyed by the
   version parsed from each file's own name under `roots/`. The caller (a future relayd
   `main()`, step 6) does nothing more than list the directory and read each file's bytes
   into this map; `internal/agent` decides which are usable and in what order, consistent
   with this package's existing convention for `InitialRootBytes` ("internal/agent has no
   filesystem access of its own for config paths").
3. **`establishTrustRoot` walks forward one version at a time** starting from
   `persisted.Version + 1`, using a candidate set built from
   `AvailableRPMRoots` plus `InitialRootBytes` (folded in by its own declared version, so
   the existing single-hop behavior via `root.json` alone is simply the one-candidate case
   of this general walk — no behavior change for any existing caller that never populates
   `AvailableRPMRoots`). Each step is verified independently via `(*trust.Root).Update`
   against the previous step's result (not the originally persisted root), so a 10-version
   gap is 10 independent signature-threshold checks, never a single "trust the last one"
   shortcut.
4. **Stopping rules**, each logged via `Auditor` and never surfaced as a `Startup` error
   (Part C7's existing "never accept silently on failure, but never fail here either" —
   the persisted root was already good enough to boot on):
   - No file at exactly the next version needed: stop (a gap, or simply nothing further).
   - A file's own declared metadata version does not match its file name: that file is
     ignored for its filename's slot entirely (never trusted by file name alone); if
     nothing else fills that slot, this becomes the same "gap" case above.
   - Two files claim the same version with different content: the first one encountered
     (in a fixed, deterministic order — `root.json`, then `roots/` ascending by version) is
     used; the other is ignored and audited.
   - `(*trust.Root).Update` fails (bad signature threshold, expired, wrong payload type,
     etc.): stop, keep the last version the walk actually reached.
   - The walk reaches `limits.MaxRootChainFiles` (64) successful steps in one `Startup`
     call: stop, even if a further usable candidate exists, and audit it distinctly from an
     ordinary gap. A legitimate fleet does not rotate its root key set anywhere near 64
     times between two consecutive agent restarts (architecture doc 7.6: 365-day root
     validity); this exists purely to bound the CPU a single `Startup` call will spend
     chain-verifying, regardless of how many files a compromised or buggy packaging source
     might place on disk.
5. **Bounding file count is layered**: `Startup` itself returns the typed
   `ErrTooManyRootFiles` if `len(Config.AvailableRPMRoots) > limits.MaxRootChainFiles`,
   rather than silently processing only the first 64 (map iteration order is not
   meaningful, so a silent truncation would be non-deterministic about which versions it
   kept). The REVIEW's "bound the number of files read" is primarily the eventual
   directory-listing caller's responsibility (step 6: it should never even attempt to read
   more than this many files from `roots/` in the first place); this check is defense in
   depth at the boundary `internal/agent` actually controls.

## Consequences

- No change to any existing `internal/agent` test or caller that leaves `AvailableRPMRoots`
  unset: the single-hop behavior via `InitialRootBytes`/`root.json` alone is unchanged bit
  for bit (it is the one-candidate case of the general walk).
- `internal/store` is untouched: `PersistTrustRoot`'s "version must move strictly forward"
  invariant already supports persisting any later version reached by however many steps the
  walk took; it has no notion of "steps" at all.
- The actual RPM `%files`/spec changes to ship `roots/<version>.root.json` files, and
  relayd's `main()` listing that directory into `Config.AvailableRPMRoots`, are deferred to
  step 6/8 as before — this ADR only fixes the shape those later steps must produce and
  consume.
