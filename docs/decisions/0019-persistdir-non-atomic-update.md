# ADR 0019: PersistDir's update sequence is not atomic

## Status

Proposed.

## Context

`internal/apply.PersistDir` (step 3 prompt Part D4) writes the relay-managed policy set
to `/etc/tetragon/tetragon.tp.d/relay/` so Tetragon reloads the same set across a
restart (ADR 0016). Commit 709f3da made this atomic (sibling-temp-directory swap: write
into a fresh temp directory next to `relay/`, then two renames to swap it in), but doing
so required the relay group to have write access to `relay/`'s *parent*,
`/etc/tetragon/tetragon.tp.d`, itself.

The architect's review of 709f3da (`docs/reviews/step-03a-review.md`, R3-2) rejected this:
the production unit's `ProtectSystem=strict` + `ReadWritePaths=.../relay`
(`packaging/systemd/tetragon-relay.service`) keeps the parent directory read-only, so the
atomic-swap design would pass CI (which widened the parent's permissions to make the
test pass) but fail on every real host — and widening production to match would let the
relay agent create or delete policy files it does not own in a directory it otherwise
has no business writing to.

## Decision

`PersistDir` is redesigned (R3-2) to operate using only paths inside `relay/` itself: a
staging subdirectory (`relay/.staging/`) holds newly-written files until they are
fsynced, then each is renamed directly into `relay/` (a same-filesystem rename, since
`.staging` is a child of `relay/`, not a sibling needing the parent's write permission);
stale files are then removed and `relay/` itself is fsynced.

This sequence is accepted as **not atomic**: a crash between any two of its steps can
leave `relay/` with a mix of old and new files, or a leftover `.staging` directory (which
the next `PersistDir` call always clears before proceeding). This is acceptable because:

- Tetragon reads `relay/` only at its own process startup (ADR 0016's
  `cmd/tetragon/main.go:694-726` citation); this engine never races that read against an
  in-progress `PersistDir` call, so a non-atomic intermediate state on disk is never
  observed by Tetragon mid-update.
- The relay's `Reconcile` (`internal/apply/reconcile.go`) compares Tetragon's actually
  loaded policies against the LKG set on every cycle and after every control-stream
  reconnect, and re-asserts LKG (calling `Apply`'s same add-before-remove procedure,
  which calls `PersistDir` again) whenever they differ — including immediately after any
  Tetragon restart that picked up a stale or partially-updated `relay/` directory from a
  crash during a previous `PersistDir` call. A crash here therefore converges to the
  correct final state on the next successful `PersistDir` call, not through atomicity of
  any single call.

`.staging`'s own nesting (two directory levels below Tetragon's
`--tracing-policy-dir` root, vs. `relay/`'s one) is itself what keeps Tetragon's loader
from ever reading it mid-update: ADR 0016 cites `cmd/tetragon/main.go:694-726`'s
`tpMaxDepth := 1`, under which "a directory two or more levels deep is skipped
(`fs.SkipDir`)".

## Consequences

- `packaging/systemd/tetragon-relay.service`'s `ReadWritePaths=` needs no change beyond
  what architecture doc section 8.6 already specifies (`.../tetragon.tp.d/relay`, not its
  parent).
- `.github/workflows/ci.yml` and `scripts/e2e-rhel9.sh` no longer grant the relay group
  write access to `/etc/tetragon/tetragon.tp.d` itself, only to `relay/`, matching
  production and closing the CI/production gap R3-2 identified.
- `internal/apply/persist_test.go`'s `TestPersistDir_CrashRecovery` covers a crash
  injected at every step of the sequence (staging write, staging fsync, rename, stale
  removal, `relay/`'s own fsync, final staging cleanup) and confirms a subsequent
  `PersistDir` call for the same target set converges correctly in every case.
