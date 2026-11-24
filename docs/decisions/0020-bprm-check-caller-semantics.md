# ADR 0020: `security_bprm_check` reports the caller, not the new image

## Status

Accepted.

## Context

`TestIntegration_RollbackOnAdminPathKill` (step 3 prompt Part E3's "rollback when the
health window sees a forbidden admin-path kill" scenario) failed against real Tetragon
v1.8.0: a `Sigkill` policy with `matchBinaries: In ["/usr/bin/bash"]` on
`security_bprm_check` never killed anything and never produced a matching event, even
though the same mechanism demonstrably works for `TestIntegration_EnforcementKillsCanary_AdminPathSurvives`'s
dedicated canary binary.

The architect's diagnosis (docs/reviews/step-03a-review.md "R3-E3" discussion) identified
the cause: `security_bprm_check` is an LSM hook invoked during `execve()` **before** the
calling process's image is replaced by the new one. At the point the hook fires, the
process information Tetragon reports (and that `matchBinaries` matches against) is still
the **caller's own binary**, not the binary about to be loaded.

A throwaway diagnostic (PR #2, not merged; `internal/apply/diagnose_r3e3_test.go`, deleted)
confirmed this empirically against real Tetragon v1.8.0, using the pinned tarball's own
unfiltered `tetra getevents -o compact`:

- **E1** (`security_bprm_check` kprobe with `matchActions: [Post]` and no `matchBinaries`,
  then the test process itself execs `/usr/bin/true` directly): first matching event at
  **778 ms** after `AddTracingPolicy` returned. This rules out BPF-attach latency as an
  explanation — well under both the 10 s and 15 s windows the original failing tests used.
- **E2** (same hook, `matchBinaries: In ["/tmp/testbin/bash"]`, a private copy of
  `/usr/bin/bash` at `/tmp/testbin/bash` as the trigger, invoked as
  `/tmp/testbin/bash -c "/usr/bin/true; /usr/bin/true"`): first matching event and first
  `Sigkill` both at **691 ms**. Reported `process.binary` on the event was
  `"/tmp/testbin/bash"` — the **caller**, confirming the hypothesis directly.

`bash -c "true"` (the original test's trigger) never produces any event at all, regardless
of policy or timing: `true` is a bash builtin, so a single-command `-c` string never causes
bash to `execve()` anything — there is no second exec event for a `matchBinaries` filter on
any *other* binary to catch, and bash itself was never the target of the policy's
`matchBinaries` (it listed `/usr/bin/bash`, which only matches bash as a *caller*, not as the
image the test process itself directly exec'd).

## Decision

- `security_bprm_check` (and any other pre-image-replacement exec hook) policies must be
  understood as matching the **caller**, not the binary being loaded. This is already the
  correct semantics for `internal/apply`'s own D5 admin-path rule (architecture doc; step
  3 prompt Part D5): the intent is "an admin shell was killed while about to run its next
  command", which is exactly what a caller-side match captures.
- `internal/apply/integration_test.go`'s admin-path test now targets a private copy of
  `/usr/bin/bash` at `/tmp/testbin/bash` (never the real system binary, which is also the
  CI runner's own step-execution shell — see the R3-E3 fix F1 commit) and triggers it with
  two sequential external commands (`/usr/bin/true; /usr/bin/true`), not one: bash
  optimizes a single trailing command in a `-c` string into a tail-call `execve()` that
  replaces bash's own image, which would make the *second* exec's caller be bash only
  transiently (and, for a single builtin command, never at all).
- `limits.MinApplyHealthWindow` is unchanged: E1/E2 showed sub-second real-world attach
  latency, well inside the existing bound. The original failure was never a timing problem.
- `internal/apply/admin.go` documents the caller-vs-new-image distinction directly on
  `adminPathBinaries` so a future reader does not reach for the same "it must be a timing
  bug" hypothesis.

## Consequences

- No change to `internal/apply`'s production logic (`admin.go`, `health.go`): the D5 rule's
  existing behavior was already correct for this semantics; only the test's trigger and
  target were wrong.
- `docs/reports/step-03.md` section 13 records the diagnostic evidence (E1/E2 timings, the
  `tetra getevents` excerpts) so this is not re-litigated from scratch in a future step.
- step-03a-review.md's "R3-E3 fix F1/F2" commits (scoping every integration test policy to
  `/tmp/testbin/`, cleaning up after every test, and a final-step assertion that nothing is
  left loaded) are a direct consequence of having now confirmed that a policy targeting the
  *caller* path `/usr/bin/bash` would otherwise be live and enforcing against the CI
  runner's own shell for the rest of the job.
