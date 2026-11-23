# ADR 0015: Resolutions to step 2b's open questions (architect review item C7)

## Status

Accepted (architect review of commit fe11a62, item C7). Records decisions
only; no code in this step implements anything beyond what C1-C6 already
require.

## Context

`docs/reports/step-02b.md` section 9 listed six open questions for the
architect. The review of commit fe11a62 resolves four of them directly
(C7); the review items themselves (C1-C6) effectively resolve or
supersede the other two (G3's exec-hook coverage and the exact filename
arg index), which are addressed in `docs/reports/step-02c.md` instead.

## Decisions

1. **`UpdateState` stays rejected (G7 unknown action).** Step 2b's
   `internal/guard/actions.go` already classified `UpdateState` as
   neither enforcement nor observe, rejecting any policy that uses it.
   The architect confirms this is correct and should not be revisited
   until a future step analyzes whether `UpdateState`'s cross-selector
   state mutation needs its own guard rule (step 2b's open question 4).
   No code change; this ADR records the decision as final for this
   project's current scope.

2. **ADR 0013 (G9 in root metadata) is approved** as the eventual
   placement for `ProtectedSetSource`'s real data, for the step that
   implements it. See ADR 0013's updated Status section.

3. **`hostSelector`/`nodeSelector` stay rejected as Kubernetes-only
   selectors (B4).** Step 2b's open question 6 asked whether the
   architect agreed with treating these as Kubernetes-only given neither
   is literally a "namespace selector." Confirmed: both operate on
   Kubernetes-specific concepts (host-vs-pod workload distinction and
   Kubernetes `Node` object labels respectively) that do not exist on a
   bare RHEL host, and architecture doc section 1.2 scopes Kubernetes
   deployments out entirely. No code change;
   `internal/policydoc/allowlist.go`'s existing rejection is confirmed
   correct, not provisional.

4. **Step 3 will verify usrmerge symlinks at agent startup.** This
   project's guardrail matching (`internal/guard/protected.go`) assumes a
   fixed, RHEL 9-standard usrmerge topology (`/var/run` -> `/run`,
   `/sbin` -> `/usr/sbin`, `/bin` -> `/usr/bin`) baked in at compile time,
   since no host-specific information is available when a bundle is
   verified (architecture doc section 7.4 explicitly: "Verification uses
   only local state; it never calls the controller," and no filesystem
   probing happens during `Verify`/`Check` either). Architect review item
   C1's self-review already flagged this as a residual-risk assumption
   (docs/reports/step-02b.md section 10, item 5). The architect confirms
   the mitigation belongs in step 3 (the relay agent's startup/health
   checks, architecture doc section 8 and `Hello`'s host-fact reporting),
   not in the guardrail engine itself: step 3 should verify the assumed
   symlinks actually exist and point where expected, and alert (or refuse
   to apply policy) if they don't, since `internal/guard`'s compiled-in
   protected lists would otherwise silently stop covering half of a
   protected binary's real path on a host where usrmerge was reverted or
   never completed. No code in this step implements this; it is recorded
   here as a requirement for step 3.
