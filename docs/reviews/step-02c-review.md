# Architect review of step 2c (commit 5bf5866)

D1. [CRITICAL] Negative operators fail open via path.Clean.
    Reproduced by the architect: kprobe security_file_open + Sigkill with matchBinaries
    whose values are every protected binary written as "/usr/sbin/sshd/" (NotIn),
    "//usr/sbin/sshd" (NotIn), "/usr/./sbin/sshd" (NotIn), "/usr/sbin/sshd/" (NotPrefix)
    all pass Parse + Check. Tetragon compares raw strings, so these exclude nothing.
    Fix:
    - Delete cleanAnchoredValues and every other normalization of selector VALUES in
      internal/guard. matches() compares raw strings only. (Protected-set TARGETS keep
      their explicit usrmerge spellings; do not normalize values toward them.)
    - In every selector with an enforcement action, for matchBinaries and for matchArgs
      on path-typed args, reject any non-canonical anchored value:
        In/Equal/NotIn/NotEqual: v must be absolute and v == path.Clean(v)
        Prefix/NotPrefix:        v == path.Clean(v) or v == path.Clean(v) + "/"
      Postfix/NotPostfix keep the existing empty/".." rejection and additionally reject
      values containing "//" or "/./" or "/../".
      Typed error, rule G1 (binaries) or G2 (paths), message names the offending value
      truncated per the existing 128-byte rule.
    - Positive operators get the same canonical-value rule (no special cases).

D2. Tests:
    - The four architect probes above, plus each variant applied to a single binary
      inside an otherwise exact list (all must be rejected), plus the exact list
      (must pass).
    - Rewrite the G1 property test's reference implementation from scratch so it does
      NOT import or mirror any internal/guard helper: it applies Tetragon's raw-string
      operator semantics (cite kernel.go file:line) to the protected targets. The
      generator must produce non-canonical spellings (trailing "/", "//", "/./",
      "/../", mixed usrmerge prefixes) at least 30% of the time. Assert: guard accepts
      ⇒ reference says no protected binary matches AND every value is canonical.
    - Extend the negative mutation sweep with the four non-canonical spellings.
    - Re-run the upstream corpus; report any verdict changes with reasons.

Definition of done: make ci green locally and on GitHub Actions (run number in report);
every probe rejected; coverage gates hold.
