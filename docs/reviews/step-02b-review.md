# Architect review of step 2B/2C (commit fe11a62)

C1. [CRITICAL] G1 negative operators fail open.
    Reproduced by the architect: a kprobe on security_file_open with Sigkill and
    matchBinaries NotIn [""] / NotIn ["relative"] / NotPrefix ["x"] / NotPrefix with
    "-x"-suffixed look-alikes of every protected binary passes Parse + Check.
    Root cause: excludesAllBinaries reuses the positive "could match" helpers
    (ambiguous ⇒ true), and coversPrefix's "nested inside" direction is wrong for
    exclusion.
    Fix by replacing the helpers with ONE reference semantics function, written to
    match Tetragon v1.8.0's matching (cite file:line for each operator):
        matches(op string, values []string, path string) bool
      In/Equal: path == v;  Prefix: HasPrefix(path, v);  Postfix: HasSuffix(path, v);
      NotIn/NotEqual/NotPrefix/NotPostfix: the negation of the positive form over ALL
      values (i.e. NotIn matches iff path is not equal to any value).
    Then:
      - G1 for binaries (exact files): reject iff ∃ protected binary b (both usrmerge
        spellings, after path.Clean) with matches(op, values, b). This one rule
        covers positive and negative operators; delete excludesAllBinaries/covers*.
      - Values that are empty, relative or contain ".." are rejected outright in any
        enforcement selector (G1 and G2), for every operator, before matching.
      - Selectors with more than one matchBinaries entry → reject (do not inspect [0]
        only), and add a test asserting the pinned CRD has maxItems: 1 for
        matchBinaries under every hook type.
    Tests: every probe above plus: NotIn missing exactly one protected binary (for each
    one), NotPostfix ["d"] (must be accepted only if every protected binary ends in
    something excluded... compute it, don't assume), NotPrefix ["/usr/"] (should exclude
    /usr/... but not /sbin/init; check after usrmerge canonicalization).
    Mutation test: extend to negative operators: for each passing corpus policy and each
    protected binary, generate NotIn/NotPrefix/NotPostfix sets that miss that binary
    (including ambiguous and look-alike values); every mutant MUST be rejected. Add a
    property test: G1's decision equals the brute-force "∃ protected b: matches" over
    randomly generated operators/values.

C2. [HIGH] G2 path coverage.
    - Treat as path-typed for G2/G3: file, filename, path, linux_binprm, AND every
      string-like arg type (string, char_buf, char_iovec, and any other textual type
      in the pinned generictypes) on any hook. Cite the type list file:line.
    - For directory targets D: a value could match a path inside D iff
        In/Equal: v == D or HasPrefix(v, D+"/")
        Prefix:   HasPrefix(D, v) or HasPrefix(v, D+"/")
        Postfix:  ALWAYS (some path inside D ends with any suffix) → reject
      Negative-only path selectors with enforcement remain rejected.
    - Re-run the upstream corpus and update the table; explain every changed verdict.

C3. [HIGH] G3 exec-hook coverage.
    Replace the fixed list: a hook is exec-related iff its identifier (kprobe call,
    lsmhook hook, tracepoint subsystem/event, uprobe symbol) contains "exec" or "bprm",
    case-insensitive, across all hook types. Include tests for kprobe sys_execve with
    syscall: true, sys_execveat, tracepoint syscalls/sys_enter_execve, lsmhook
    bprm_check_security, kprobe bprm_execve.

C4. G3 scoping must be specific: "positive matchArgs" now means a positive operator on a
    path-typed arg (per C2). linux_binprm: confirm from the pinned source that its
    matchArgs values are compared against the binary path and cite file:line; if you
    cannot confirm, G3 must not count linux_binprm matchArgs as scoping (and say so).

C5. Override placement: Override is allowed only on kprobes (subject to G8
    KprobeOverride) and lsmhooks (subject to G8 LSMBPF). Override on uprobes or
    tracepoints → REJECTED_GUARDRAIL (new rule ID G10, documented in ADR).

C6. Protected binaries: add /usr/libexec/openssh/sshd-session and
    /usr/lib/systemd/systemd-logind (one-line rationale each).

C7. Open-question resolutions to record in the report and an ADR (no code beyond C1–C6):
    UpdateState stays rejected; ADR 0013 (G9 in root metadata) is approved for a future
    root-format change; hostSelector/nodeSelector stay rejected; step 3 will verify
    usrmerge symlinks at agent startup.

Definition of done: make ci green locally and on GitHub Actions for the final commit
(include run number); coverage gates hold; corpus table updated; every probe in C1
rejected.
