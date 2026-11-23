# Architect review: step 2D (commit 4f32285)

Reviewer: architect · Date: 2026-11-23 · Verdict: **Step 2 closed**, with one open
finding (R2D-1) carried into step 3 as Part A1.

## Verified fixed

All probes were re-run end to end through `policydoc.Parse` + `Guardrails.Check`, using a
kprobe on `security_file_open` with a `Sigkill` action. Every protected binary was listed
in each probe unless the row says otherwise.

| Probe | Result |
| --- | --- |
| `NotIn [""]`, `NotIn ["relative"]`, `NotPrefix ["x"]` | rejected |
| `NotPrefix` with `-x` look-alikes of every protected binary | rejected |
| `NotIn` with trailing `/`, doubled leading `/`, or `/./` spellings | rejected |
| `NotPrefix` with trailing `/` spellings | rejected |
| Exact canonical list with a single trailing `/` on one entry | rejected |
| Uppercase `/USR/...` spellings | rejected |
| Zero-width-space (U+200B) look-alike spellings | rejected |
| Exact canonical `NotIn` list (control) | accepted (correct) |
| G3: `sys_execve` (`syscall: true`), `Sigkill`, `NotIn`-only scope | rejected (G3) |
| G10: `Override` on a libc uprobe | rejected (G10) |

Accepted and correct by design:
- `NotPrefix ["/usr/","/sbin/","/bin/"]`: every protected binary is under these prefixes.
- `NotPrefix ["/"]`: matches nothing, so the policy has no effect.
- `NotPostfix` listing the final letter of every protected binary: G1 is satisfied.
  See design note DN-1.

## Open finding

### R2D-1 [HIGH] Escape-decoded control and invisible characters in YAML scalars

B1's control-character rejection runs only over the raw document bytes
(`checkRawBytes`, `internal/policydoc/yamlharden.go`). Escape sequences inside
double-quoted scalars (`\0`, `\t`, `\u0000`, `\u202e`) are decoded by the YAML parser
afterwards, and the decoded values are never re-checked. These pass Parse + Check:

- `Prefix "/\0anything"`
- `Prefix "/\tx"`
- `In "/opt/app\u0000/usr/sbin/sshd"`
- `Prefix "/\u202e"`

Impact:
1. **Possible G1 bypass.** If Tetragon or the kernel side truncates at NUL,
   `"/\0anything"` becomes `Prefix "/"`, which matches every binary (host lockout).
   This is not confirmed against the v1.8.0 source, so the finding is rated high, not
   critical.
2. **Approval spoofing (T-12).** Bidi overrides and zero-width characters make the string
   an approver sees in the UI differ from the string the agent enforces. This undermines
   two-person approval regardless of kernel behavior.

Required fix (step 3, Part A1): in `internal/policydoc`, after escape decoding, for every
scalar (keys and values):
- reject Unicode category Cc except `\t` `\n` `\r`
- reject all of category Cf (bidi controls, zero-width characters, BOM)
- reject U+2028, U+2029 and Unicode noncharacters

In selector values and hook identifiers (`matchBinaries` / `matchArgs` values, `call`,
`symbols`, `path`, `subsystem`, `event`), additionally reject `\t` `\n` `\r`.

Regression tests are required for all four probes above and for each character class,
with fuzz seed additions.

## Design note

### DN-1: Admin-path availability is not fully covered by G1

`NotPostfix` with the final letter of every protected binary is correctly accepted by G1,
but such a policy would still `Sigkill` `/usr/bin/bash`. Admins could authenticate
through sshd and then lose their shell. Adding shells to the protected set would reject
common, legitimate policies (e.g. blocking bash from reading `/etc/shadow`), so this is
not addressed in the guardrails.

Resolution: the step 3 apply engine's health window (Part D5) fails and rolls back on any
enforcement event whose process or any ancestor is in the admin-path set (sshd,
sshd-session, bash, sh, zsh, dash, login, su, sudo, systemd-logind, relayd, tetragon,
spire-agent; both usrmerge spellings).

## Status of earlier reviews

- step-01-review: all items closed.
- step-02b-review: all items closed (C1–C7, with D1 in step 2D).
- step-02c-review: D1 and D2 closed at ad752ec.
- step-02d-review (this document): R2D-1 open, tracked as step 3 A1; DN-1 tracked as
  step 3 D5.
