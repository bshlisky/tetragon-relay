# ADR 0014: G10, Override hook placement

## Status

Accepted (architect review of commit fe11a62, item C5).

## Context

G8 (capability gating) only has a `HostCapabilities` check for `Override`
on kprobes (`KprobeOverride()`) and lsmhooks (`LSMBPF()`). The CRD's own
`ActionSelector` doc comment
(`pkg/k8s/apis/cilium.io/v1alpha1/types.go:384-396` in the pinned
`cilium/tetragon` v1.8.0 source) states `Override` has three variants and
says which hooks each is "supported" on:

```
//   1. Override the return value of function
//        Supported hooks: kprobes, uprobes, lsm
//   2. Override the value of a register
//        Supported hooks: uprobes
//   3. Override a function call
//        Supported hooks: uprobes
```

So `Override` on a uprobe is real and CRD-schema-legal, but it works via a
completely different mechanism than kprobe/lsmhook override (symbol/
address/offset substitution in the traced binary, not the kernel's
`ALLOW_ERROR_INJECTION`/`CONFIG_BPF_KPROBE_OVERRIDE` machinery G8's
`KprobeOverride()` detects). `Override` on a tracepoint is not listed as
supported at all. Before this review, neither case was gated by anything:
G8's switch only matched `HookKindKProbe`/`HookKindLsmHook` and silently
did nothing for the other two kinds, meaning an `Override` on a uprobe or
tracepoint would sail through every guardrail unchecked.

## Decision

Add G10: reject `Override` (in `matchActions` or `matchReturnActions`) on
any hook kind other than kprobe and lsmhook, unconditionally —
`REJECTED_GUARDRAIL`, not `REJECTED_CAPABILITY` (G8's code), since this
is not a capability-detection gap but an outright unsupported-by-this-project
placement. `internal/guard.RuleG10` identifies it; `internal/verify` maps
every rule other than G8 to `CodeRejectedGuardrail`, so no change to that
mapping was needed.

Rejecting uprobe `Override` outright, rather than adding a capability
check for it, is deliberate: this project has no detection mechanism for
whatever uprobe override actually requires (it is not one of the kernel
config checks in architecture doc section 9.3), and guessing it is always
safe would violate "never guess a fact about Tetragon." A future step that
adds real uprobe-override capability detection can extend G8 (not G10) and
remove the corresponding kind from G10's rejection set.

## Consequences

- No existing committed vector or upstream-corpus policy used `Override`
  on a uprobe or tracepoint before this change, so this is purely new
  coverage, not a behavior change for previously-accepted bundles.
- `internal/guard.RuleG10` is a new entry in the `RuleID` enum; existing
  switch statements over `RuleID` elsewhere in the codebase (none outside
  `internal/guard`/`internal/verify` exist yet) are unaffected.
