# ADR 0016: Apply engine mode mechanism, Enable/Disable handling, and loaded-name scheme

## Status

Accepted.

## Context

Step 3 prompt Part B1 fixes a typed RPC allowlist for `internal/tetra`:
`AddTracingPolicy`, `DeleteTracingPolicy`, `ListTracingPolicies`,
`EnableTracingPolicy`, `DisableTracingPolicy`, `GetHealth`, `GetVersion`,
`GetEvents`, enforced by a test that fails if the package references any other RPC.

Part D2 separately requires: "if v1.8.0 has native per-policy mode (cite), use it.
Otherwise rewrite every enforcement action to Post in the canonical JSON before load."

Inspecting the pinned v1.8.0 source (`api/v1/tetragon/sensors.proto`, commit
`a5a667837d4b1ecd9018797994bb4e39b98702e1`) shows both halves of this are true at once,
in tension:

- v1.8.0 *does* have a native per-policy mode: `TracingPolicyMode`
  (`TP_MODE_UNKNOWN`/`TP_MODE_ENFORCE`/`TP_MODE_MONITOR`/`TP_MODE_MONITOR_ONLY`,
  `sensors.proto:59-64`), reported back on every `TracingPolicyStatus.mode`
  (`sensors.proto:153`).
- The *only* RPC that sets it is `ConfigureTracingPolicy`
  (`ConfigureTracingPolicyRequest.mode`, `sensors.proto:193-203`), which is not in
  Part B1's allowlist. The `TracingPolicy` CRD itself has no `mode`-shaped field
  anywhere in `pkg/k8s/apis/cilium.io/v1alpha1/types.go` or the vendored
  `cilium.io_tracingpolicies.yaml` schema, so mode cannot be set through the YAML body
  of an `AddTracingPolicyRequest` either. There is no way to use native mode without
  calling `ConfigureTracingPolicy`.

## Decision

Part B1's allowlist (and its enforcing test) is treated as the harder constraint: it is
a specific, reviewed security control (bounding the blast radius of what this package
can ever ask Tetragon to do), not an incidental detail. `internal/apply`'s Part D2 is
therefore satisfied using the fallback mechanism unconditionally: every `Sigkill` /
`Signal` / `Override` / `NotifyEnforcer` / `Set` / `UpdateState` action (every
enforcement-shaped `KprobeAction` other than `Post`/`NoPost`, per
`api/v1/tetragon/tetragon.proto:500-536`) in a policy's canonical JSON is rewritten to
`Post` before `AddTracingPolicy` is called for "monitor" loads. `ApplyResult` records
`mode_mechanism: "action-rewrite"` for every load (never `"native"`), and this project's
status quo never calls `ConfigureTracingPolicy`.

Consequence for D2's "mode switch is a new versioned load, never an in-place mutation":
this falls out for free, since there is no in-place mutation path available at all
(native mode would have been the only candidate for one).

### EnableTracingPolicy / DisableTracingPolicy are deprecated server-side

`pkg/server/server.go:370-373` (v1.8.0): `EnableTracingPolicy` returns an error
unconditionally unless the daemon was started with
`--enable-deprecated-tracingpolicy-grpc` (`option.Config.EnableGRPCDeprecatedTP`).
`DisableTracingPolicy` is gated the same way. Since this project's apply engine never
needs to pause a policy without unloading it (D3's add-before-remove and D6's rollback
both operate by adding/deleting whole, distinctly-named versions), `internal/tetra`
still exposes typed `EnableTracingPolicy`/`DisableTracingPolicy` methods (the allowlist
requires them to exist), but `internal/apply` never calls them in its core add/remove/
rollback/reconcile paths. Architecture doc section 9.1 (Tetragon daemon configuration)
is amended to document that this flag is *not* required for this project's correctness,
and should not be enabled solely for this relay (reduces the Tetragon daemon's own
attack surface by one deprecated, soon-to-be-removed RPC pair).

### Loaded-policy digest (Part D8)

`TracingPolicyStatus` (`sensors.proto:131-160`) carries `id`, `name`, `namespace`,
`info`, `sensors`, `enabled` (deprecated), `filter_id`, `error`, `state`,
`kernel_memory_bytes`, `mode`, `stats`, `domain`, `hook_statuses` — no raw policy
content or hash. `ListTracingPolicies` therefore cannot return policy content, confirming
Part D8's premise; the digest is computed over the sorted
`(loaded_name, state, enabled_bool_from_state, mode, sensors)` tuples it does return. The
loaded name already embeds `CanonicalSHA256`'s first 8 hex (Part D1), so content
identity is bound as D8 describes; the residual risk (root attacker deletes and re-adds
a different policy under the same loaded name) is unchanged from the step 3 prompt's own
framing and is not mitigated further in this step.

### Loaded name validation (Part D1)

`pkg/tracingpolicy/k8s.go:38-59` dispatches to `crdutils.CRDContext.FromYAML`, which
calls `apivalidation.ValidateObjectMeta(..., apivalidation.NameIsDNSSubdomain, ...)`
(`pkg/crdutils/crdutils.go:110-115`): the loaded name must be a valid RFC 1123 DNS
subdomain, max 253 bytes. This project's own `internal/limits.PolicyNamePattern`
(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`, max 63 bytes, no dots) is strictly narrower than
a DNS subdomain segment, so `"<name>-v<version>-<8 hex>"` (name ≤ 63 bytes, version ≤ 10
decimal digits, 8 hex digits, two literal separators ⇒ ≤ 85 bytes total) is always both a
valid DNS subdomain and well under 253 bytes; no additional length check against
Tetragon's own limit is reachable in practice, but `internal/apply` asserts it anyway as
a defensive invariant (test fails loudly if `internal/limits.PolicyNamePattern` or the
version bound is ever widened past what this bound assumes).

### Relay-managed marker (Part D1)

No field returned by `ListTracingPolicies` is a free-form label/annotation Tetragon
preserves verbatim. However, `domain` (`AddTracingPolicyRequest.domain`,
`DeleteTracingPolicyRequest.domain`, `TracingPolicyStatus.domain`) is exactly such a
mechanism: Tetragon stores and returns it, and `ListTracingPoliciesRequest.domain` filters
by it server-side (`sensors.proto:33-36`, `pkg/server/server.go:250-258` for the
`"grpc"` default applied to requests that don't set one). `internal/apply` sets
`domain = "relay-managed"` on every `AddTracingPolicyRequest`/`DeleteTracingPolicyRequest`
it issues and lists with `ListTracingPoliciesRequest{Domain: "relay-managed"}` to enumerate
only its own policies; combined with the `D1` loaded-name pattern
(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?-v[0-9]+-[0-9a-f]{8}$`), a policy must match both to
ever be deleted by this engine. Policies loaded any other way (static directory at
startup with no domain wrapper, a different gRPC client, or a human operator) have a
different domain and are never touched, only reported (Part D1's "foreign policies are
never touched" requirement).

### Policy directory read semantics (Part D4)

`cmd/tetragon/main.go:694-726` (`loadTpFromDir`): the default directory is
`/etc/tetragon/tetragon.tp.d` (`pkg/defaults/defaults.go:54`, flag
`--tracing-policy-dir`), walked with `fs.WalkDir` and `tpMaxDepth := 1`: entries exactly
one level below the root (i.e. one subdirectory deep) ARE visited; a directory two or
more levels deep is skipped (`fs.SkipDir`). Every regular file found (`st.Mode().IsRegular()`,
no extension filter of any kind) is loaded via `tracingpolicy.FromFile` +
`observer.GetSensorManager().AddTracingPolicy`, in the lexical order `fs.WalkDir`/
`os.DirFS.ReadDir` produces (Go's `os.ReadDir` sorts entries by filename). This confirms
the step 3 prompt's "if subdirectories are not read, use a relay- filename prefix"
fallback is unnecessary: `internal/apply` (Part D4) writes the persisted set to
`/etc/tetragon/tetragon.tp.d/relay/` (one level down, matching Tetragon's own default
directory and the recorded depth), which Tetragon reloads at restart with no extension
or naming requirement. Load order is deterministic (lexical by filename within the
subdirectory) but not otherwise meaningful to this project (every file is an
independent, uniquely-named `AddTracingPolicy` call; order does not create or remove
an enforcement gap within the directory load itself the way D3's add-before-remove does
across a live reconfiguration).

## Consequences

- `internal/tetra`'s typed client never calls `ConfigureTracingPolicy`,
  `EnableTracingPolicy`, or `DisableTracingPolicy` from `internal/apply`'s core paths;
  `Enable`/`DisableTracingPolicy` remain available on the client (allowlist requirement)
  but are unused by `internal/apply` and documented as requiring a daemon flag this
  project does not recommend enabling.
- If a future Tetragon version removes the deprecated RPCs or changes
  `ConfigureTracingPolicy`'s availability, this ADR's reasoning (not this project's
  correctness) would need to be revisited, not before.
- Architecture doc section 9.1 should NOT list `--enable-deprecated-tracingpolicy-grpc`
  among recommended Tetragon daemon flags.
