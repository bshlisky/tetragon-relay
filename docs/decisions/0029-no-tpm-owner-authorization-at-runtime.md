# ADR 0029: relayd never uses TPM owner-hierarchy authorization

## Status

Accepted.

## Context

`docs/reviews/step-05a-review.md` R5A-1 [MEDIUM]: as built in step 5a, `relayd` depends on
TPM owner-hierarchy authorization at runtime in two places:

- `internal/tpm.CreateSRK` (`srk.go`) creates the SRK fresh on every `KeySealer.Unseal` and
  `HostSigner.Sign`/`createHostSigner` call via `tpm2.CreatePrimary{PrimaryHandle:
  tpm2.TPMRHOwner}` with an implicit empty owner authorization.
- `internal/tpm.Counter.Read`/`Increment` (`counter.go`) authorize `TPM2_NV_Read` and
  `TPM2_NV_Increment` as `tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth:
  tpm2.PasswordAuth(nil)}` — the NV index's `OwnerRead`/`OwnerWrite` attributes
  (`expectedCounterAttributes`), not any authorization of its own.

Both assume the TPM's owner hierarchy authorization is, and stays, empty. The review
identifies two consequences:

1. **Fleet breakage.** A host whose TPM has a non-empty owner password (common under
   enterprise TPM provisioning standards, e.g. a vendor or site security baseline that sets
   one at imaging time) cannot seal/unseal the store key, read or increment the counter, or
   sign with the host key — `relayd` never accepts a bundle on such a host.
2. **Excess authority.** `relayd` is an unprivileged, long-running network-facing daemon
   (packaging/systemd/tetragon-relay.service: no capabilities, `/dev/tpmrm0` only). Routinely
   exercising owner-hierarchy authorization — the authorization that can also define/undefine
   NV indices, change the owner hierarchy's own auth value, and clear the TPM — is far more
   authority than anything `relayd` actually needs (read, increment, load/unseal/sign under an
   already-provisioned parent and index). This violates this project's least-privilege design
   (architecture doc P6/P9) even on a TPM with empty owner auth today.

## Decision

Split "define" from "use" cleanly along the same root/unprivileged-daemon line this project
already draws for host-facts collection (`relay-probe`, architecture doc 8.7) and the counter
index itself (step-05a prompt C3): **provisioning (root, owner-authorized, once) creates
persistent, self-authorized objects; `relayd` (unprivileged) thereafter uses only the
authorization those objects were given, never the owner hierarchy.**

### 1. Persistent SRK (supersedes ADR 0027 §4's "no persistent handle")

`internal/tpm.ProvisionSRK(t, ownerAuth)` (root, `relay-probe --provision-tpm`, owner
authorization, idempotent):

- Reads the public area at `TCGStandardSRKHandle` (`0x81000001`, the TCG "EK Credential
  Profile"/`tpm2-tools`-conventional default SRK handle many host TPM stacks already
  populate). If an object is already persistent there **and its template matches
  `SRKTemplate` exactly** (type, name algorithm, object attributes, ECC curve and symmetric
  parameters — not `Unique`, which is the actual, non-template-fixed public point), that
  handle is used: provisioning makes no changes and defines nothing new. Sharing the
  well-known handle with another already-provisioned stack is safe specifically because the
  template is checked field-for-field first; a mismatched object at that handle is left alone
  and this project falls through to its own handle instead of overwriting or adopting it.
- Otherwise reads `ProjectSRKHandle` (`0x81020001`, a handle this project owns exclusively, in
  the TCG-registered owner persistent-object range `0x81000000`-`0x817FFFFF`, chosen to avoid
  the single most commonly pre-populated slot, `0x81000001`, while still being far from any
  handle another default tool is likely to also pick). If an object is already there and
  matches the template, that handle is used (idempotent re-run). If an object is there and
  does **not** match, provisioning fails closed (`ErrSRKHandleMismatch`) rather than silently
  picking a third handle or overwriting a collision — the same "detect and refuse, never
  adopt" rule `ProvisionCounter`/`validateCounterIndex` already apply to the NV counter
  index.
- If neither handle holds a matching object, provisioning creates a fresh primary from
  `SRKTemplate` under the owner hierarchy (`tpm2.CreatePrimary{PrimaryHandle:
  tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(ownerAuth)}}` — the one
  remaining owner-authorized operation, run exactly once by provisioning, same budget as
  `ProvisionCounter`'s own `TPM2_NV_DefineSpace`) and persists it at `ProjectSRKHandle` via
  `TPM2_EvictControl` (also owner-authorized), then flushes the transient copy.

`internal/tpm.OpenSRK(t)` (unprivileged, `relayd`, called by `KeySealer` and `HostSigner`
instead of `CreateSRK`): performs the same two-handle lookup-and-template-match as
`ProvisionSRK`'s read path, with **no authorization at all** (`TPM2_ReadPublic` is
unauthenticated) and no owner hierarchy involvement whatsoever. It returns
`ErrSRKNotProvisioned` if neither handle holds a matching object — the same "provisioning
must have run first" contract `OpenCounter`/`ErrCounterNotProvisioned` already has.

Because the SRK is now persistent, `KeySealer.Unseal` and `HostSigner.Sign`/
`createHostSigner` load and seal/unseal/sign **under the persistent handle's own object
authorization** (`UserWithAuth`, empty authValue — unchanged from today, since "no separate
owner password in this design" already described this project's non-owner object auth
choice) via `tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth:
tpm2.PasswordAuth(nil)}`, exactly as `CreateSRK`'s transient handle was used as a parent
before. No owner hierarchy reference remains anywhere in this path. This also removes a
`TPM2_CreatePrimary`/`TPM2_FlushContext` round trip from every `Unseal`/`Sign` call (the
primary is already resident), which step-05a's report (section 10, item 2) flagged as a
latency concern worth revisiting.

`CreateSRK`/`FlushSRK` (`srk.go`) are kept as the low-level primitives `ProvisionSRK` uses
internally for the one first-time creation; nothing outside provisioning calls them anymore.

### 2. Self-authorized NV counter (supersedes ADR 0027 §5's owner-only attributes)

`ProvisionCounter(t, handle, ownerAuth)` defines the index (still owner-authorized — defining
or undefining an NV index is as inherently a provisioning-time, root-only operation as
creating the SRK, and nothing in the review asks to change that) with attributes
`AuthWrite | AuthRead | NT=Counter | NoDA` — **no `OwnerWrite`/`OwnerRead`** — and sets the
index's own authorization value via `NVDefineSpace.Auth` (`TPM2BAuth`).

**Index authorization value: empty**, the same choice this project already made for the SRK
and every other object it provisions ("no separate owner password in this design"). This is
safe for this specific index because **monotonicity, not secrecy, is what prevents
rollback**: the counter's security property is that its value can only increase and that a
delete+redefine cannot lower it below any value it ever held on this TPM (step-05a report
section 12, confirmed against real hardware-equivalent swtpm) — a property enforced by the
TPM itself regardless of who can authorize reading or incrementing it. An authValue on this
index would only matter if some *other*, less-privileged local actor needed to be denied
counter access while `relayd` still had it; no such actor exists (`relayd` is the only
process this project grants `/dev/tpmrm0` access to, via the `tss` group and `DeviceAllow`,
packaging/systemd/tetragon-relay.service) — an empty authValue costs nothing a non-empty one
would have bought here, while a non-empty one would need its own secret-distribution story
(a second root-only file, more to provision and rotate) for no additional protection against
this project's actual threat model (ADV2: root on the host already has `/dev/tpmrm0` access
and could read any file-based authValue anyway).

`Counter.Read`/`Increment` (`counter.go`) authorize `TPM2_NV_Read`/`TPM2_NV_Increment` as
`tpm2.AuthHandle{Handle: c.handle, Name: name, Auth: tpm2.PasswordAuth(nil)}` — the index's
own (empty) authValue, permitted because `AuthRead`/`AuthWrite` are now set — never
`tpm2.TPMRHOwner`. `validateCounterIndex`/`counterAttributesMatch` are updated to require
`AuthWrite`/`AuthRead` and reject `OwnerWrite`/`OwnerRead` (a counter index provisioned the
old, step-05a way is a mismatch here, by design — see Consequences).

### 3. Reading owner authorization during provisioning

`relay-probe --provision-tpm` gains `--tpm-owner-auth-file <path>` (optional; absent means
empty owner authorization, matching every host whose TPM has never had an owner password
set). When given, the file's exact contents (no trailing-newline trimming beyond a single
trailing `\n`, documented) are used as `ownerAuth` for `ProvisionSRK` and `ProvisionCounter`;
the file must be root-only (`0400`/`0600`) and relay-probe refuses (not silently proceeds
with empty auth) if it cannot be read when the flag is given. **Operator procedure**
(documented in `cmd/relay-probe`'s package doc and this ADR): on a host whose TPM owner
password is already set by the site's provisioning standard, write that password to a
root-only file before the unit's first start and pass `--tpm-owner-auth-file` in the unit's
`ExecStartPre=+` line (packaging/systemd/tetragon-relay.service); on a host with no owner
password (the common case), omit the flag entirely. This file is read exactly once, by
provisioning, and is never read by `relayd`.

## Consequences

- **This is a breaking change to step 5a's NV counter attributes.** An index already
  provisioned by step 5a's code (`OwnerWrite | OwnerRead`) does not match this ADR's expected
  attributes and is now `ErrNVIndexAttributeMismatch` on open — correct and intended (the
  whole point is that the old shape is no longer the one this project accepts), but it means
  any host that already ran step-5a's `ProvisionCounter` needs a one-time
  `TPM2_NV_UndefineSpace` + re-`ProvisionCounter` to pick up the new attributes before
  `relayd` will start. Since this project has not shipped to a real host yet (every prior
  ADR's "formats are unreleased" rationale applies equally here), this is a design correction,
  not a field migration.
- **Same for the SRK**: step 5a's SRK was transient-only (no persistent handle); this ADR
  adds persistence, which existing swtpm test state directories (ephemeral per test run)
  naturally satisfy on the next run, and which provisioning handles automatically on a fresh
  TPM.
- `internal/tpm`'s own doc comments and `docs/decisions/0027-tpm-library-and-software-tpm.md`
  sections 4 and 5 are superseded by this ADR for the SRK persistence and NV index
  authorization-attribute decisions specifically; ADR 0027 is not edited (this project's
  working agreement: superseded decisions are recorded in a new ADR, not by rewriting an
  Accepted one) but a future reader should treat this ADR as authoritative on those two
  points.
- No change to `ErrCounterNotProvisioned`, `ErrNVIndexAttributeMismatch`,
  `store.MonotonicCounter`/`store.KeySealer`'s contracts, or anything in `internal/store`:
  this ADR is scoped entirely to which TPM hierarchy authorizes which operation, not to the
  counter's or sealed key's externally-observable behavior.
- `ErrSRKNotProvisioned` and `ErrSRKHandleMismatch` are new typed errors
  (`internal/tpm/errors.go`), parallel to the counter's `ErrCounterNotProvisioned`/
  `ErrNVIndexAttributeMismatch`, so an operator can tell "provisioning never ran" apart from
  "something else is using this handle."
- `relayd` (once its `main()` exists, step 6) still refuses to start without a provisioned
  TPM (`agent.ErrTPMRequired`, unchanged); it now also never needs, holds, or is configured
  with any TPM owner or platform authorization value at all — the only secret `relay-probe
  --provision-tpm` may need (`--tpm-owner-auth-file`) is read once, by a root-run, short-lived
  process, before `relayd` itself ever starts.
</content>
