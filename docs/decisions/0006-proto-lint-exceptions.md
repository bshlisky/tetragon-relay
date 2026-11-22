# ADR 0006: buf lint exceptions for naming conventions

## Status

Accepted.

## Context

`buf lint`'s `STANDARD` rule set enforces naming conventions (service names
suffixed `Service`, RPC request/response types named `<Method>Request` /
`<Method>Response`, enum values prefixed with the enum name, zero-value enums
suffixed `_UNSPECIFIED`) that conflict with the wire shape transcribed
verbatim from architecture doc section 6.2 (`AgentControl`, `AgentMessage`,
`ControllerMessage`, `ApplyResult.Status.APPLIED`, `Terminate.Reason.UNKNOWN`,
etc.). The prompt requires the field numbers and shapes to match the
architecture doc exactly.

## Decision

`buf.yaml` disables the following `STANDARD` rules, with this ADR as the
explanation a reviewer will find via the comment in `buf.yaml`:

- `SERVICE_SUFFIX`
- `RPC_REQUEST_RESPONSE_UNIQUE`
- `RPC_REQUEST_STANDARD_NAME`
- `RPC_RESPONSE_STANDARD_NAME`
- `ENUM_VALUE_PREFIX`
- `ENUM_ZERO_VALUE_SUFFIX`

All other `STANDARD` rules remain enabled, including field-number and
breaking-change checks (`buf.yaml`'s `breaking: use: [FILE]`), which matter
more for a wire protocol than naming style.

## Consequences

- Future `.proto` files added to this module that are *not* constrained by
  an existing architecture-doc transcription should follow the standard
  naming conventions; these exceptions apply repo-wide today only because
  there is a single proto package.
