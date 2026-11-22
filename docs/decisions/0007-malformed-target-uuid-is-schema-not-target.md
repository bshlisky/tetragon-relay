# ADR 0007: A malformed entry in `targets.host_uuids` is REJECTED_SCHEMA, not REJECTED_TARGET

## Status

Accepted.

## Context

Architecture doc section 7.4 step 6 says: "host.uuid in p.targets.host_uuids
(exact, case-sensitive string compare after validating UUID format) else
REJECTED_TARGET." It does not say what happens if an entry *in* the list
fails UUID-format validation, only that validation happens before the
compare.

## Decision

Per the "implement the safest interpretation, the one that rejects more"
rule, any entry in `targets.host_uuids` that is not a well-formed UUID
causes `REJECTED_SCHEMA` (treated as a structurally invalid payload), rather
than being silently skipped (which could let an attacker pad the list with
garbage without consequence) or causing `REJECTED_TARGET` only when it
happens to be the host's own match (which would make a malformed-but-present
target entry behave differently depending on unrelated list contents).

The host's own UUID (`Input.HostUUID`) failing format validation is treated
the same way — `REJECTED_SCHEMA` — since a local configuration or caller
contract violation, not an authorization fact about the bundle, is the
actual problem.

## Consequences

- A bundle targeting host A correctly but with one malformed entry elsewhere
  in `host_uuids` (e.g. a typo for host B) is rejected outright rather than
  accepted for host A. This is the conservative choice and is covered by
  `TestVerify_MalformedTargetUUID` and `TestVerify_LocalHostUUIDMalformed`
  in `internal/verify`.
- Flagged as an open question for the architect in docs/reports/step-01.md.
