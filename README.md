# Secure Management Plane for Tetragon

A secure management plane that pushes Tetragon `TracingPolicy` bundles to RHEL 9
hosts and receives their security telemetry, with a Cisco N9300 Smart Switch
(Hypershield) acting as a host-independent, top-of-rack enforcer.

## Status

Early stage. The architecture is specified in
[`docs/security-architecture.md`](docs/security-architecture.md); implementation
has not started yet. The first component to be built is the on-host **relay
agent** (`relayd`), the single, unprivileged Go binary that is the only
permitted caller of the local Tetragon gRPC socket (see Section 8 of the
architecture doc).

## Repository layout

```
docs/                  Design and architecture documentation
cmd/relayd/            Entry point for the relay agent binary (scaffold only)
internal/              Relay agent implementation packages (to be built out)
```

## Design summary

- **Host-local lockdown** — Tetragon listens only on a unix socket; the relay
  agent is the sole permitted caller (DAC + SELinux).
- **Hardware-rooted identity and mTLS** — each host holds a TPM-resident key
  and a short-lived X.509-SVID; hosts never accept inbound management
  connections.
- **Policy supply chain integrity** — bundles require two-person approval and
  are signed by an isolated, HSM-backed signer; the controller can deliver
  policy but cannot authorize it.
- **Telemetry separation** — telemetry is a one-way, hash-chained stream to a
  collector with no ability to send control messages back to a host.
- **Network enforcement outside the host's trust domain** — the N9300 DPU
  enforces segmentation per switch port and quarantines hosts on controller
  command.

See the full specification in [`docs/security-architecture.md`](docs/security-architecture.md)
for the threat model, trust boundaries, protocol definitions, and operational
procedures.

## Out of scope

- Policy-authoring UI implementation (it already exists elsewhere)
- Detection content (which TracingPolicies to write)
- SIEM correlation logic and analytics storage sizing
- Kubernetes deployments of Tetragon
