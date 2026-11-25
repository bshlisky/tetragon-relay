# tetragon-relay — new session: Step 5b (TPM owner-auth fix, enrollment interface, mTLS client, server contract)

You are continuing an existing, security-critical project for an enterprise customer.
You have no memory of earlier sessions; the repository is the source of truth.

Repo: https://github.com/bshlisky/tetragon-relay (branch main). Clone it fresh.

## Binding context
- The working agreement, environment rules and "Read these before writing any code" list
  in docs/prompts/step-04b.md (Part 0) apply unchanged, including the session-size rule.
- Read docs/architecture.md sections 3.2 (flows), 5 (identity and PKI), 6.1 (TLS profile),
  6.3 (session lifecycle), 6.5 (controller-side protections), 11.4 (port binding);
  docs/reports/step-05a.md; ADRs 0026–0028; and the attached review.
- Current state: steps 1–5a are accepted at 94ab501. internal/tpm provides a non-exportable
  HostSigner (crypto.Signer), a KeySealer and a MonotonicCounter, all tested on swtpm.

## Two project decisions that shape this step
1. **The server side is not built in this repository.** The customer's existing backend
   (the policy UI's server) implements the controller's stream gateway, the signer and
   the collector. This repository builds the agent, plus a minimal test server used only
   in CI, plus a written contract the backend team implements against (Part D).
2. **The enrollment system is undecided** (SPIRE with TPM attestation, or Red Hat
   IdM/FreeIPA). Build against an interface with a test CA implementation. The real
   enroller is a later, small step. Do not pick or integrate SPIRE or IdM in this step.

## First actions
1. Two files are ATTACHED: this prompt and step-05a-review.md. Commit them verbatim in one
   commit ("docs: add step 5a review and step 5b prompt"):
   - docs/reviews/step-05a-review.md
   - docs/prompts/step-05b.md
2. Run `make ci` from a clean clone; confirm green.
3. Acknowledge with ≤ 12 bullets: the plan for Parts A–E.

## Part A — Step 5a review follow-ups (first; one commit each; tests each)
A1. R5A-1: relayd must never use TPM owner authorization. Write the ADR first (Proposed);
    stop and ask if anything conflicts. Provisioning (root) creates a persistent SRK and
    defines the NV counter with its own authorization; relayd uses only those. Tests on
    swtpm with an owner password set after provisioning. Full requirements are in the
    review.
A2. R5A-2: replace the book citation with the TCG TPM 2.0 Library Specification section
    (version and section number), or state that the exact text could not be confirmed.

## Part B — Enrollment interface and host identity (new package internal/identity)
B1. Interface:
      type Enroller interface {
          // Enroll exchanges proof of identity plus a CSR signed by the TPM HostSigner
          // for a certificate chain. It never receives or generates a private key.
          Enroll(ctx context.Context, csr []byte) (chain []*x509.Certificate, err error)
      }
    Every implementation must certify the TPM-held key from a CSR. Any enrollment design
    that would issue a software-generated private key (for example a stock SPIRE Workload
    API SVID) is out of bounds; record this as a constraint in an ADR, because it decides
    how SPIRE or IdM is integrated later.
B2. Certificate manager:
    - Builds a CSR with the HostSigner. The subject and SANs come from config: a SPIFFE-
      style URI SAN `spiffe://<trust-domain>/host/<host-uuid>`, no DNS SANs. The host UUID
      comes from the existing host facts or config (cite where it comes from today); never
      from the hostname.
    - Validates the returned chain: leaf public key equals the HostSigner's public key;
      URI SAN equals the expected identity; EKU clientAuth; validity window sane (not
      before now − skew, not after the configured maximum TTL); chain verifies to the
      configured enrollment trust bundle. Anything else is rejected.
    - Renews at 50% of lifetime with full-jitter backoff on failure (base 10 s, cap 5 min).
      Reports "expiring soon" (under 15 minutes left) so the state machine can enter
      DEGRADED later (step 6).
    - Persists only the certificate chain (public) in the store directory; the key stays
      in the TPM.
    - Rotation: uses 5a's key-rotation primitive on a configured interval (default 7 days).
      A new key requires a new enrollment; the old key is retired only after the new
      certificate is in use.
B3. Test enroller (build tag `testca`, never in production builds): a small in-process
    CA with a one-time join token, for unit and integration tests.

## Part C — mTLS client (package internal/controlclient, transport only)
C1. TLS profile, per architecture 6.1:
    - TLS 1.3 only. Cipher suites TLS_AES_256_GCM_SHA384 and TLS_AES_128_GCM_SHA256.
      Groups from config, defaulting to secp384r1 and secp256r1. Groups are a config
      list so hybrid ML-KEM groups can be enabled later without code changes (PQC is
      deferred; do NOT enable ML-KEM groups by default; ADR 0022's not-yet-agile list
      applies).
    - Client certificate: the enrolled chain, signed through the TPM HostSigner.
    - Server authentication: verify the chain to the configured controller CA bundle AND
      require that the server certificate's URI SAN exactly equals the configured
      controller SPIFFE ID. Hostname verification is not used. Implement this with
      VerifyConnection, not InsecureSkipVerify plus custom code, unless you document why.
    - No session resumption (no session tickets, no client session cache) and no 0-RTT.
    - Pinned endpoints from config (IP:port list); DNS is not used.
C2. Connection management: dial with full-jitter exponential backoff (1 s base, 5 min
    cap), HTTP/2 keepalive PING every 30 s with a 10 s timeout, and the size limits from
    6.1 on the client side. Expose a Connect API that returns a gRPC client connection to
    AgentControl; implement only the Hello/HelloAck exchange in this step. The full message
    loop, heartbeats and bundle handling are step 6.
C3. Hello content: fill every field of the Hello message (control.proto) that existing
    components can already supply (host UUID, versions, boot ID, per-scope epochs, loaded
    digest, LKG digest, trust root digest and version, config digest). Leave the PCR quote
    empty (remote attestation is a later step). List every field and its source in the
    report.

## Part D — Server contract for the backend team (docs/server-contract.md)
A standalone document the customer's backend engineers implement against, derived from
the architecture and this repo's code (cite file:line for every protocol detail):
- the AgentControl gRPC service and messages, with field-by-field semantics
- the TLS profile the gateway must use, including its SPIFFE ID and the client checks it
  must perform (architecture 6.3 steps 1–2: chain, URI SAN, denylist, inventory state,
  source-IP binding)
- controller-side limits and behaviors (6.5): one stream per identity, rate limits, seq
  monotonicity, message size caps, Terminate reasons
- the bundle and trust-root formats (envelope, payload, root metadata, keytypes,
  require_keytypes), with the signer's obligations (architecture 7.2 steps 4–7) and the
  rule that the gateway forwards bundles verbatim and never constructs envelopes
- what the agent will reject and the ApplyResult codes it returns
- an explicit "what the agent trusts the server for, and what it does not" section
- a conformance checklist the backend can test against, and a pointer to the test server
  (Part E2) as a reference implementation of the handshake only

## Part E — Tests
E1. Unit: CSR contents; every chain-validation rejection (wrong key, wrong URI SAN, extra
    or missing SANs, wrong EKU, expired, not yet valid, unknown issuer); renewal timing
    with an injected clock; rotation sequencing; TLS config assertions (versions, suites,
    groups, no tickets).
E2. Test server (cmd/testcontroller, build tag `testserver`): implements only TLS, client
    certificate checks per 6.3 and Hello/HelloAck. Used in CI. Its README says it is not a
    production controller.
E3. Integration (CI, swtpm): enroll via the test CA with a TPM-held key; connect to the
    test server; complete Hello/HelloAck. Negative cases: the server presents the wrong
    SPIFFE ID (client refuses); the client's certificate is for another host UUID (server
    refuses); the server attempts TLS 1.2 (refused); an expired client certificate.
E4. Coverage ≥ 90% for internal/identity and internal/controlclient.

## Out of scope
SPIRE or IdM integration, PCR quotes and remote attestation, the full control message loop
(step 6), telemetry (step 7), the production controller or gateway, PQC key exchange.

## Definition of done
ci, integration and the TPM job green on GitHub for the final commit.

## Report: docs/reports/step-05b.md (also paste it in your final message)
Sections 1–10 as in previous steps, plus:
11. Hello field-by-field source table (C3).
12. Integration evidence for E3, including each negative case's observed error.
13. Open questions for the customer, if any, separate from questions for the architect.
