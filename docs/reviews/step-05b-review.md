# Architect review: step 5b (origin/main @ 440b7a0)

Reviewer: architect · Date: 2026-11-25 · Verdict: **Step 5b accepted.** No blocking
findings. One low follow-up (R5B-1) and answers to the three open questions are carried
into step 6a. ADRs 0029 and 0030 are Accepted. R5A-1 and R5A-2 are closed.

Review method: code reading, plus Devin's ci, integration and TPM runs on 440b7a0.

## Verified by reading

- **R5A-1 closed.** relayd uses a persistent SRK found only at the TCG standard handle
  (adopted only if its public template matches exactly) or the project handle (never
  overwritten if occupied by anything else). The NV counter uses its own authorization.
  Owner authorization appears only in `relay-probe --provision-tpm`.
- **R5A-2 closed.** The citation now points to TCG Part 1 Rev 01.59 §37.2.6.3.
- **Server authentication (internal/controlclient).** `InsecureSkipVerify` plus a
  `VerifyConnection` that performs the full chain verification (controller CA roots,
  ExtKeyUsageServerAuth), exactly one URI SAN equal to the configured controller SPIFFE
  ID, TLS 1.3 and an allowed cipher suite. This is the standard SPIFFE pattern and is
  acceptable. Finding that grpc-go fills `ServerName` from the dial target was a good catch.
- **Session resumption** is disabled (`SessionTicketsDisabled`, no client session cache).
- **Enrollment boundary.** `Enroller` takes a CSR and returns a chain; it can never carry
  a private key (ADR 0030).
- **docs/server-contract.md** is accurate on the points checked, and correctly tells the
  backend team not to rely on the agent for cipher-suite policy.

## Answers to the open questions

1. **Source of `host_uuid`.** Step 6a adds a config loader. `host.uuid` is a required field
   of `/etc/tetragon-relay/relay.yaml`, written by the provisioning pipeline (Satellite or
   kickstart). It is not sourced from host facts and not stored in TPM NV for now. It must be
   a canonical lowercase UUID. A local change cannot impersonate another host: the
   enrolled certificate's URI SAN binds the UUID, and the controller binds it to inventory
   and the switch port. `config_digest` is the SHA-256 of the exact relay.yaml bytes.
2. **Go's crypto/tls with `VerifyConnection`.** Acceptable long-term; stay on the standard
   library. TLS 1.3 suites are all AEAD. In FIPS 140-3 mode Go limits TLS 1.3 to the
   AES-GCM suites, so the post-handshake check is defense in depth there. Record this in an
   ADR (Accepted) and close the question.
3. **`seq` numbering.** Pin it: in each direction, the first message on a stream has
   `seq = 1` and every following message is exactly the previous plus 1. Any other value
   is a protocol error: the receiver closes the stream (the agent with backoff; the
   gateway with `Terminate{PROTOCOL_ERROR}`). Update `docs/server-contract.md` and add an
   ADR.

## R5B-1 [LOW] Inject the clock into server certificate verification

`VerifyConnection` calls `leaf.Verify` with a zero `CurrentTime`, so validity is checked
against the wall clock, and certificate-validity edges cannot be tested deterministically.
Take the time from the injected clock the rest of the package uses, and add boundary tests
(not yet valid, just expired).

## Customer actions (unchanged)

- Run `scripts/e2e-rhel9.sh` (including its TPM section) on the RHEL 9 test server.
- Decide the enrollment system (SPIRE or IdM). Under ADR 0030, it must certify the
  TPM-held key from a CSR.
- Hand `docs/server-contract.md` to the backend team.
