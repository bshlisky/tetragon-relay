# tetragon-relay — new session: Step 6a (config loader, relayd assembly, state machine, control loop)

You are continuing an existing, security-critical project for an enterprise customer.
You have no memory of earlier sessions; the repository is the source of truth.

Repo: https://github.com/bshlisky/tetragon-relay (branch main). Clone it fresh.

## Binding context
- The working agreement, environment rules and "Read these before writing any code" list
  in docs/prompts/step-04b.md (Part 0) apply unchanged, including the session-size rule.
- Read docs/architecture.md sections 6 (control channel), 8.1–8.6 (agent spec), 10.4
  (signals), docs/server-contract.md, docs/reports/step-05b.md and the attached review.
- Current state: steps 1–5b are accepted at 440b7a0. Every agent component exists
  (verify, guard, apply, store, tpm, identity, controlclient), but cmd/relayd's main only
  prints its version, and the control stream stops after Hello/HelloAck.
- Step 6 is split. 6a (this session) builds the running agent: config, assembly, the state
  machine and the control message loop without bundle handling. 6b (later) adds
  PolicyBundle and TrustUpdate handling end to end, the reconcile schedule, drift
  detection and alerts.

## First actions
1. Two files are ATTACHED: this prompt and step-05b-review.md. Commit them verbatim in one
   commit ("docs: add step 5b review and step 6a prompt"):
   - docs/reviews/step-05b-review.md
   - docs/prompts/step-06a.md
2. Run `make ci` from a clean clone; confirm green.
3. Acknowledge with ≤ 12 bullets: the plan for Parts A–E.

## Part A — Step 5b review follow-ups (first; one commit each; tests each)
A1. R5B-1: inject the clock into server certificate verification; boundary tests.
A2. Q2: ADR (Accepted) recording that Go's crypto/tls with VerifyConnection is the
    long-term choice, with the reasoning in the review.
A3. Q3: pin seq numbering (start at 1, exactly +1, else protocol error). ADR; update
    docs/server-contract.md; the agent enforces it on inbound messages; the test server
    enforces it on agent messages.

## Part B — Config loader (new package internal/config)
B1. Source: /etc/tetragon-relay/relay.yaml (path from the --config flag). Before reading,
    check: regular file, not a symlink, owner root, group tetragon-relay, mode at most
    0640. Refuse otherwise.
B2. Parsing: reuse the hardened YAML ingestion already in internal/policydoc. Extract it
    into a shared internal package rather than duplicating it, with no behavior change to
    policydoc (prove that with the existing tests). The schema is closed: unknown keys are
    errors.
B3. Schema: start from architecture 8.5's example and the components' existing Config
    structs. Required fields have no defaults: host.uuid (canonical lowercase UUID),
    host.allowed_scopes, controller endpoints and SPIFFE ID, collector endpoints and SPIFFE
    ID (unused until step 7, but validated), identity trust domain and enrollment trust
    bundle path, tetragon socket path and persist directory. Every security-relevant
    setting uses a name whose zero or absent value is the secure behavior. Fields that
    would relax a security check (for example `allow_selinux_disabled`) require an
    explicit value and produce a loud startup audit record when set.
B4. config_digest = SHA-256 of the exact bytes read. It goes into Hello.
B5. Tests: every validation rule; permission and ownership refusals; fuzz target
    FuzzConfig in the CI smoke and nightly workflows.

## Part C — relayd assembly (cmd/relayd and internal/agent)
C1. relayd main: parse flags (--config only, plus --version), load config, then run the
    startup sequence. Order: crypto self-test, host facts (refuse enforcement bundles if
    missing or stale, as today), TPM components, store open, trust root, LKG
    re-verification, Tetragon client (peer verification), apply engine, certificate
    manager, control client. Each stage that fails puts the agent in the state the
    architecture defines (8.3), never a crash loop that skips checks.
C2. Enrollment in production builds: no production Enroller exists yet (the customer is
    choosing SPIRE or IdM). A production build of relayd must start, enforce LKG,
    keep reconcile ready (6b) and stay in UNENROLLED with a clear audit record. It must
    not fall back to any test enroller. The test CA remains available only under its build
    tag, for CI.
C3. TPM device: production builds accept only /dev/tpmrm0. Any alternative transport
    (swtpm) is available only under a test build tag.
C4. sd_notify READY once startup completes; watchdog keepalive every half of WatchdogSec
    (30 s in the unit); clean shutdown on SIGTERM (close the stream, flush the store, never
    unload Tetragon policies).

## Part D — State machine and control loop (internal/agent)
D1. Implement the states and transitions of architecture 8.3 as an explicit, table-driven
    state machine: UNENROLLED, ENROLLING, CONNECTING, SYNCING, STEADY, APPLYING (6b),
    ROLLBACK (6b), DRIFT (6b), DEGRADED, REVOKED. Every transition is logged as an audit
    record. A test asserts that every state keeps the LKG enforcing (no transition calls
    anything that unloads Tetragon policies).
D2. Control loop:
    - Hello with every field that has a source (now including host_uuid and
      config_digest from Part B); HelloAck nonce handling (PCR quote stays empty).
    - Heartbeat every 15 s: epochs, loaded digest, Tetragon health. Telemetry fields stay
      zero until step 7.
    - StateRequest: reply with a StateReport echoing the request's nonce.
    - RotateIdentity: trigger the certificate manager's rotation.
    - Terminate: handle every reason; REVOKED stops reconnecting until operator
      re-enrollment (the Reenroller interface from ADR 0023).
    - PolicyBundle and TrustUpdate: in 6a, respond with an ApplyResult or Alert that says
      the agent does not yet process them, without touching state. 6b implements them.
    - Inbound validation: seq rules (A3), message size caps, unknown message types close
      the stream. The agent never executes anything not in the closed message set.
    - Expiring certificate (under 15 minutes left) puts the agent in DEGRADED.
D3. Reconnect: full-jitter backoff as specified in 5b; enter DEGRADED after 5 minutes
    without a stream.

## Part E — Tests
E1. Unit tests for the state machine (every transition, including forbidden ones) and
    for each message handler.
E2. Test server: extend cmd/testcontroller so it can drive scripted sequences (heartbeat
    expectations, StateRequest, RotateIdentity, every Terminate reason, out-of-order
    seq, oversize messages, unknown types).
E3. Integration (CI): run relayd as a real process under the production systemd unit's
    sandbox settings (same User=, empty capabilities, ProtectSystem=strict,
    ReadWritePaths, ProtectProc=invisible), with swtpm through the test build tag, against
    real Tetragon and the test controller. Scenarios: clean start to STEADY with
    heartbeats arriving; Terminate{REVOKED} stops reconnecting; controller unavailable
    leads to DEGRADED after the threshold while Tetragon keeps enforcing; SIGTERM leaves
    Tetragon's loaded policies unchanged; a production build (no test tags) starts, stays
    UNENROLLED and still enforces LKG.
E4. Coverage ≥ 90% for internal/config and internal/agent.

## Out of scope
PolicyBundle and TrustUpdate processing, reconcile scheduling, drift alerts (6b);
telemetry (7); the SELinux module, RPM and final packaging (8); a production Enroller.

## Definition of done
ci, integration and TPM jobs green on GitHub for the final commit.

## Report: docs/reports/step-06a.md (also paste it in your final message)
Sections 1–10 as in previous steps, plus:
11. The complete relay.yaml schema, with each field's validation and its secure default.
12. State transition table as implemented, with the test covering each transition.
13. E3 integration evidence per scenario.
