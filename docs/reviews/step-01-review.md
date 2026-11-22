# Architect review of step 1

ADRs 0002, 0003, 0006, 0007, 0008 are approved; 0004 is approved with the
amendments below; 0005 is superseded by A8. Open question 1: docs/architecture.md
is the source of truth from now on.

A1. [CRITICAL] Case-insensitive key matching in internal/strictjson.
    encoding/json matches struct fields case-insensitively (including Unicode folding:
    "ſcope" → scope, "\u212Aeyid" (Kelvin sign) → keyid). The duplicate-key pass compares
    exactly, so {"scope":"dev","SCOPE":"prod-db"} passes and decodes as prod-db.
    Fix: DecodeStrict must verify, before decoding, that every object key EXACTLY equals
    a json tag of the target struct at that level (reflection-based walker over the
    token stream or a UseNumber generic decode; map[string]T fields accept any key but
    still exact-duplicate-checked). Additionally reject any object in which two keys are
    equal under Unicode simple case folding (strings.EqualFold), even for map fields.
    Regression tests and new vectors for envelope, bundle and root payloads:
    "SCOPE", "Scope", "ſcope", "\u212Aeyid", "payloadtype", "PayloadType".
    Add a fuzz property: if DecodeStrict succeeds, re-marshalling the result and
    comparing the key set to the input's key set must match exactly.

A2. [CRITICAL] Nil Guardrails fails open. Verify must return REJECTED_GUARDRAIL when
    Input.Guardrails is nil. Tests that need "no guardrails" use an explicit
    allow-all fake declared only in _test.go files.

A3. [HIGH] Validate mode. bundle.mode must be exactly "monitor" or "enforce"
    (case-sensitive) else REJECTED_SCHEMA, checked in step 5 with the other schema checks.
    Vectors: "", "ENFORCE", "audit".

A4. [HIGH] Signature count DoS.
    - limits.MaxSignaturesPerEnvelope = 16, enforced in dsse.ParseEnvelope
    - duplicate keyid values within one envelope's signatures → envelope rejected
      (REJECTED_SCHEMA for bundles, ErrMalformedMetadata for roots). Update the
      duplicate_signature_same_key_threshold2 vector's expected code and README.
    - verifyRoleThreshold attempts each key ID at most once
    - benchmark: worst-case envelope verify time must be < 50 ms; record it

A5. Validity window. In step 9 also require expires > not_before, and
    expires - not_before ≤ limits.MaxBundleValidity = 90 days, else REJECTED_SCHEMA.
    Add boundary-exact vectors: now == not_before - 300s (accept),
    now == not_before - 301s (reject), now == expires + 299s (accept),
    now == expires + 300s (reject).

A6. Trust-root hardening (amends ADR 0004; update the ADR):
    - root, targets and log roles must use pairwise disjoint key sets
    - root metadata validity ≤ 400 days from now at Update time, and initial root
      expires - (time it was loaded) is reported but not enforced (it ships in the RPM)
    - Root becomes immutable: unexport Keys/Roles or return copies from accessors
    Vectors: targets key also in root role; root expiring in 5 years.

A7. Canonical inputs (REJECTED_SCHEMA unless noted):
    - policy sha256 must be exactly 64 lowercase hex chars (remove ToLower)
    - host UUIDs (local and targets) must be lowercase canonical form
    - policy version 1 ≤ v ≤ 2^31-1
    - bundle_id ≤ 128 bytes, ^[A-Za-z0-9._-]+$
    - epoch ≤ current + limits.MaxEpochJump (1,000,000) else REJECTED_EPOCH
      (prevents a single signed epoch near 2^64 from bricking a scope)

A8. Proto: define the messages exactly as below (ADR 0005 is superseded; write ADR 0010).
    The proto is unreleased, so change field types freely now; afterwards set the buf
    breaking-change baseline to this commit and record the SHA in the report.

  message Hello {           // replace current_epoch with per-scope epochs
    ... keep fields 1–6 ...
    map<string, uint64> epochs = 7;      // scope -> current epoch
    ... keep 8–12 ...
    bytes config_digest = 13;            // sha256 of relay.yaml (section 8.5)
  }
  message Heartbeat {
    map<string, uint64> epochs = 1;
    bytes loaded_digest = 2;
    TetragonHealth health = 3;
    uint64 telemetry_last_seq = 4;
    uint32 telemetry_backlog = 5;
  }
  message HelloAck      { bytes nonce = 1;  /* exactly 32 bytes */
                          uint32 heartbeat_interval_seconds = 2; }
  message PolicyBundle  { bytes envelope = 1; }   // raw DSSE bytes, ≤ 1 MiB, never re-encoded
  message TrustUpdate   { repeated bytes signed_roots = 1; } // ordered N+1..M, each verified
                                                             // against its predecessor
  message StateRequest  { bytes nonce = 1; }
  message StateReport   { bytes nonce = 1;
                          map<string, uint64> epochs = 2;
                          bytes loaded_digest = 3;
                          bytes lkg_bundle_digest = 4;
                          repeated LoadedPolicy policies = 5;
                          TetragonHealth health = 6; }
  message LoadedPolicy  { string name = 1; string state = 2; bool enabled = 3;
                          bytes canonical_sha256 = 4; }
  message TetragonHealth{ bool serving = 1; string version = 2;
                          uint64 process_start_time_unix = 3;
                          uint32 restarts_since_boot = 4; string detail = 5; }
  message RotateIdentity{ string reason = 1; }
  message Terminate     { enum Reason { REASON_UNSPECIFIED = 0; REVOKED = 1;
                          DUPLICATE_SESSION = 2; PROTOCOL_ERROR = 3; SHUTDOWN = 4; }
                          Reason reason = 1; string detail = 2; }
  message Alert         { enum Kind { KIND_UNSPECIFIED = 0; DRIFT = 1;
                          TETRAGON_UNHEALTHY = 2; TRUST_EXPIRED = 3; TAMPER = 4;
                          GUARDRAIL_REJECT = 5; }
                          Kind kind = 1; string detail = 2; int64 unix_time = 3; }
  ApplyResult.Status: add REJECTED_CAPABILITY = 9 (see Part C, G8).

A9. CI hardening:
    - reproducible build: build in two different temp directories, each with its own
      fresh GOCACHE and GOPATH, then cmp
    - add `go mod verify` and a vendor drift check (`go mod vendor && git diff --exit-code vendor/`)
    - coverage gate ≥ 95% also for internal/dsse and internal/strictjson
    - pin the runner to ubuntu-24.04
    - enrich the FuzzRootUpdate seed corpus (vary key counts, role shapes, thresholds)
      so it runs > 10,000 execs in 60 s; record the count

A10. Report accuracy: fix the Go version statement (go.mod says go 1.26.0). From now on
     the report's facts must be generated from the repo (paste command output), not
     written from memory.

Report section 14 for step 2 must list each A-item with its commit SHA and test names.
