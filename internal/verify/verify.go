package verify

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

func reject(code Code, reason string) Result {
	return Result{Code: code, Reason: boundReason(reason)}
}

// Verify implements architecture doc section 7.4 exactly. Checks are
// evaluated in the fixed order below; the first failing check determines
// the result and no later check is consulted. Verify never panics and
// performs no I/O.
func Verify(in Input) Result {
	// Step 1: size(envelope) <= 1 MiB, before any parsing.
	if len(in.Envelope) > limits.MaxEnvelopeBytes {
		return reject(CodeRejectedSchema, "envelope exceeds maximum size")
	}

	// Steps 2 (payloadType) and the envelope-level parsing that step 2
	// requires (extracting payloadType itself needs a parsed envelope).
	// Any envelope-level structural failure is also REJECTED_SCHEMA: the
	// algorithm has no other code available before signature
	// verification (step 3) can even be attempted.
	env, err := dsse.ParseEnvelope(in.Envelope, limits.MaxEnvelopeBytes, limits.MaxJSONDepth)
	if err != nil {
		return reject(CodeRejectedSchema, "malformed envelope")
	}
	if env.PayloadType != BundlePayloadType {
		return reject(CodeRejectedSchema, "unexpected payload type")
	}

	// Step 3: signature valid under a key in the targets role, threshold
	// satisfied. An unobtainable trust Verifier (e.g. expired root
	// metadata) is treated the same as a failed signature check: there
	// is no key the agent currently trusts to evaluate against.
	if in.Trust == nil {
		return reject(CodeRejectedSignature, "no trust verifier configured")
	}
	if err := in.Trust.Verify(env); err != nil {
		return reject(CodeRejectedSignature, "signature verification failed")
	}

	// Step 4: transparency-log inclusion proof, if required. Proof
	// verification is not implemented in this step (see
	// docs/reports/step-01.md, Open questions); per the "no silent
	// fallbacks" rule, a root that requires it causes rejection rather
	// than silently skipping the check.
	if in.Trust.RequireLogProof() {
		return reject(CodeRejectedSignature, "log inclusion proof required but not supported")
	}

	// Step 5: parse payload with the strict decoder.
	var bp bundlePayload
	if err := strictjson.DecodeStrict(env.Payload, limits.MaxJSONDepth, &bp); err != nil {
		return reject(CodeRejectedSchema, "malformed bundle payload")
	}
	if bp.Schema != BundleSchema {
		return reject(CodeRejectedSchema, "unexpected bundle schema")
	}
	if bp.BundleID == "" || bp.Scope == "" {
		return reject(CodeRejectedSchema, "missing bundle_id or scope")
	}
	if len(bp.BundleID) > limits.MaxBundleIDBytes || !limits.BundleIDPattern.MatchString(bp.BundleID) {
		return reject(CodeRejectedSchema, "invalid bundle_id")
	}
	if bp.Mode != "monitor" && bp.Mode != "enforce" {
		return reject(CodeRejectedSchema, "invalid mode")
	}
	for _, u := range bp.Targets.HostUUIDs {
		if !validUUID(u) {
			return reject(CodeRejectedSchema, "malformed target host UUID")
		}
	}

	// Step 6: host.uuid in p.targets.host_uuids.
	if !validUUID(in.HostUUID) {
		return reject(CodeRejectedSchema, "local host UUID is malformed")
	}
	targeted := false
	for _, u := range bp.Targets.HostUUIDs {
		if u == in.HostUUID {
			targeted = true
			break
		}
	}
	if !targeted {
		return reject(CodeRejectedTarget, "host not in bundle targets")
	}

	// Step 7: p.scope in host.allowed_scopes.
	scopeAllowed := false
	for _, s := range in.AllowedScopes {
		if s == bp.Scope {
			scopeAllowed = true
			break
		}
	}
	if !scopeAllowed {
		return reject(CodeRejectedTarget, "scope not in host's allowed scopes")
	}

	// Step 8: p.epoch > state.current_epoch(p.scope). An error from the
	// epoch source is always a rejection, never an accept.
	if in.Epochs == nil {
		return reject(CodeRejectedEpoch, "no epoch source configured")
	}
	currentEpoch, err := in.Epochs.Current(bp.Scope)
	if err != nil {
		return reject(CodeRejectedEpoch, "epoch source error")
	}
	if bp.Epoch <= currentEpoch {
		return reject(CodeRejectedEpoch, "epoch not greater than current")
	}
	// A single signed bundle with an epoch far beyond the current one
	// would permanently brick the scope (every future bundle would need
	// an epoch higher still); bound how far ahead one bundle may jump.
	// Step 1 review A7.
	if bp.Epoch-currentEpoch > limits.MaxEpochJump {
		return reject(CodeRejectedEpoch, "epoch jump exceeds maximum")
	}

	// Step 9: now >= not_before - skew and now < expires + skew. Missing
	// timestamps are schema failures, not expiry failures: a zero-value
	// time.Time cannot have been a deliberate, meaningful not_before or
	// expires. expires must be strictly after not_before, and the window
	// between them must be bounded (step 1 review A5): an unbounded
	// validity window defeats the purpose of having one at all.
	if bp.NotBefore.IsZero() || bp.Expires.IsZero() {
		return reject(CodeRejectedSchema, "missing not_before or expires")
	}
	if !bp.Expires.After(bp.NotBefore) {
		return reject(CodeRejectedSchema, "expires must be after not_before")
	}
	if bp.Expires.Sub(bp.NotBefore) > limits.MaxBundleValidity {
		return reject(CodeRejectedSchema, "validity window exceeds maximum")
	}
	skew := limits.ClockSkew
	if in.Now.Before(bp.NotBefore.Add(-skew)) {
		return reject(CodeRejectedExpired, "bundle not yet valid")
	}
	if !in.Now.Before(bp.Expires.Add(skew)) {
		return reject(CodeRejectedExpired, "bundle expired")
	}

	// Step 10: tetragon_version >= p.tetragon_min_version.
	if bp.TetragonMinVersion == "" {
		return reject(CodeRejectedSchema, "missing tetragon_min_version")
	}
	minVersion, err := parseSemver(bp.TetragonMinVersion)
	if err != nil {
		return reject(CodeRejectedSchema, "invalid tetragon_min_version")
	}
	runningVersion, err := parseSemver(in.TetragonVersion)
	if err != nil {
		return reject(CodeRejectedSchema, "invalid running Tetragon version")
	}
	if compareSemver(runningVersion, minVersion) < 0 {
		return reject(CodeRejectedSchema, "running Tetragon version too old")
	}

	// Step 11: per-policy hash and schema validation.
	if len(bp.Policies) == 0 || len(bp.Policies) > limits.MaxPoliciesPerBundle {
		return reject(CodeRejectedSchema, "policy count out of bounds")
	}
	seenNames := make(map[string]struct{}, len(bp.Policies))
	policies := make([]Policy, 0, len(bp.Policies))
	for _, p := range bp.Policies {
		if len(p.YAML) > limits.MaxPolicyYAMLBytes {
			return reject(CodeRejectedSchema, "policy YAML exceeds size limit")
		}
		if !limits.PolicyNamePattern.MatchString(p.Name) {
			return reject(CodeRejectedSchema, "invalid policy name")
		}
		if _, dup := seenNames[p.Name]; dup {
			return reject(CodeRejectedSchema, "duplicate policy name")
		}
		seenNames[p.Name] = struct{}{}

		if p.Version < limits.MinPolicyVersion || p.Version > limits.MaxPolicyVersion {
			return reject(CodeRejectedSchema, "policy version out of bounds")
		}

		// The declared digest must already be canonical: exactly 64
		// lowercase hex characters. Normalizing case ourselves (e.g.
		// strings.ToLower) would accept a non-canonical declaration as
		// if it were equivalent, which is exactly the kind of
		// canonicalization gap step 1 review A7 closes.
		if !limits.PolicySHA256Pattern.MatchString(p.SHA256) {
			return reject(CodeRejectedSchema, "policy sha256 is not canonical lowercase hex")
		}
		sum := sha256.Sum256([]byte(p.YAML))
		got := hex.EncodeToString(sum[:])
		if got != p.SHA256 {
			return reject(CodeRejectedSchema, "policy YAML hash mismatch")
		}

		policies = append(policies, Policy(p))
	}

	// Step 12: guardrails, called last and only on an otherwise-valid
	// bundle. A nil Guardrails is a configuration failure, not "no
	// guardrails required": it must fail closed (step 1 review A2),
	// never silently accept. Callers that genuinely want no guardrail
	// restrictions must supply an explicit allow-all implementation.
	if in.Guardrails == nil {
		return reject(CodeRejectedGuardrail, "no guardrails configured")
	}
	if err := in.Guardrails.Check(policies); err != nil {
		return reject(CodeRejectedGuardrail, "guardrail check failed")
	}

	return Result{
		Code: CodeAccept,
		Bundle: &Bundle{
			BundleID:           bp.BundleID,
			Epoch:              bp.Epoch,
			Scope:              bp.Scope,
			HostUUIDs:          bp.Targets.HostUUIDs,
			NotBefore:          bp.NotBefore,
			Expires:            bp.Expires,
			TetragonMinVersion: bp.TetragonMinVersion,
			Mode:               bp.Mode,
			Policies:           policies,
			Provenance: Provenance{
				Author:          bp.Provenance.Author,
				Approvers:       bp.Provenance.Approvers,
				ChangeRef:       bp.Provenance.ChangeRef,
				ControllerBuild: bp.Provenance.ControllerBuild,
			},
		},
	}
}
