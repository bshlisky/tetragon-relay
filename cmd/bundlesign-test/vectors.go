//go:build testtools

package main

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/guard"
	"github.com/bshlisky/tetragon-relay/internal/policydoc"
	"github.com/bshlisky/tetragon-relay/internal/testvectors"
	"github.com/bshlisky/tetragon-relay/internal/trust"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// baseNow is the fixed reference time every vector is built and
// self-checked against, so generated fixtures never depend on wall-clock
// time.
var baseNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const (
	stdHost    = "11111111-1111-4111-8111-111111111111"
	otherHost  = "22222222-2222-4222-8222-222222222222"
	stdScope   = "prod-db"
	otherScope = "staging"
)

// fakeEpochSource is a trivial EpochSource for generation-time self-checks.
type fakeEpochSource struct{ current uint64 }

func (f fakeEpochSource) Current(string) (uint64, error) { return f.current, nil }

// allowAllGuardrails is the explicit "no restrictions" fake used so that
// generation-time self-checks of ACCEPT vectors exercise the real
// verify.Verify guardrail step (step 1 review A2: a nil Guardrails now
// fails closed) without unconditionally running the real internal/guard
// engine (some vectors want a deliberate, controllable guard outcome
// instead; see realGuardrails below for those).
type allowAllGuardrails struct{}

func (allowAllGuardrails) Check(guard.GuardContext, []*policydoc.Doc) error { return nil }

// realPolicyParser delegates to the real internal/policydoc.Parse, so
// generated vectors are self-checked against the actual step 2 Part B
// pipeline, not a stand-in.
type realPolicyParser struct{}

func (realPolicyParser) Parse(name, yamlDoc string) (*policydoc.Doc, error) {
	return policydoc.Parse(name, yamlDoc)
}

// realGuardrails delegates to the real internal/guard engine with
// caller-controlled fakes, for vectors that need a genuine guard
// acceptance/rejection rather than the allow-all stub.
type realGuardrails struct {
	caps    guard.HostCapabilities
	history guard.PolicyHistory
}

func (g realGuardrails) Check(ctx guard.GuardContext, docs []*policydoc.Doc) error {
	gr := &guard.Guardrails{Capabilities: g.caps, History: g.history}
	return gr.Check(ctx, docs)
}

type allowAllCapabilities struct{}

func (allowAllCapabilities) KprobeOverride() bool { return true }
func (allowAllCapabilities) LSMBPF() bool         { return true }

type denyOverrideCapabilities struct{}

func (denyOverrideCapabilities) KprobeOverride() bool { return false }
func (denyOverrideCapabilities) LSMBPF() bool         { return false }

type allowAllHistory struct{}

func (allowAllHistory) SeenInMonitor(string, string) (bool, error) { return true, nil }

// validPolicyYAML returns deterministic, padded YAML content of at least
// minBytes: a real, schema-valid, guard-safe TracingPolicy (step 2 Parts
// B/C) with name as its metadata.name, so generated vectors round-trip
// through the real internal/policydoc.Parse + internal/guard pipeline
// (not just internal/verify's own bundle-level checks). The single kprobe
// uses only the observe action Post with no matchBinaries, which needs no
// guardrail scoping at all (G1 only requires matchBinaries for selectors
// carrying an enforcement action), so it passes every guard rule
// trivially; vectors that need to exercise guard rejections build their
// own policy body instead of using this helper (see guardrailRejectYAML /
// capabilityRejectYAML below).
func validPolicyYAML(name string, minBytes int) string {
	base := fmt.Sprintf("apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: %s\nspec:\n  kprobes:\n  - call: \"do_something\"\n    selectors:\n    - matchActions:\n      - action: \"Post\"\n", name)
	if len(base) >= minBytes {
		return base
	}
	pad := strings.Repeat("# pad\n", (minBytes-len(base))/6+1)
	return base + pad
}

// rootBundle holds a built, signed root envelope plus the raw material used
// to build it, for reuse across vectors.
type rootBundle struct {
	envelope []byte
	rootKeys []*testKey
	tgtKeys  []*testKey
	logKeys  []*testKey
}

func buildStandardRoot(version int, expires time.Time, targetsThreshold int, numTargetKeys int, requireLogProof bool) (*rootBundle, error) {
	r1, err := newP384Key()
	if err != nil {
		return nil, err
	}
	r2, err := newP384Key()
	if err != nil {
		return nil, err
	}
	r3, err := newP384Key()
	if err != nil {
		return nil, err
	}
	l1, err := newP384Key()
	if err != nil {
		return nil, err
	}
	tgtKeys := make([]*testKey, 0, numTargetKeys)
	for i := 0; i < numTargetKeys; i++ {
		k, err := newP384Key()
		if err != nil {
			return nil, err
		}
		tgtKeys = append(tgtKeys, k)
	}
	allKeys := append([]*testKey{r1, r2, r3, l1}, tgtKeys...)

	spec := rootSpec{
		version: version,
		expires: expires,
		keys:    allKeys,
		root:    roleOf([]*testKey{r1, r2, r3}, 2),
		targets: roleOf(tgtKeys, targetsThreshold),
		log:     roleOf([]*testKey{l1}, 1),
	}
	payload, err := buildRootPayload(spec)
	if err != nil {
		return nil, err
	}
	// root payload above does not include require_log_proof when false
	// (Go zero value is already false; included explicitly below if true
	// via re-marshal is unnecessary since the field defaults to false.)
	_ = requireLogProof

	env, err := signEnvelope(rootPayloadType, payload, r1, r2)
	if err != nil {
		return nil, err
	}
	return &rootBundle{envelope: env, rootKeys: []*testKey{r1, r2, r3}, tgtKeys: tgtKeys, logKeys: []*testKey{l1}}, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// checkVerify runs the real production code path and fails loudly if the
// generated vector does not produce the expected result. This is the
// generator's own correctness check: no vector is written unless the actual
// internal/trust and internal/verify packages agree with its label.
func checkVerify(v testvectors.Vector) error {
	rootBytes, err := base64.StdEncoding.DecodeString(v.RootMetadataB64)
	if err != nil {
		return fmt.Errorf("%s: decode root: %w", v.Name, err)
	}
	root, err := trust.LoadInitialRoot(rootBytes)
	if err != nil {
		return fmt.Errorf("%s: LoadInitialRoot: %w", v.Name, err)
	}
	now, err := time.Parse(time.RFC3339, v.Now)
	if err != nil {
		return fmt.Errorf("%s: parse now: %w", v.Name, err)
	}

	var tv trust.Verifier
	if ver, err := root.TargetsVerifier(now); err == nil {
		tv = ver
	}

	envBytes, err := base64.StdEncoding.DecodeString(v.EnvelopeB64)
	if err != nil {
		return fmt.Errorf("%s: decode envelope: %w", v.Name, err)
	}

	result := verify.Verify(verify.Input{
		Envelope:        envBytes,
		Now:             now,
		HostUUID:        v.HostUUID,
		AllowedScopes:   v.AllowedScopes,
		TetragonVersion: v.TetragonVersion,
		Trust:           tv,
		Epochs:          fakeEpochSource{current: v.CurrentEpoch},
		PolicyParser:    realPolicyParser{},
		Guardrails:      guardrailsForVector(v),
	})
	if result.Code.String() != v.ExpectedResult {
		return fmt.Errorf("%s: got %s want %s (reason: %s)", v.Name, result.Code, v.ExpectedResult, result.Reason)
	}
	return nil
}

// guardrailsForVector selects which Guardrails fake a vector is
// self-checked (and re-checked by the test suite) against: allow-all for
// every ordinary vector, and the real internal/guard engine (with
// deliberately-configured fakes) for the handful of vectors that exist
// specifically to exercise a guard-level rejection.
func guardrailsForVector(v testvectors.Vector) verify.Guardrails {
	switch v.Name {
	case "guardrail_rejection_unscoped_sigkill":
		return realGuardrails{caps: allowAllCapabilities{}, history: allowAllHistory{}}
	case "capability_rejection_override":
		return realGuardrails{caps: denyOverrideCapabilities{}, history: allowAllHistory{}}
	default:
		return allowAllGuardrails{}
	}
}

var trustErrorsByName = map[string]error{
	"ErrUnsupportedKeyType":     trust.ErrUnsupportedKeyType,
	"ErrKeyIDMismatch":          trust.ErrKeyIDMismatch,
	"ErrThresholdNotMet":        trust.ErrThresholdNotMet,
	"ErrOldThresholdNotMet":     trust.ErrOldThresholdNotMet,
	"ErrNewThresholdNotMet":     trust.ErrNewThresholdNotMet,
	"ErrVersionRollback":        trust.ErrVersionRollback,
	"ErrVersionSkip":            trust.ErrVersionSkip,
	"ErrExpiredMetadata":        trust.ErrExpiredMetadata,
	"ErrMalformedMetadata":      trust.ErrMalformedMetadata,
	"ErrInvalidRoleDefinition":  trust.ErrInvalidRoleDefinition,
	"ErrRootValidityTooLong":    trust.ErrRootValidityTooLong,
	"ErrUnknownKeyType":         trust.ErrUnknownKeyType,
	"ErrKeytypeSPKIMismatch":    trust.ErrKeytypeSPKIMismatch,
	"ErrMLDSAUnavailable":       trust.ErrMLDSAUnavailable,
	"ErrInvalidRequireKeyTypes": trust.ErrInvalidRequireKeyTypes,
}

func checkTrustLoad(v testvectors.Vector) error {
	rootBytes, err := base64.StdEncoding.DecodeString(v.RootMetadataB64)
	if err != nil {
		return fmt.Errorf("%s: decode root: %w", v.Name, err)
	}
	_, err = trust.LoadInitialRoot(rootBytes)
	want := trustErrorsByName[v.ExpectedError]
	if want == nil {
		return fmt.Errorf("%s: unknown expected_error %q", v.Name, v.ExpectedError)
	}
	if !errors.Is(err, want) {
		return fmt.Errorf("%s: LoadInitialRoot error = %w, want %w", v.Name, err, want)
	}
	return nil
}

func checkTrustUpdate(v testvectors.Vector) error {
	rootBytes, err := base64.StdEncoding.DecodeString(v.RootMetadataB64)
	if err != nil {
		return fmt.Errorf("%s: decode root: %w", v.Name, err)
	}
	root, err := trust.LoadInitialRoot(rootBytes)
	if err != nil {
		return fmt.Errorf("%s: LoadInitialRoot: %w", v.Name, err)
	}
	newBytes, err := base64.StdEncoding.DecodeString(v.NewRootMetadataB64)
	if err != nil {
		return fmt.Errorf("%s: decode new root: %w", v.Name, err)
	}
	now, err := time.Parse(time.RFC3339, v.Now)
	if err != nil {
		return fmt.Errorf("%s: parse now: %w", v.Name, err)
	}
	_, err = root.Update(newBytes, now)
	if v.ExpectedError == "" {
		// An empty expected_error means this vector asserts Update
		// SUCCEEDS (step 4 prompt Part B6: "root rotation from
		// ECDSA-only to hybrid, accept when both old and new
		// requirements are met").
		if err != nil {
			return fmt.Errorf("%s: Update error = %w, want success", v.Name, err)
		}
		return nil
	}
	want := trustErrorsByName[v.ExpectedError]
	if want == nil {
		return fmt.Errorf("%s: unknown expected_error %q", v.Name, v.ExpectedError)
	}
	if !errors.Is(err, want) {
		return fmt.Errorf("%s: Update error = %w, want %w", v.Name, err, want)
	}
	return nil
}

func saveChecked(dir string, v testvectors.Vector) error {
	var err error
	switch v.Kind {
	case testvectors.KindVerify:
		err = checkVerify(v)
	case testvectors.KindTrustLoad:
		err = checkTrustLoad(v)
	case testvectors.KindTrustUpdate:
		err = checkTrustUpdate(v)
	default:
		err = fmt.Errorf("%s: unknown kind %q", v.Name, v.Kind)
	}
	if err != nil {
		return err
	}
	return testvectors.Save(dir, v)
}

func generateAll(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	stdRoot, err := buildStandardRoot(1, baseNow.Add(365*24*time.Hour), 1, 1, false)
	if err != nil {
		return err
	}
	t1 := stdRoot.tgtKeys[0]
	l1 := stdRoot.logKeys[0]

	thr2Root, err := buildStandardRoot(1, baseNow.Add(365*24*time.Hour), 2, 2, false)
	if err != nil {
		return err
	}
	t2a := thr2Root.tgtKeys[0]

	expiredRoot, err := buildStandardRoot(1, baseNow.Add(-1*time.Hour), 1, 1, false)
	if err != nil {
		return err
	}

	validPolicy := newPolicy("block-shadow-read", 7, validPolicyYAML("block-shadow-read", 64), "")

	stdBundleSpec := func() bundleSpec {
		return bundleSpec{
			bundleID:           "pb-test-0001",
			epoch:              10,
			scope:              stdScope,
			hostUUIDs:          []string{stdHost},
			notBefore:          baseNow.Add(-1 * time.Hour),
			expires:            baseNow.Add(24 * time.Hour),
			tetragonMinVersion: "1.3.0",
			mode:               "enforce",
			policies:           []policyPayload{validPolicy},
		}
	}

	vector := func(name, desc string, kind testvectors.Kind) testvectors.Vector {
		return testvectors.Vector{
			Name:            name,
			Kind:            kind,
			Description:     desc,
			HostUUID:        stdHost,
			AllowedScopes:   []string{stdScope},
			TetragonVersion: "1.4.0",
			CurrentEpoch:    5,
			Now:             baseNow.Format(time.RFC3339),
		}
	}

	// 1. valid
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("valid", "A correctly signed, targeted, in-window bundle. Must be accepted.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeAccept.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 2. wrong_key: signed by a key absent from the trust root entirely.
	{
		stray, err := newP384Key()
		if err != nil {
			return err
		}
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, stray)
		if err != nil {
			return err
		}
		v := vector("wrong_key", "Signed by a key that is not present in the trust root at all.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 3. key_not_in_targets_role: signed by a key present in the root's
	// key set (the log role) but not listed in the targets role.
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, l1)
		if err != nil {
			return err
		}
		v := vector("key_not_in_targets_role", "Signed by a key that exists in the trust root but only in the log role, not the targets role.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 4. threshold_not_met: targets role requires 2 signatures, only 1 given.
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t2a)
		if err != nil {
			return err
		}
		v := vector("threshold_not_met", "Targets role threshold is 2; only one valid signature is present.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(thr2Root.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 5. duplicate_signature_same_key_threshold2: two signatures, both
	// from the same key, against a threshold-2 role.
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		pae := paeFor(bundlePayloadType, payload)
		sig1, err := makeSig(t2a, pae)
		if err != nil {
			return err
		}
		sig2, err := makeSig(t2a, pae)
		if err != nil {
			return err
		}
		env, err := rawEnvelopeWithSigs(bundlePayloadType, payload, []wireSignature{sig1, sig2})
		if err != nil {
			return err
		}
		v := vector("duplicate_signature_same_key_threshold2", "Two signatures are present but both come from the same key; rejected at envelope parsing (step 1 review A4: duplicate signature keyids are never legitimate and are rejected outright, before threshold counting is ever reached).", testvectors.KindVerify)
		v.RootMetadataB64 = b64(thr2Root.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 6. payloadtype_mismatch
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		wrongType := bundlePayloadType + ".v0"
		env, err := signEnvelope(wrongType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("payloadtype_mismatch", "Envelope payloadType does not match the expected bundle media type.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 7. tampered_payload_byte: valid envelope, one payload byte flipped
	// after signing.
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		tampered, err := flipPayloadByte(env)
		if err != nil {
			return err
		}
		v := vector("tampered_payload_byte", "A validly-signed envelope with one byte of the (decoded) payload flipped after signing.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(tampered)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 9. host_not_targeted
	{
		spec := stdBundleSpec()
		spec.hostUUIDs = []string{otherHost}
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("host_not_targeted", "Bundle targets a different host UUID.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedTarget.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 10. scope_not_allowed
	{
		spec := stdBundleSpec()
		spec.scope = otherScope
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("scope_not_allowed", "Host is targeted, but the bundle's scope is not in the host's allowed_scopes.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedTarget.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 11. epoch_equal
	{
		spec := stdBundleSpec()
		spec.epoch = 5
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("epoch_equal", "Bundle epoch equals the host's current epoch; epoch must be strictly greater.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedEpoch.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 12. epoch_lower
	{
		spec := stdBundleSpec()
		spec.epoch = 3
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("epoch_lower", "Bundle epoch is lower than the host's current epoch (replay of an old bundle).", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedEpoch.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 13. not_yet_valid
	{
		spec := stdBundleSpec()
		spec.notBefore = baseNow.Add(1 * time.Hour)
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("not_yet_valid", "Bundle's not_before is in the future, beyond clock skew tolerance.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedExpired.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 14. expired
	{
		spec := stdBundleSpec()
		spec.notBefore = baseNow.Add(-2 * time.Hour)
		spec.expires = baseNow.Add(-1 * time.Hour)
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("expired", "Bundle's expires is in the past, beyond clock skew tolerance.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedExpired.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// Boundary-exact clock skew vectors (step 1 review A5). All four use
	// the standard bundle's not_before/expires (baseNow-1h / baseNow+24h)
	// and vary only the vector's "now".
	{
		spec := stdBundleSpec()
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}

		mk := func(name, desc string, now time.Time, expected verify.Code) error {
			v := vector(name, desc, testvectors.KindVerify)
			v.RootMetadataB64 = b64(stdRoot.envelope)
			v.EnvelopeB64 = b64(env)
			v.Now = now.Format(time.RFC3339)
			v.ExpectedResult = expected.String()
			return saveChecked(dir, v)
		}

		notBefore := spec.notBefore
		expires := spec.expires

		if err := mk("not_before_minus_skew_exact_accept",
			"now is exactly not_before - 300s (the clock skew boundary); still accepted.",
			notBefore.Add(-300*time.Second), verify.CodeAccept); err != nil {
			return err
		}
		if err := mk("not_before_minus_skew_plus_one_reject",
			"now is 301s before not_before, one second past the clock skew boundary; rejected as not yet valid.",
			notBefore.Add(-301*time.Second), verify.CodeRejectedExpired); err != nil {
			return err
		}
		if err := mk("expires_plus_skew_minus_one_accept",
			"now is exactly expires + 299s, one second inside the clock skew boundary; still accepted.",
			expires.Add(299*time.Second), verify.CodeAccept); err != nil {
			return err
		}
		if err := mk("expires_plus_skew_exact_reject",
			"now is exactly expires + 300s (the clock skew boundary); rejected as expired.",
			expires.Add(300*time.Second), verify.CodeRejectedExpired); err != nil {
			return err
		}
	}

	// 15. expired_root_metadata
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, expiredRoot.tgtKeys[0])
		if err != nil {
			return err
		}
		v := vector("expired_root_metadata", "The trust root itself has already expired as of 'now'; no Verifier can be obtained, so the bundle is rejected as if unsigned.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(expiredRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 16. unknown_json_field
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		injected := strings.Replace(string(payload), `{"schema"`, `{"unexpected_field":"x","schema"`, 1)
		env, err := signEnvelope(bundlePayloadType, []byte(injected), t1)
		if err != nil {
			return err
		}
		v := vector("unknown_json_field", "Payload JSON has a top-level field not in the schema.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 17. duplicate_json_key_top_level
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		needle := fmt.Sprintf(`"scope":"%s"`, stdScope)
		injected := strings.Replace(string(payload), needle, needle+","+needle, 1)
		env, err := signEnvelope(bundlePayloadType, []byte(injected), t1)
		if err != nil {
			return err
		}
		v := vector("duplicate_json_key_top_level", "Payload JSON has the top-level key \"scope\" twice.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 18. duplicate_json_key_nested
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		needle := `"selector_digest":""`
		injected := strings.Replace(string(payload), needle, needle+","+needle, 1)
		env, err := signEnvelope(bundlePayloadType, []byte(injected), t1)
		if err != nil {
			return err
		}
		v := vector("duplicate_json_key_nested", "Payload JSON has the nested key \"targets.selector_digest\" twice.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 19. oversize_envelope: 5 policies at the 256 KiB per-policy cap.
	{
		spec := stdBundleSpec()
		policies := make([]policyPayload, 0, 5)
		for i := 0; i < 5; i++ {
			name := fmt.Sprintf("oversize-policy-%d", i)
			policies = append(policies, newPolicy(name, 1, validPolicyYAML(name, 256*1024), ""))
		}
		spec.policies = policies
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("oversize_envelope", "Envelope exceeds the 1 MiB cap because of several large (but individually within-limit) policies; rejected before any parsing.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 20. sixty_five_policies
	{
		spec := stdBundleSpec()
		policies := make([]policyPayload, 0, 65)
		for i := 0; i < 65; i++ {
			name := fmt.Sprintf("policy-%02d", i)
			policies = append(policies, newPolicy(name, 1, validPolicyYAML(name, 32), ""))
		}
		spec.policies = policies
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("sixty_five_policies", "Bundle has 65 policies, one more than the 64 cap.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 21. yaml_hash_mismatch
	{
		spec := stdBundleSpec()
		spec.policies = []policyPayload{newPolicy("block-shadow-read", 7, validPolicyYAML("block-shadow-read", 64), strings.Repeat("0", 64))}
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("yaml_hash_mismatch", "Policy's declared sha256 does not match the actual hash of its YAML.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 22. invalid_policy_name
	{
		spec := stdBundleSpec()
		spec.policies = []policyPayload{newPolicy("Invalid_Name!", 1, validPolicyYAML("Invalid_Name!", 32), "")}
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("invalid_policy_name", "Policy name does not match the required pattern.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 23. duplicate_policy_names
	{
		spec := stdBundleSpec()
		spec.policies = []policyPayload{
			newPolicy("dup-policy", 1, validPolicyYAML("dup-policy", 32), ""),
			newPolicy("dup-policy", 2, validPolicyYAML("dup-policy", 32), ""),
		}
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("duplicate_policy_names", "Two policies in the same bundle share the same name.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 24. tetragon_version_too_old
	{
		spec := stdBundleSpec()
		spec.tetragonMinVersion = "2.0.0"
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("tetragon_version_too_old", "Bundle requires a Tetragon version newer than the host is running.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// mode_empty, mode_enforce_uppercase, mode_audit: bundle.mode must be
	// exactly "monitor" or "enforce" (step 1 review A3).
	for _, tc := range []struct {
		name, mode string
	}{
		{"mode_empty", ""},
		{"mode_enforce_uppercase", "ENFORCE"},
		{"mode_audit", "audit"},
	} {
		spec := stdBundleSpec()
		spec.mode = tc.mode
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector(tc.name, fmt.Sprintf("Bundle mode is %q, neither \"monitor\" nor \"enforce\" (case-sensitive).", tc.mode), testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// case_fold_duplicate_bundle_scope: the bundle payload has both
	// "scope" and "SCOPE" keys, which fold to the same key (step 1
	// review A1). Rejected at strict payload parsing (step 5).
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		injected := strings.Replace(string(payload), `"scope":"`+stdScope+`"`, `"scope":"`+stdScope+`","SCOPE":"other"`, 1)
		env, err := signEnvelope(bundlePayloadType, []byte(injected), t1)
		if err != nil {
			return err
		}
		v := vector("case_fold_duplicate_bundle_scope", "Bundle payload has both \"scope\" and \"SCOPE\", which fold to the same key under Unicode simple case folding.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// case_fold_duplicate_envelope_payloadtype: the envelope's own JSON
	// has both "payloadType" and "PayloadType" at the top level. Rejected
	// while parsing the envelope itself (step 2), before any signature or
	// payload work.
	{
		payload, err := buildBundlePayload(stdBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		injected := strings.Replace(string(env), `{"payloadType"`, `{"PayloadType":"x","payloadType"`, 1)
		v := vector("case_fold_duplicate_envelope_payloadtype", "Envelope JSON has both \"payloadType\" and \"PayloadType\" at the top level, which fold to the same key.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64([]byte(injected))
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// case_fold_duplicate_root_metadata_keyid: root metadata's "keys" map
	// has two entries whose IDs are equal under Unicode simple case
	// folding (an uppercase-hex variant of a real key ID). Rejected while
	// parsing the root payload.
	{
		r1, err := newP384Key()
		if err != nil {
			return err
		}
		r2, err := newP384Key()
		if err != nil {
			return err
		}
		tk, err := newP384Key()
		if err != nil {
			return err
		}
		lk, err := newP384Key()
		if err != nil {
			return err
		}
		spec := rootSpec{
			version: 1,
			expires: baseNow.Add(365 * 24 * time.Hour),
			keys:    []*testKey{r1, r2, tk, lk},
			root:    roleOf([]*testKey{r1, r2}, 2),
			targets: roleOf([]*testKey{tk}, 1),
			log:     roleOf([]*testKey{lk}, 1),
		}
		payload, err := buildRootPayload(spec)
		if err != nil {
			return err
		}
		upper := strings.ToUpper(strings.TrimPrefix(tk.id, "sha256:"))
		duplicateKeyEntry := fmt.Sprintf(`,"sha256:%s":{"keytype":"ecdsa-p384","public_key_der_b64":%q}`, upper, tk.publicB64)
		injected := strings.Replace(string(payload), `"`+tk.id+`":{"keytype":"ecdsa-p384","public_key_der_b64":"`+tk.publicB64+`"}`,
			`"`+tk.id+`":{"keytype":"ecdsa-p384","public_key_der_b64":"`+tk.publicB64+`"}`+duplicateKeyEntry, 1)
		if injected == string(payload) {
			return fmt.Errorf("case_fold_duplicate_root_metadata_keyid: injection needle not found")
		}
		env, err := signEnvelope(rootPayloadType, []byte(injected), r1, r2)
		if err != nil {
			return err
		}
		v := vector("case_fold_duplicate_root_metadata_keyid", "Root metadata's \"keys\" map has two entries whose IDs are equal under Unicode simple case folding (an uppercase-hex variant of a real key ID).", testvectors.KindTrustLoad)
		v.RootMetadataB64 = b64(env)
		v.ExpectedError = "ErrMalformedMetadata"
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 25. non_p384_key: root metadata contains a non-P-384 key entry.
	{
		r1, err := newP384Key()
		if err != nil {
			return err
		}
		r2, err := newP384Key()
		if err != nil {
			return err
		}
		r3, err := newP384Key()
		if err != nil {
			return err
		}
		t1k, err := newP384Key()
		if err != nil {
			return err
		}
		l1k, err := newP384Key()
		if err != nil {
			return err
		}
		bad, err := newKey(elliptic.P256(), "ecdsa-p384") // lies about its type
		if err != nil {
			return err
		}
		spec := rootSpec{
			version: 1,
			expires: baseNow.Add(365 * 24 * time.Hour),
			keys:    []*testKey{r1, r2, r3, t1k, l1k, bad},
			root:    roleOf([]*testKey{r1, r2, r3}, 2),
			targets: roleOf([]*testKey{t1k}, 1),
			log:     roleOf([]*testKey{l1k}, 1),
		}
		payload, err := buildRootPayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(rootPayloadType, payload, r1, r2)
		if err != nil {
			return err
		}
		v := vector("non_p384_key", "Root metadata contains a key whose actual curve is P-256 even though it declares keytype ecdsa-p384.", testvectors.KindTrustLoad)
		v.RootMetadataB64 = b64(env)
		v.ExpectedError = "ErrKeytypeSPKIMismatch"
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// root_role_key_overlap: a key appears in both the root and targets
	// roles, which step 1 review A6 requires to be pairwise disjoint.
	{
		r1, err := newP384Key()
		if err != nil {
			return err
		}
		r2, err := newP384Key()
		if err != nil {
			return err
		}
		l1k, err := newP384Key()
		if err != nil {
			return err
		}
		spec := rootSpec{
			version: 1,
			expires: baseNow.Add(365 * 24 * time.Hour),
			keys:    []*testKey{r1, r2, l1k},
			root:    roleOf([]*testKey{r1, r2}, 2),
			// r1 is also listed in the targets role: not disjoint.
			targets: roleOf([]*testKey{r1}, 1),
			log:     roleOf([]*testKey{l1k}, 1),
		}
		payload, err := buildRootPayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(rootPayloadType, payload, r1, r2)
		if err != nil {
			return err
		}
		v := vector("root_role_key_overlap", "A key is listed in both the root role and the targets role; roles must be pairwise disjoint.", testvectors.KindTrustLoad)
		v.RootMetadataB64 = b64(env)
		v.ExpectedError = "ErrInvalidRoleDefinition"
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// root_update_validity_too_long: a candidate root update's expiry is
	// more than limits.MaxRootValidity (400 days) past "now" at Update
	// time.
	if err := genRootUpdateVectorWithExpiry(dir, "root_update_validity_too_long",
		"Root update's expiry is 5 years past 'now' at Update time, exceeding the 400-day maximum validity window.",
		1, 2, baseNow.Add(5*365*24*time.Hour), "ErrRootValidityTooLong", signOldKeys); err != nil {
		return err
	}

	// 26. root_rollback: new version <= current version.
	if err := genRootUpdateVector(dir, "root_rollback",
		"New root metadata version (1) is not greater than the current version (2).",
		2, 1, "ErrVersionRollback", signOldKeys); err != nil {
		return err
	}

	// 27. root_version_skip: new version jumps by more than one.
	if err := genRootUpdateVector(dir, "root_version_skip",
		"New root metadata version (3) skips ahead of the current version (1) by more than one.",
		1, 3, "ErrVersionSkip", signOldKeys); err != nil {
		return err
	}

	// 28. root_update_signed_only_by_old_keys: new threshold not met.
	if err := genRootUpdateVector(dir, "root_update_signed_only_by_old_keys",
		"Root update to version 2 is signed only by the outgoing (version 1) root keys, not by a threshold of the incoming root keys.",
		1, 2, "ErrNewThresholdNotMet", signOldKeys); err != nil {
		return err
	}

	// 29. root_update_signed_only_by_new_keys: old threshold not met.
	if err := genRootUpdateVector(dir, "root_update_signed_only_by_new_keys",
		"Root update to version 2 is signed only by the incoming (version 2) root keys, not by a threshold of the outgoing root keys.",
		1, 2, "ErrOldThresholdNotMet", signNewKeys); err != nil {
		return err
	}

	// policy_schema_failure: a policy using a Kubernetes-only selector
	// (podSelector), rejected by internal/policydoc's B4 allowlist. Step
	// 2 prompt Part D's "schema failure" vector.
	{
		spec := stdBundleSpec()
		badYAML := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: schema-failure\nspec:\n  podSelector: {}\n"
		spec.policies = []policyPayload{newPolicy("schema-failure", 1, badYAML, "")}
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("policy_schema_failure", "Policy uses a Kubernetes-only selector (podSelector), rejected by internal/policydoc's B4 allowlist (step 2 prompt Part B).", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// policy_name_mismatch: the policy YAML's metadata.name differs from
	// the bundle's declared policies[].name. Step 2 prompt Part B8.
	{
		spec := stdBundleSpec()
		spec.policies = []policyPayload{newPolicy("declared-name", 1, validPolicyYAML("different-metadata-name", 32), "")}
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("policy_name_mismatch", "Policy YAML's metadata.name does not match the bundle's declared policy name (step 2 prompt Part B8).", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSchema.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// guardrail_rejection_unscoped_sigkill: a Sigkill selector with no
	// matchBinaries at all, rejected by internal/guard's G1 (step 2
	// prompt Part C). Self-checked against the real guard engine via
	// guardrailsForVector, keyed by this vector's name.
	{
		spec := stdBundleSpec()
		yaml := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: unscoped-sigkill\nspec:\n  kprobes:\n  - call: \"do_something\"\n    selectors:\n    - matchActions:\n      - action: \"Sigkill\"\n"
		spec.policies = []policyPayload{newPolicy("unscoped-sigkill", 1, yaml, "")}
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("guardrail_rejection_unscoped_sigkill", "A Sigkill action with no matchBinaries at all, rejected by internal/guard's G1 (protected processes: every enforcement selector must have matchBinaries).", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedGuardrail.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// capability_rejection_override: Override on a kprobe, but the host
	// (per the fake HostCapabilities this vector is self-checked
	// against) does not support kprobe Override. internal/guard's G8,
	// mapped by internal/verify to REJECTED_CAPABILITY.
	{
		spec := stdBundleSpec()
		yaml := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: override-no-capability\nspec:\n  kprobes:\n  - call: \"security_bprm_check\"\n    selectors:\n    - matchBinaries:\n      - operator: \"In\"\n        values:\n        - \"/usr/bin/safe\"\n      matchActions:\n      - action: \"Override\"\n        argError: -1\n"
		spec.policies = []policyPayload{newPolicy("override-no-capability", 1, yaml, "")}
		payload, err := buildBundlePayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, t1)
		if err != nil {
			return err
		}
		v := vector("capability_rejection_override", "Override on a kprobe where the host lacks the KprobeOverride capability, rejected by internal/guard's G8 and mapped to REJECTED_CAPABILITY.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(stdRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedCapability.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// role_missing_require_keytypes (step-04a-review.md R4A-1): the
	// targets role's require_keytypes field is omitted entirely.
	// Mandatory on every role; omission is malformed metadata, not "no
	// requirement".
	{
		r1, err := newP384Key()
		if err != nil {
			return err
		}
		r2, err := newP384Key()
		if err != nil {
			return err
		}
		r3, err := newP384Key()
		if err != nil {
			return err
		}
		tk, err := newP384Key()
		if err != nil {
			return err
		}
		lk, err := newP384Key()
		if err != nil {
			return err
		}
		spec := rootSpec{
			version: 1,
			expires: baseNow.Add(365 * 24 * time.Hour),
			keys:    []*testKey{r1, r2, r3, tk, lk},
			root:    roleOf([]*testKey{r1, r2, r3}, 2),
			// targets role omits require_keytypes entirely.
			targets: roleOfOmittingKeyTypes([]*testKey{tk}, 1),
			log:     roleOf([]*testKey{lk}, 1),
		}
		payload, err := buildRootPayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(rootPayloadType, payload, r1, r2)
		if err != nil {
			return err
		}
		v := vector("role_missing_require_keytypes", "The targets role's require_keytypes field is omitted entirely; require_keytypes is mandatory on every role (step-04a-review.md R4A-1), so this is malformed metadata, not \"no algorithm requirement\".", testvectors.KindTrustLoad)
		v.RootMetadataB64 = b64(env)
		v.ExpectedError = "ErrInvalidRequireKeyTypes"
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// root_update_new_root_missing_require_keytypes (step-04a-review.md
	// R4A-1): a root rotation whose NEW root's targets role omits
	// require_keytypes. Must be rejected before it is ever accepted as
	// the new persisted root.
	if err := genRootUpdateVectorMissingKeyTypes(dir); err != nil {
		return err
	}

	if err := generateHybridVectors(dir); err != nil {
		return err
	}

	return writeVectorsReadme(dir)
}

// paeFor recomputes the PAE for payload under payloadType using the same
// construction as internal/dsse.PAE (duplicated locally only to avoid an
// import cycle concern; verified against internal/dsse in
// internal/dsse/pae_test.go and exercised transitively by every generated
// vector's self-check).
func paeFor(payloadType string, payload []byte) []byte {
	out := make([]byte, 0, len(payloadType)+len(payload)+32)
	out = append(out, "DSSEv1 "...)
	out = append(out, []byte(fmt.Sprintf("%d", len(payloadType)))...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, []byte(fmt.Sprintf("%d", len(payload)))...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// flipPayloadByte decodes a signed envelope, flips the last byte of the
// decoded payload, and re-encodes it with the ORIGINAL signatures (so the
// signatures no longer verify).
func flipPayloadByte(envJSON []byte) ([]byte, error) {
	var env wireEnvelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	payload[len(payload)-1] ^= 0xFF
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	return json.Marshal(env)
}
