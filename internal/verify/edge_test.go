package verify_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/verify"
)

const (
	edgeHost  = "33333333-3333-4333-8333-333333333333"
	edgeScope = "prod-db"
)

// edgePolicyYAML is real, schema-valid TracingPolicy content (flow-style
// YAML, so it embeds into a JSON string literal on one line without needing
// escaped newlines) matching policy name "edge-policy": an observe-only
// Post action needing no matchBinaries, which internal/guard accepts
// trivially, so these tests (which only exercise internal/verify's own
// earlier checks) never fail at the policy-parsing or guardrail step.
const edgePolicyYAML = `{apiVersion: cilium.io/v1alpha1, kind: TracingPolicy, metadata: {name: edge-policy}, spec: {kprobes: [{call: x, selectors: [{matchActions: [{action: Post}]}]}]}}`

func validBundleJSON(overrides string) string {
	base := map[string]string{
		"bundle_id":            `"pb-edge-0001"`,
		"epoch":                `10`,
		"scope":                fmt.Sprintf("%q", edgeScope),
		"targets":              fmt.Sprintf(`{"host_uuids":[%q],"selector_digest":""}`, edgeHost),
		"not_before":           `"2026-11-22T11:00:00Z"`,
		"expires":              `"2026-11-23T11:00:00Z"`,
		"tetragon_min_version": `"1.3.0"`,
		"mode":                 `"enforce"`,
		"policies":             fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":%q}]`, hashHex(edgePolicyYAML), edgePolicyYAML),
		"provenance":           `{"author":"a@example.com","approvers":["b@example.com","c@example.com"],"change_ref":"CHG-1","controller_build":""}`,
	}
	_ = overrides
	return mapToJSON(base)
}

func mapToJSON(m map[string]string) string {
	s := `{"schema":"relay.policybundle.v1"`
	for k, v := range m {
		s += fmt.Sprintf(`,%q:%s`, k, v)
	}
	s += "}"
	return s
}

func buildEdgeInput(t *testing.T, payload string, now time.Time) (verify.Input, []byte) {
	t.Helper()
	rootEnv, tk := edgeRoot(t, false, now.Add(365*24*time.Hour))
	env := edgeSignEnvelope(verify.BundlePayloadType, []byte(payload), tk)
	tv := edgeTargetsVerifier(t, rootEnv, now)
	return verify.Input{
		Envelope:        env,
		Now:             now,
		HostUUID:        edgeHost,
		AllowedScopes:   []string{edgeScope},
		TetragonVersion: "1.4.0",
		Trust:           tv,
		Epochs:          fakeEpochSource{current: 5},
		PolicyParser:    realPolicyParser{},
		Guardrails:      allowAllGuardrails{},
	}, env
}

func TestVerify_MissingNotBefore(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	base := map[string]string{
		"bundle_id": `"pb-1"`, "epoch": `10`, "scope": fmt.Sprintf("%q", edgeScope),
		"targets": fmt.Sprintf(`{"host_uuids":[%q],"selector_digest":""}`, edgeHost),
		"expires": `"2026-11-23T11:00:00Z"`, "tetragon_min_version": `"1.3.0"`, "mode": `"enforce"`,
		"policies":   fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":%q}]`, hashHex(edgePolicyYAML), edgePolicyYAML),
		"provenance": `{}`,
	}
	payload := mapToJSON(base)
	in, _ := buildEdgeInput(t, payload, now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_MissingExpires(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	base := map[string]string{
		"bundle_id": `"pb-1"`, "epoch": `10`, "scope": fmt.Sprintf("%q", edgeScope),
		"targets":    fmt.Sprintf(`{"host_uuids":[%q],"selector_digest":""}`, edgeHost),
		"not_before": `"2026-11-22T11:00:00Z"`, "tetragon_min_version": `"1.3.0"`, "mode": `"enforce"`,
		"policies":   fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":%q}]`, hashHex(edgePolicyYAML), edgePolicyYAML),
		"provenance": `{}`,
	}
	payload := mapToJSON(base)
	in, _ := buildEdgeInput(t, payload, now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_MalformedTargetUUID(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	base := map[string]string{
		"bundle_id": `"pb-1"`, "epoch": `10`, "scope": fmt.Sprintf("%q", edgeScope),
		"targets":    `{"host_uuids":["not-a-uuid"],"selector_digest":""}`,
		"not_before": `"2026-11-22T11:00:00Z"`, "expires": `"2026-11-23T11:00:00Z"`,
		"tetragon_min_version": `"1.3.0"`, "mode": `"enforce"`,
		"policies":   fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":%q}]`, hashHex(edgePolicyYAML), edgePolicyYAML),
		"provenance": `{}`,
	}
	payload := mapToJSON(base)
	in, _ := buildEdgeInput(t, payload, now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_MissingBundleIDOrScope(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	base := map[string]string{
		"epoch":      `10`,
		"targets":    fmt.Sprintf(`{"host_uuids":[%q],"selector_digest":""}`, edgeHost),
		"not_before": `"2026-11-22T11:00:00Z"`, "expires": `"2026-11-23T11:00:00Z"`,
		"tetragon_min_version": `"1.3.0"`, "mode": `"enforce"`,
		"policies":   fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":%q}]`, hashHex(edgePolicyYAML), edgePolicyYAML),
		"provenance": `{}`,
	}
	payload := mapToJSON(base)
	in, _ := buildEdgeInput(t, payload, now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_WrongBundleSchema(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	payload := `{"schema":"wrong.schema.v9","bundle_id":"pb-1","epoch":10,"scope":"prod-db",` +
		`"targets":{"host_uuids":["` + edgeHost + `"],"selector_digest":""},` +
		`"not_before":"2026-11-22T11:00:00Z","expires":"2026-11-23T11:00:00Z",` +
		`"tetragon_min_version":"1.3.0","mode":"enforce","policies":[],"provenance":{}}`
	in, _ := buildEdgeInput(t, payload, now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA", result.Code)
	}
}

func TestVerify_LocalHostUUIDMalformed(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, validBundleJSON(""), now)
	in.HostUUID = "not-a-uuid"
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA", result.Code)
	}
}

func TestVerify_RequireLogProofRejects(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	rootEnv, tk := edgeRoot(t, true, now.Add(365*24*time.Hour))
	payload := validBundleJSON("")
	env := edgeSignEnvelope(verify.BundlePayloadType, []byte(payload), tk)
	tv := edgeTargetsVerifier(t, rootEnv, now)

	result := verify.Verify(verify.Input{
		Envelope:        env,
		Now:             now,
		HostUUID:        edgeHost,
		AllowedScopes:   []string{edgeScope},
		TetragonVersion: "1.4.0",
		Trust:           tv,
		Epochs:          fakeEpochSource{current: 5},
	})
	if result.Code != verify.CodeRejectedSignature {
		t.Fatalf("Code = %s, want REJECTED_SIGNATURE (log proof required but unsupported)", result.Code)
	}
}

func TestVerify_NoEpochSourceConfigured(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, validBundleJSON(""), now)
	in.Epochs = nil
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedEpoch {
		t.Fatalf("Code = %s, want REJECTED_EPOCH", result.Code)
	}
}

func TestVerify_ZeroPolicies(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	payload := `{"schema":"relay.policybundle.v1","bundle_id":"pb-1","epoch":10,"scope":"prod-db",` +
		`"targets":{"host_uuids":["` + edgeHost + `"],"selector_digest":""},` +
		`"not_before":"2026-11-22T11:00:00Z","expires":"2026-11-23T11:00:00Z",` +
		`"tetragon_min_version":"1.3.0","mode":"enforce","policies":[],"provenance":{}}`
	in, _ := buildEdgeInput(t, payload, now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA", result.Code)
	}
}

// TestVerify_NilGuardrailsRejectsClosed is the step 1 review's A2
// regression: a nil Guardrails must never be treated as "no restrictions."
// An otherwise fully valid, signed, in-window, correctly-targeted bundle
// must still be rejected if no guardrail implementation is configured.
func TestVerify_NilGuardrailsRejectsClosed(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, validBundleJSON(""), now)
	in.Guardrails = nil
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedGuardrail {
		t.Fatalf("Code = %s, want REJECTED_GUARDRAIL (reason: %s)", result.Code, result.Reason)
	}
}

// TestVerify_NilPolicyParserRejectsClosed mirrors
// TestVerify_NilGuardrailsRejectsClosed for PolicyParser (step 2 prompt
// Part C0): an otherwise fully valid, signed, in-window, correctly-targeted
// bundle must still be rejected if no policy parser is configured, with
// CodeRejectedSchema (fail closed), never silently skipping schema
// validation.
func TestVerify_NilPolicyParserRejectsClosed(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, validBundleJSON(""), now)
	in.PolicyParser = nil
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

// edgeBundleJSON builds a valid bundle payload with one field overridden to
// a raw JSON fragment (e.g. `"not-an-id!"` or `9999999999`), for targeted
// step 1 review A3/A5/A7 regression tests.
func edgeBundleJSON(field, rawValue string) string {
	base := map[string]string{
		"bundle_id":            `"pb-edge-0001"`,
		"epoch":                `10`,
		"scope":                fmt.Sprintf("%q", edgeScope),
		"targets":              fmt.Sprintf(`{"host_uuids":[%q],"selector_digest":""}`, edgeHost),
		"not_before":           `"2026-11-22T11:00:00Z"`,
		"expires":              `"2026-11-23T11:00:00Z"`,
		"tetragon_min_version": `"1.3.0"`,
		"mode":                 `"enforce"`,
		"policies":             fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":%q}]`, hashHex(edgePolicyYAML), edgePolicyYAML),
		"provenance":           `{}`,
	}
	base[field] = rawValue
	return mapToJSON(base)
}

func TestVerify_InvalidBundleID(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	cases := []string{`"has a space"`, `"has/slash"`, fmt.Sprintf("%q", strings.Repeat("a", 129))}
	for _, c := range cases {
		in, _ := buildEdgeInput(t, edgeBundleJSON("bundle_id", c), now)
		result := verify.Verify(in)
		if result.Code != verify.CodeRejectedSchema {
			t.Errorf("bundle_id %s: Code = %s, want REJECTED_SCHEMA", c, result.Code)
		}
	}
}

func TestVerify_EpochJumpExceedsMaximum(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	// current epoch is 5 (fakeEpochSource default); jump far beyond it.
	in, _ := buildEdgeInput(t, edgeBundleJSON("epoch", "100000000"), now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedEpoch {
		t.Fatalf("Code = %s, want REJECTED_EPOCH (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_ExpiresNotAfterNotBefore(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, edgeBundleJSON("expires", `"2026-11-22T11:00:00Z"`), now) // == not_before
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_ValidityWindowExceedsMaximum(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, edgeBundleJSON("expires", `"2027-03-01T11:00:00Z"`), now) // > 90 days after not_before
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_MissingTetragonMinVersion(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, edgeBundleJSON("tetragon_min_version", `""`), now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_InvalidTetragonMinVersion(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, edgeBundleJSON("tetragon_min_version", `"not-a-version"`), now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_InvalidRunningTetragonVersion(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, validBundleJSON(""), now)
	in.TetragonVersion = "not-a-version"
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_PolicyYAMLExceedsSizeLimit(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	big := strings.Repeat("a", 256*1024+1)
	policy := fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":%q}]`, hashHex(big), big)
	in, _ := buildEdgeInput(t, edgeBundleJSON("policies", policy), now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestVerify_PolicyVersionOutOfBounds(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	cases := []int{0, -1}
	for _, v := range cases {
		policy := fmt.Sprintf(`[{"name":"edge-policy","version":%d,"sha256":%q,"yaml":%q}]`, v, hashHex(edgePolicyYAML), edgePolicyYAML)
		in, _ := buildEdgeInput(t, edgeBundleJSON("policies", policy), now)
		result := verify.Verify(in)
		if result.Code != verify.CodeRejectedSchema {
			t.Errorf("version %d: Code = %s, want REJECTED_SCHEMA", v, result.Code)
		}
	}
}

func TestVerify_PolicySHA256NotCanonical(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	upper := strings.ToUpper(hashHex(edgePolicyYAML))
	policy := fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":%q}]`, upper, edgePolicyYAML)
	in, _ := buildEdgeInput(t, edgeBundleJSON("policies", policy), now)
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSchema {
		t.Fatalf("Code = %s, want REJECTED_SCHEMA (reason: %s)", result.Code, result.Reason)
	}
}

func TestCode_String_Unknown(t *testing.T) {
	var c verify.Code = 999
	if got := c.String(); got != "UNKNOWN" {
		t.Fatalf("String() = %q, want UNKNOWN", got)
	}
}
