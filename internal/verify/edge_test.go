package verify_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/verify"
)

const (
	edgeHost  = "33333333-3333-4333-8333-333333333333"
	edgeScope = "prod-db"
)

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
		"policies":             fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":"edge-yaml"}]`, hashHex("edge-yaml")),
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
	}, env
}

func TestVerify_MissingNotBefore(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	base := map[string]string{
		"bundle_id": `"pb-1"`, "epoch": `10`, "scope": fmt.Sprintf("%q", edgeScope),
		"targets": fmt.Sprintf(`{"host_uuids":[%q],"selector_digest":""}`, edgeHost),
		"expires": `"2026-11-23T11:00:00Z"`, "tetragon_min_version": `"1.3.0"`, "mode": `"enforce"`,
		"policies":   fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":"edge-yaml"}]`, hashHex("edge-yaml")),
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
		"policies":   fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":"edge-yaml"}]`, hashHex("edge-yaml")),
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
		"policies":   fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":"edge-yaml"}]`, hashHex("edge-yaml")),
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
		"policies":   fmt.Sprintf(`[{"name":"edge-policy","version":1,"sha256":%q,"yaml":"edge-yaml"}]`, hashHex("edge-yaml")),
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

func TestVerify_NilGuardrailsSkipsCheck(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in, _ := buildEdgeInput(t, validBundleJSON(""), now)
	in.Guardrails = nil
	result := verify.Verify(in)
	if result.Code != verify.CodeAccept {
		t.Fatalf("Code = %s, want ACCEPT (reason: %s)", result.Code, result.Reason)
	}
}

func TestCode_String_Unknown(t *testing.T) {
	var c verify.Code = 999
	if got := c.String(); got != "UNKNOWN" {
		t.Fatalf("String() = %q, want UNKNOWN", got)
	}
}
