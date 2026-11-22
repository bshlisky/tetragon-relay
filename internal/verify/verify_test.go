package verify_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/testvectors"
	"github.com/bshlisky/tetragon-relay/internal/trust"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

const vectorsDir = "../../testdata/vectors"

type fakeEpochSource struct {
	current uint64
	err     error
}

func (f fakeEpochSource) Current(string) (uint64, error) { return f.current, f.err }

// recordingGuardrails is the fake Guardrails implementation used by this
// step's tests, per the prompt: a real guardrail engine is step 2.
type recordingGuardrails struct {
	calls      int
	lastLen    int
	rejectWith error
}

func (g *recordingGuardrails) Check(policies []verify.Policy) error {
	g.calls++
	g.lastLen = len(policies)
	return g.rejectWith
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return b
}

// buildInput constructs a verify.Input from a vector, obtaining the trust
// Verifier the same way the real agent would: parse the root, then try to
// obtain a targets Verifier at the vector's "now". If the root has expired,
// Trust is left nil, matching step 3's "no trust verifier configured" path.
func buildInput(t *testing.T, v testvectors.Vector) verify.Input {
	t.Helper()
	now, err := time.Parse(time.RFC3339, v.Now)
	if err != nil {
		t.Fatalf("parse now: %v", err)
	}
	root, err := trust.LoadInitialRoot(mustDecode(t, v.RootMetadataB64))
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	var tv trust.Verifier
	if got, err := root.TargetsVerifier(now); err == nil {
		tv = got
	}
	return verify.Input{
		Envelope:        mustDecode(t, v.EnvelopeB64),
		Now:             now,
		HostUUID:        v.HostUUID,
		AllowedScopes:   v.AllowedScopes,
		TetragonVersion: v.TetragonVersion,
		Trust:           tv,
		Epochs:          fakeEpochSource{current: v.CurrentEpoch},
	}
}

func TestVectors_Verify(t *testing.T) {
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	found := 0
	for _, v := range vectors {
		if v.Kind != testvectors.KindVerify {
			continue
		}
		found++
		v := v
		t.Run(v.Name, func(t *testing.T) {
			in := buildInput(t, v)
			result := verify.Verify(in)
			if result.Code.String() != v.ExpectedResult {
				t.Fatalf("Code = %s, want %s (reason: %q)", result.Code, v.ExpectedResult, result.Reason)
			}
			if result.Code == verify.CodeAccept && result.Bundle == nil {
				t.Fatalf("ACCEPT result must populate Bundle")
			}
			if result.Code != verify.CodeAccept && result.Bundle != nil {
				t.Fatalf("non-ACCEPT result must not populate Bundle")
			}
		})
	}
	if found == 0 {
		t.Fatalf("no verify vectors found in %s", vectorsDir)
	}
}

// TestVectors_Verify_PinnedOrder re-runs the "valid" vector but breaks each
// check in turn by corrupting only the field that check is responsible for,
// confirming the specific code produced at each step, pinning the required
// check order from architecture doc section 7.4.
func TestVectors_Verify_PinnedOrder(t *testing.T) {
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	byName := map[string]testvectors.Vector{}
	for _, v := range vectors {
		byName[v.Name] = v
	}

	order := []struct {
		vector string
		want   verify.Code
	}{
		{"oversize_envelope", verify.CodeRejectedSchema},        // step 1
		{"payloadtype_mismatch", verify.CodeRejectedSchema},     // step 2
		{"wrong_key", verify.CodeRejectedSignature},             // step 3
		{"unknown_json_field", verify.CodeRejectedSchema},       // step 5
		{"host_not_targeted", verify.CodeRejectedTarget},        // step 6
		{"scope_not_allowed", verify.CodeRejectedTarget},        // step 7
		{"epoch_equal", verify.CodeRejectedEpoch},               // step 8
		{"expired", verify.CodeRejectedExpired},                 // step 9
		{"tetragon_version_too_old", verify.CodeRejectedSchema}, // step 10
		{"yaml_hash_mismatch", verify.CodeRejectedSchema},       // step 11
		{"valid", verify.CodeAccept},                            // -> ACCEPT
	}
	for _, step := range order {
		v, ok := byName[step.vector]
		if !ok {
			t.Fatalf("missing vector %q", step.vector)
		}
		t.Run(step.vector, func(t *testing.T) {
			in := buildInput(t, v)
			result := verify.Verify(in)
			if result.Code != step.want {
				t.Fatalf("Code = %s, want %s", result.Code, step.want)
			}
		})
	}
}

func TestVerify_GuardrailCalledLastAndOnlyOnOtherwiseValid(t *testing.T) {
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var valid, hostNotTargeted testvectors.Vector
	for _, v := range vectors {
		switch v.Name {
		case "valid":
			valid = v
		case "host_not_targeted":
			hostNotTargeted = v
		}
	}

	t.Run("not called when an earlier check fails", func(t *testing.T) {
		g := &recordingGuardrails{}
		in := buildInput(t, hostNotTargeted)
		in.Guardrails = g
		result := verify.Verify(in)
		if result.Code != verify.CodeRejectedTarget {
			t.Fatalf("Code = %s, want REJECTED_TARGET", result.Code)
		}
		if g.calls != 0 {
			t.Fatalf("Guardrails.Check called %d times, want 0", g.calls)
		}
	})

	t.Run("called exactly once on an otherwise-valid bundle", func(t *testing.T) {
		g := &recordingGuardrails{}
		in := buildInput(t, valid)
		in.Guardrails = g
		result := verify.Verify(in)
		if result.Code != verify.CodeAccept {
			t.Fatalf("Code = %s, want ACCEPT", result.Code)
		}
		if g.calls != 1 {
			t.Fatalf("Guardrails.Check called %d times, want 1", g.calls)
		}
		if g.lastLen != 1 {
			t.Fatalf("Guardrails.Check saw %d policies, want 1", g.lastLen)
		}
	})

	t.Run("guardrail rejection surfaces as REJECTED_GUARDRAIL", func(t *testing.T) {
		g := &recordingGuardrails{rejectWith: errGuardrail}
		in := buildInput(t, valid)
		in.Guardrails = g
		result := verify.Verify(in)
		if result.Code != verify.CodeRejectedGuardrail {
			t.Fatalf("Code = %s, want REJECTED_GUARDRAIL", result.Code)
		}
	})
}

var errGuardrail = &guardrailError{"fake guardrail rejection"}

type guardrailError struct{ msg string }

func (e *guardrailError) Error() string { return e.msg }

func TestVerify_EpochSourceErrorIsRejection(t *testing.T) {
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var valid testvectors.Vector
	for _, v := range vectors {
		if v.Name == "valid" {
			valid = v
		}
	}
	in := buildInput(t, valid)
	in.Epochs = fakeEpochSource{err: errGuardrail}
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedEpoch {
		t.Fatalf("Code = %s, want REJECTED_EPOCH", result.Code)
	}
}

func TestVerify_NilTrustIsRejectedSignature(t *testing.T) {
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var valid testvectors.Vector
	for _, v := range vectors {
		if v.Name == "valid" {
			valid = v
		}
	}
	in := buildInput(t, valid)
	in.Trust = nil
	result := verify.Verify(in)
	if result.Code != verify.CodeRejectedSignature {
		t.Fatalf("Code = %s, want REJECTED_SIGNATURE", result.Code)
	}
}

func TestVerify_NeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil, {}, []byte("{"), []byte("not json"), []byte(`{"payloadType":1}`),
		make([]byte, 2<<20),
	}
	for _, env := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on envelope %q: %v", env, r)
				}
			}()
			verify.Verify(verify.Input{
				Envelope:        env,
				Now:             time.Now(),
				HostUUID:        "not-a-uuid",
				AllowedScopes:   nil,
				TetragonVersion: "not-a-version",
				Trust:           nil,
				Epochs:          fakeEpochSource{},
			})
		}()
	}
}
