package verify

import "testing"

func TestCode_String_AllValues(t *testing.T) {
	cases := map[Code]string{
		CodeAccept:            "ACCEPT",
		CodeRejectedSignature: "REJECTED_SIGNATURE",
		CodeRejectedTarget:    "REJECTED_TARGET",
		CodeRejectedEpoch:     "REJECTED_EPOCH",
		CodeRejectedExpired:   "REJECTED_EXPIRED",
		CodeRejectedSchema:    "REJECTED_SCHEMA",
		CodeRejectedGuardrail: "REJECTED_GUARDRAIL",
		Code(999):             "UNKNOWN",
	}
	for code, want := range cases {
		if got := code.String(); got != want {
			t.Errorf("Code(%d).String() = %q, want %q", code, got, want)
		}
	}
}
