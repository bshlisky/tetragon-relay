package verify

// Code is the outcome of verifying a policy bundle envelope. These values
// map 1:1 to the ApplyResult.Status enum in
// api/relay/control/v1/control.proto and must be kept stable: the wire
// protocol and any stored audit records depend on their meaning never
// changing.
type Code int

const (
	// CodeAccept means the envelope passed every check and Result.Bundle
	// is populated.
	CodeAccept Code = iota
	// CodeRejectedSignature covers: payloadType mismatch is NOT this
	// code (that is schema); an invalid or threshold-unmet signature, an
	// unobtainable trust Verifier (e.g. expired root metadata), or a
	// required-but-unimplemented transparency-log proof.
	CodeRejectedSignature
	// CodeRejectedTarget means the host was not in the bundle's target
	// list, or the bundle's scope is not one of the host's allowed
	// scopes.
	CodeRejectedTarget
	// CodeRejectedEpoch means the bundle's epoch was not strictly
	// greater than the host's current epoch for that scope, or the epoch
	// source itself returned an error.
	CodeRejectedEpoch
	// CodeRejectedExpired means the bundle is not yet valid or is past
	// its expiry, outside the allowed clock skew.
	CodeRejectedExpired
	// CodeRejectedSchema covers every structural problem: oversized
	// envelope, malformed JSON, unknown/duplicate fields, bad base64,
	// invalid UUIDs, policy count/size/name/hash problems, and
	// unsupported Tetragon version.
	CodeRejectedSchema
	// CodeRejectedGuardrail means the bundle passed every check above
	// but was rejected by the Guardrails implementation (step 2 of this
	// project; a fake is used in this step's tests).
	CodeRejectedGuardrail
)

// String returns the stable, upper-snake-case name used in logs, tests, and
// the proto mapping.
func (c Code) String() string {
	switch c {
	case CodeAccept:
		return "ACCEPT"
	case CodeRejectedSignature:
		return "REJECTED_SIGNATURE"
	case CodeRejectedTarget:
		return "REJECTED_TARGET"
	case CodeRejectedEpoch:
		return "REJECTED_EPOCH"
	case CodeRejectedExpired:
		return "REJECTED_EXPIRED"
	case CodeRejectedSchema:
		return "REJECTED_SCHEMA"
	case CodeRejectedGuardrail:
		return "REJECTED_GUARDRAIL"
	default:
		return "UNKNOWN"
	}
}

// Result is the outcome of Verify.
type Result struct {
	Code Code
	// Reason is a short, bounded, human-readable explanation. It never
	// contains more than limits.MaxReasonBytes of attacker-controlled
	// content (truncated and escaped) and is safe to log.
	Reason string
	// Bundle is populated only when Code == CodeAccept.
	Bundle *Bundle
}
