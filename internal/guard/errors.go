package guard

import "fmt"

// RuleID identifies which guardrail (G1-G10) produced a violation.
type RuleID string

// The guardrail rule IDs from the step 2 prompt's Part C (G9 has no
// runtime check of its own: see internal/guard/interfaces.go's
// ProtectedSetSource doc comment) plus G10 (architect review item C5,
// added in the step 2c review pass: Override hook placement).
const (
	RuleG1  RuleID = "G1"  // protected processes
	RuleG2  RuleID = "G2"  // protected paths
	RuleG3  RuleID = "G3"  // unscoped exec denial
	RuleG4  RuleID = "G4"  // size limits
	RuleG5  RuleID = "G5"  // monitor-first
	RuleG6  RuleID = "G6"  // mode coherence
	RuleG7  RuleID = "G7"  // unknown action or hook type
	RuleG8  RuleID = "G8"  // capability check
	RuleG10 RuleID = "G10" // Override hook placement
)

// Violation is the typed error every guard rule returns on rejection. The
// Rule field is what internal/verify uses to map G8 to
// CodeRejectedCapability and everything else to CodeRejectedGuardrail
// (step 2 prompt Part C0), and what the Result reason string includes.
type Violation struct {
	Rule RuleID
	// Detail is a short, non-attacker-controlled-content description
	// (policy/hook/selector names from a policy are themselves
	// attacker-influenced but bounded by internal/limits well before
	// guard ever runs, and verify.go further bounds the final reason
	// string via boundReason).
	Detail string
}

func (v *Violation) Error() string {
	return fmt.Sprintf("guard: rule %s: %s", v.Rule, v.Detail)
}

func violation(rule RuleID, format string, args ...interface{}) *Violation {
	return &Violation{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}
