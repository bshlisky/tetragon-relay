// Package limits centralizes every size, count and timing constant used by
// the policy-bundle verification and trust-metadata packages.
//
// Security responsibility: bound the resources an attacker-controlled
// message (a policy bundle envelope, trust-root update, or JSON payload) can
// consume before it is fully validated, and provide the single, reviewable
// source of truth for those bounds so internal/verify and internal/trust
// never diverge on what "too big" or "too deep" means.
//
// Invariants addressed: INV-1 (nothing is accepted that was not fully and
// correctly checked) depends on these bounds being enforced before parsing;
// loosely related to T-20 (DoS via oversized or deeply nested messages).
package limits
