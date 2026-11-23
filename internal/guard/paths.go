package guard

import (
	"path"
	"strings"
)

// recognizedMatchOperators are every operator matches() implements.
// checkSelectorG1/checkSelectorG2 reject any other operator outright
// rather than let matches()'s default (false) silently treat an
// unrecognized operator as "never matches."
var recognizedMatchOperators = map[string]bool{
	"In": true, "Equal": true, "Prefix": true, "Postfix": true,
	"NotIn": true, "NotEqual": true, "NotPrefix": true, "NotPostfix": true,
}

// isUnsafeAnchoredValue reports whether v cannot be safely compared as an
// anchored (In/Equal/Prefix and their Not* forms) path value: empty,
// relative, or containing "..". Architect review (step 2b, item C1): such
// values must be rejected outright, for every operator, rather than fed
// into matching logic that treats "ambiguous" as "matches" — that
// conflation is exactly what made NotIn/NotPrefix fail open in step 2b
// (an ambiguous value was treated as trivially satisfying exclusion).
func isUnsafeAnchoredValue(v string) bool {
	return v == "" || strings.Contains(v, "..") || !strings.HasPrefix(v, "/")
}

// isUnsafePostfixValue is the Postfix/NotPostfix counterpart:
// Postfix values are legitimately not absolute (e.g. the bare filename
// "tetragon.sock"), so only empty and ".."-containing values are unsafe.
func isUnsafePostfixValue(v string) bool {
	return v == "" || strings.Contains(v, "..")
}

// hasUnsafeValue reports whether any value in values is unsafe for
// operator's family (C1's "reject outright" rule), checked before any
// matching is attempted.
func hasUnsafeValue(operator string, values []string) bool {
	postfix := operator == "Postfix" || operator == "NotPostfix"
	for _, v := range values {
		if postfix {
			if isUnsafePostfixValue(v) {
				return true
			}
		} else if isUnsafeAnchoredValue(v) {
			return true
		}
	}
	return false
}

// cleanAnchoredValues path.Cleans every value for the anchored operator
// families (not Postfix/NotPostfix, whose values are not path-shaped), so
// a sloppy-but-equivalent value ("/usr/sbin//sshd") cannot evade a literal
// string comparison against a clean candidate. Call only after
// hasUnsafeValue has confirmed every value is safe to clean (path.Clean on
// an empty or ".."-containing string is not a meaningful operation here).
func cleanAnchoredValues(operator string, values []string) []string {
	if operator == "Postfix" || operator == "NotPostfix" {
		return values
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = path.Clean(v)
	}
	return out
}

// matches reports whether operator/values, evaluated the way Tetragon
// itself evaluates a BinarySelector/ArgSelector against a resolved string
// (pkg/selectors/kernel.go:1287-1293: Equal/NotEqual on a
// path/file/string/linux_binprm-typed arg go through writeMatchStrings,
// an exact-string comparison; kernel.go:1300-1301: Prefix/NotPrefix go
// through writePrefixStrings; kernel.go:1305-1306: Postfix/NotPostfix go
// through writePostfixStrings), would match candidate.
//
// Negative operators are the boolean negation of their positive form
// evaluated against EVERY declared value: NotIn/NotEqual matches candidate
// iff candidate is not equal to any value — not "some value in the list
// looks ambiguous, so assume it matches" (the step 2b bug, architect
// review item C1). This single function is used for both "does a positive
// operator cover a protected target" and "does a negative operator fail to
// exclude a protected target" checks: both are just "would the selector,
// evaluated for real, match this candidate."
func matches(operator string, values []string, candidate string) bool {
	switch operator {
	case "In", "Equal":
		for _, v := range values {
			if candidate == v {
				return true
			}
		}
		return false
	case "Prefix":
		for _, v := range values {
			if strings.HasPrefix(candidate, v) {
				return true
			}
		}
		return false
	case "Postfix":
		for _, v := range values {
			if strings.HasSuffix(candidate, v) {
				return true
			}
		}
		return false
	case "NotIn", "NotEqual":
		for _, v := range values {
			if candidate == v {
				return false
			}
		}
		return true
	case "NotPrefix":
		for _, v := range values {
			if strings.HasPrefix(candidate, v) {
				return false
			}
		}
		return true
	case "NotPostfix":
		for _, v := range values {
			if strings.HasSuffix(candidate, v) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// matchesAnyCandidate reports whether operator/values (already known
// operator-safe; call hasUnsafeValue first) would match at least one of
// candidates, cleaning values for the anchored families first.
func matchesAnyCandidate(operator string, values []string, candidates []string) bool {
	cleaned := cleanAnchoredValues(operator, values)
	for _, c := range candidates {
		if matches(operator, cleaned, c) {
			return true
		}
	}
	return false
}

// pathCoversPositive implements architect review item C2's directory-aware
// coverage formula for a single POSITIVE operator (Equal/In/Prefix/Postfix)
// against one protected-path target, which may be a directory (trailing
// "/") or an exact file/device (no trailing "/"):
//
//   - directory D: In/Equal covers iff a value equals D or names a path
//     inside D (HasPrefix(v, D+"/")); Prefix covers iff a value is an
//     ancestor of (or equal to) D, or names something nested inside D;
//     Postfix ALWAYS covers, since some hypothetical file inside D could
//     end with any given suffix and D's contents are not enumerable here.
//   - exact file F: reuses matches() directly, which is already exactly
//     right for a single fixed candidate (including Postfix, which is
//     decidable for one known string, unlike an open-ended directory).
func pathCoversPositive(operator string, values []string, target string) bool {
	values = cleanAnchoredValues(operator, values)
	if !strings.HasSuffix(target, "/") {
		return matches(operator, values, target)
	}
	dir := strings.TrimSuffix(target, "/")
	switch operator {
	case "In", "Equal":
		for _, v := range values {
			if v == dir || strings.HasPrefix(v, dir+"/") {
				return true
			}
		}
		return false
	case "Prefix":
		for _, v := range values {
			if strings.HasPrefix(dir, v) || strings.HasPrefix(v, dir+"/") {
				return true
			}
		}
		return false
	case "Postfix":
		return true
	default:
		return false
	}
}

// anyPathCoveredPositive reports whether a positive operator/values could
// match something inside, or equal to, any protected path (including any
// G9 trust-root extension).
func anyPathCoveredPositive(operator string, values []string, extraPaths []string) bool {
	for _, t := range protectedPaths {
		if pathCoversPositive(operator, values, t) {
			return true
		}
	}
	for _, t := range extraPaths {
		if pathCoversPositive(operator, values, t) {
			return true
		}
	}
	return false
}
