package guard

import (
	"path"
	"strings"
)

// ambiguousValue reports whether v cannot be safely resolved to a single
// absolute path: contains ".." anywhere, or is empty, or is not absolute.
// Per "ambiguity: implement the interpretation that rejects more", any
// such value is treated by the caller as "could match a protected target"
// rather than attempting a best-effort resolution of it (step 2 prompt
// Part C's path normalization rules).
func ambiguousValue(v string) bool {
	return v == "" || strings.Contains(v, "..") || !strings.HasPrefix(v, "/")
}

// normalizePathValue cleans and usrmerge-canonicalizes an absolute,
// unambiguous path value for comparison against protectedBinaries/
// protectedPaths.
func normalizePathValue(v string) string {
	return canonicalizeUsrmerge(path.Clean(v))
}

// coversEqual reports whether an Equal/In-style value v names exactly
// target, or names a specific path inside target when target is a
// directory (trailing "/").
func coversEqual(v, target string) bool {
	if ambiguousValue(v) {
		return true
	}
	nv := normalizePathValue(v)
	if strings.HasSuffix(target, "/") {
		return nv == strings.TrimSuffix(target, "/") || strings.HasPrefix(nv, target)
	}
	return nv == target
}

// coversPrefix reports whether a Prefix-style value v could match target:
// either v is an ancestor of (or equal to) target, or v names something
// nested inside target (target is itself an ancestor of v). Covers both
// "Prefix '/usr/sbin/' matches sshd" and "Prefix names a path already
// inside a protected directory" shapes.
func coversPrefix(v, target string) bool {
	if ambiguousValue(v) {
		return true
	}
	nv := normalizePathValue(v)
	t := strings.TrimSuffix(target, "/")
	return strings.HasPrefix(target, nv) || strings.HasPrefix(nv, t)
}

// coversPostfix reports whether a Postfix-style value v could match
// target: target's own path ends with the literal suffix v. Postfix
// values are not required to be absolute (e.g. a bare filename like
// "tetragon.sock"), but ".." and the empty string are still rejected as
// ambiguous/universal.
func coversPostfix(v, target string) bool {
	if v == "" || strings.Contains(v, "..") {
		return true
	}
	return strings.HasSuffix(strings.TrimSuffix(target, "/"), v) || strings.HasSuffix(target, v)
}

// canonicalTargets normalizes a protected-set list (the compiled-in list
// plus any trust-root extension, G9) so entries using either usrmerge
// spelling compare equal to a normalized selector value. Protected paths
// keep their trailing "/" (it is meaningful: it marks a directory), so
// normalization here must not run them through path.Clean, which would
// strip it.
func canonicalTargets(builtin, extra []string) []string {
	out := make([]string, 0, len(builtin)+len(extra))
	for _, t := range builtin {
		out = append(out, canonicalizeTarget(t))
	}
	for _, t := range extra {
		out = append(out, canonicalizeTarget(t))
	}
	return out
}

func canonicalizeTarget(t string) string {
	if strings.HasSuffix(t, "/") {
		return canonicalizeUsrmerge(t)
	}
	return normalizePathValue(t)
}

// anyBinaryCovered reports whether operator/values could ever match any
// protected binary (plus any from extraBinaries, G9).
func anyBinaryCovered(operator string, values []string, extraBinaries []string) bool {
	return anyCovered(operator, values, canonicalTargets(protectedBinaries, extraBinaries))
}

// anyPathCovered reports whether operator/values could ever match any
// protected path (plus any from extraPaths, G9).
func anyPathCovered(operator string, values []string, extraPaths []string) bool {
	return anyCovered(operator, values, canonicalTargets(protectedPaths, extraPaths))
}

func anyCovered(operator string, values []string, targets []string) bool {
	for _, v := range values {
		for _, t := range targets {
			switch operator {
			case "In", "Equal":
				if coversEqual(v, t) {
					return true
				}
			case "Prefix":
				if coversPrefix(v, t) {
					return true
				}
			case "Postfix":
				if coversPostfix(v, t) {
					return true
				}
			}
		}
	}
	return false
}

// excludesAllBinaries reports whether a NotIn/NotPrefix/NotPostfix
// operator's values correctly exclude every protected binary (plus
// extraBinaries): required for G1's negative-operator branch to be safe.
func excludesAllBinaries(operator string, values []string, extraBinaries []string) bool {
	targets := canonicalTargets(protectedBinaries, extraBinaries)
	for _, t := range targets {
		excluded := false
		for _, v := range values {
			switch operator {
			case "NotIn":
				if coversEqual(v, t) {
					excluded = true
				}
			case "NotPrefix":
				if coversPrefix(v, t) {
					excluded = true
				}
			case "NotPostfix":
				if coversPostfix(v, t) {
					excluded = true
				}
			}
			if excluded {
				break
			}
		}
		if !excluded {
			return false
		}
	}
	return true
}
