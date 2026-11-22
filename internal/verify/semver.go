package verify

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// semverPattern is the official semver.org regular expression for
// MAJOR.MINOR.PATCH[-prerelease][+build].
var semverPattern = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
		`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`,
)

type semver struct {
	major, minor, patch uint64
	prerelease          []string // nil means "no prerelease" (release build)
}

// parseSemver parses a strict semver.org MAJOR.MINOR.PATCH version, with
// optional prerelease and build metadata. Build metadata is parsed but
// ignored for comparison, per the semver spec.
//
// internal/verify implements this in-house rather than depending on an
// external semver module: the project's dependency policy
// (docs/decisions/0001-dependencies.md) prefers the standard library, and
// strict MAJOR.MINOR.PATCH comparison with correct prerelease precedence is
// a small, fully reviewable amount of code.
func parseSemver(s string) (semver, error) {
	m := semverPattern.FindStringSubmatch(s)
	if m == nil {
		return semver{}, fmt.Errorf("verify: %q is not a valid semantic version", s)
	}
	major, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return semver{}, err
	}
	minor, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil {
		return semver{}, err
	}
	patch, err := strconv.ParseUint(m[3], 10, 64)
	if err != nil {
		return semver{}, err
	}
	sv := semver{major: major, minor: minor, patch: patch}
	if m[4] != "" {
		sv.prerelease = strings.Split(m[4], ".")
	}
	return sv, nil
}

// isNumericIdentifier reports whether s consists only of ASCII digits, per
// the semver precedence rules for prerelease identifiers.
func isNumericIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func compareIdentifier(a, b string) int {
	aNum, bNum := isNumericIdentifier(a), isNumericIdentifier(b)
	switch {
	case aNum && bNum:
		// Numeric identifiers are compared numerically; both are
		// bounded by the regex to decimal digit sequences, and in
		// practice tiny, so comparing by length then lexically after
		// stripping leading zeros (impossible here, see regex) is
		// equivalent to numeric comparison without a parse that could
		// overflow.
		if len(a) != len(b) {
			if len(a) < len(b) {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	case aNum && !bNum:
		return -1 // numeric identifiers have lower precedence
	case !aNum && bNum:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

// comparePrerelease implements semver.org precedence rule 11 for
// prerelease identifier lists.
func comparePrerelease(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdentifier(a[i], b[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// compareSemver returns -1, 0, or 1 as a is less than, equal to, or greater
// than b, following semver.org precedence (a version with a prerelease is
// always lower precedence than the same MAJOR.MINOR.PATCH without one).
func compareSemver(a, b semver) int {
	switch {
	case a.major != b.major:
		return cmpUint64(a.major, b.major)
	case a.minor != b.minor:
		return cmpUint64(a.minor, b.minor)
	case a.patch != b.patch:
		return cmpUint64(a.patch, b.patch)
	}
	switch {
	case len(a.prerelease) == 0 && len(b.prerelease) == 0:
		return 0
	case len(a.prerelease) == 0:
		return 1 // a is a release, b is a prerelease: a > b
	case len(b.prerelease) == 0:
		return -1
	default:
		return comparePrerelease(a.prerelease, b.prerelease)
	}
}

func cmpUint64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
