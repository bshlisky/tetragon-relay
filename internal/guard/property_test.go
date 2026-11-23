package guard

import (
	"math/rand"
	"path"
	"strings"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/policydoc"
)

// referenceMatches is an independently-written reference implementation of
// the same operator semantics matches() implements, used to cross-check
// matches() (architect review item C1's property test requirement). It is
// deliberately written in a different style (no shared helpers) so a bug
// in matches() is unlikely to also be present here.
func referenceMatches(operator string, values []string, candidate string) bool {
	eq := func(v string) bool { return v == candidate }
	pre := func(v string) bool { return len(candidate) >= len(v) && candidate[:len(v)] == v }
	post := func(v string) bool { return len(candidate) >= len(v) && candidate[len(candidate)-len(v):] == v }

	anyTrue := func(f func(string) bool) bool {
		for _, v := range values {
			if f(v) {
				return true
			}
		}
		return false
	}

	switch operator {
	case "In", "Equal":
		return anyTrue(eq)
	case "Prefix":
		return anyTrue(pre)
	case "Postfix":
		return anyTrue(post)
	case "NotIn", "NotEqual":
		return !anyTrue(eq)
	case "NotPrefix":
		return !anyTrue(pre)
	case "NotPostfix":
		return !anyTrue(post)
	default:
		return false
	}
}

func TestProperty_MatchesAgreesWithReference(t *testing.T) {
	operators := []string{"In", "Equal", "Prefix", "Postfix", "NotIn", "NotEqual", "NotPrefix", "NotPostfix"}
	alphabet := []string{"/usr/sbin/sshd", "/sbin/", "sshd", "d", "", "/usr", "/usr/sbin/sshd-x", "x"}

	rng := rand.New(rand.NewSource(1))
	const trials = 20000
	for i := 0; i < trials; i++ {
		op := operators[rng.Intn(len(operators))]
		n := rng.Intn(4)
		values := make([]string, n)
		for j := range values {
			values[j] = alphabet[rng.Intn(len(alphabet))]
		}
		candidate := alphabet[rng.Intn(len(alphabet))]

		got := matches(op, values, candidate)
		want := referenceMatches(op, values, candidate)
		if got != want {
			t.Fatalf("matches(%q, %v, %q) = %v, want %v (reference)", op, values, candidate, got, want)
		}
	}
}

// referenceBinaryMatches independently implements Tetragon's raw-string
// matchBinaries operator semantics - pkg/selectors/kernel.go:1287-1309:
// Equal/NotEqual go through writeMatchStrings, Prefix/NotPrefix through
// writePrefixStrings, Postfix/NotPostfix through writePostfixStrings, all
// plain byte comparisons with no normalization of either side - against
// candidate. Architect review item D2: deliberately reimplemented here
// without calling or mirroring matches()/any other internal/guard helper,
// so a bug shared between the production code and this test's expectation
// cannot hide from the property check.
func referenceBinaryMatches(operator string, values []string, candidate string) bool {
	eq := func(v string) bool { return v == candidate }
	pre := func(v string) bool { return len(candidate) >= len(v) && candidate[:len(v)] == v }
	post := func(v string) bool { return len(candidate) >= len(v) && candidate[len(candidate)-len(v):] == v }
	anyTrue := func(f func(string) bool) bool {
		for _, v := range values {
			if f(v) {
				return true
			}
		}
		return false
	}
	switch operator {
	case "In", "Equal":
		return anyTrue(eq)
	case "Prefix":
		return anyTrue(pre)
	case "Postfix":
		return anyTrue(post)
	case "NotIn", "NotEqual":
		return !anyTrue(eq)
	case "NotPrefix":
		return !anyTrue(pre)
	case "NotPostfix":
		return !anyTrue(post)
	default:
		return false
	}
}

// referenceAnyBinaryMatches reports whether operator/values would match
// any of this project's actually-protected binaries, using only
// referenceBinaryMatches above.
func referenceAnyBinaryMatches(operator string, values []string) bool {
	for _, b := range protectedBinaries {
		if referenceBinaryMatches(operator, values, b) {
			return true
		}
	}
	return false
}

// referenceIsCanonicalValue independently re-expresses architect review
// item D1's canonical-value rule using only the standard library (not
// isCanonicalAnchoredValue/isCanonicalPostfixValue themselves): for
// In/Equal/NotIn/NotEqual, v must be absolute, contain no "..", and equal
// path.Clean(v); for Prefix/NotPrefix the same, except v may also equal
// path.Clean(v)+"/"; for Postfix/NotPostfix, v must be non-empty, contain
// no "..", and contain no "//" or "/./" or "/../" substring.
func referenceIsCanonicalValue(operator, v string) bool {
	if operator == "Postfix" || operator == "NotPostfix" {
		if v == "" || strings.Contains(v, "..") {
			return false
		}
		return !strings.Contains(v, "//") && !strings.Contains(v, "/./") && !strings.Contains(v, "/../")
	}
	if v == "" || !strings.HasPrefix(v, "/") || strings.Contains(v, "..") {
		return false
	}
	clean := path.Clean(v)
	if operator == "Prefix" || operator == "NotPrefix" {
		return v == clean || v == clean+"/"
	}
	return v == clean
}

// mutateSpelling returns a value derived from a real protected binary
// (base), reporting whether the result is non-canonical. At least 30% of
// calls, across a large sample, produce one of the four non-canonical
// spellings the architect's review reproduced (trailing "/", doubled "/",
// an inserted "/./" segment, an inserted "/../" segment); the rest produce
// either an unmodified canonical value or a different-but-canonical
// usrmerge spelling of the same binary (protected.go's usrmergeAlias),
// exercising the "different real candidate" path too.
func mutateSpelling(rng *rand.Rand, base string) (string, bool) {
	switch rng.Intn(10) {
	case 0, 1, 2, 3:
		switch rng.Intn(4) {
		case 0:
			return base + "/", true
		case 1:
			return "/" + base, true // doubles the leading slash
		case 2:
			idx := strings.Index(base[1:], "/") + 1
			return base[:idx] + "/." + base[idx:], true
		default:
			idx := strings.Index(base[1:], "/") + 1
			return base[:idx] + "/.." + base[idx:], true
		}
	case 4:
		if alias, ok := usrmergeAlias(base); ok {
			return alias, false
		}
		return base, false
	default:
		return base, false
	}
}

// TestProperty_G1RawStringSemantics is architect review item D2's rewrite
// of the G1 property test: the generator produces non-canonical spellings
// (trailing "/", "//", "/./", "/../") at least 30% of the time, and the
// assertion is checked against a from-scratch reference implementation
// that shares no code with internal/guard, in both directions: guard
// accepts iff the reference says no protected binary matches AND every
// value is already canonical.
func TestProperty_G1RawStringSemantics(t *testing.T) {
	operators := []string{"In", "Equal", "Prefix", "Postfix", "NotIn", "NotEqual", "NotPrefix", "NotPostfix"}
	rng := rand.New(rand.NewSource(3))
	const trials = 10000
	nonCanonicalCount := 0
	totalValues := 0

	for i := 0; i < trials; i++ {
		op := operators[rng.Intn(len(operators))]
		n := 1 + rng.Intn(3)
		values := make([]string, n)
		for j := range values {
			base := protectedBinaries[rng.Intn(len(protectedBinaries))]
			v, nonCanonical := mutateSpelling(rng, base)
			values[j] = v
			totalValues++
			if nonCanonical {
				nonCanonicalCount++
			}
		}

		allCanonical := true
		for _, v := range values {
			if !referenceIsCanonicalValue(op, v) {
				allCanonical = false
				break
			}
		}
		refSafe := allCanonical && !referenceAnyBinaryMatches(op, values)

		s := policydoc.Selector{
			MatchBinaries: []policydoc.BinarySelector{{Operator: op, Values: values}},
			MatchActions:  []policydoc.ActionSelector{{Action: "Sigkill"}},
		}
		err := checkSelectorG1("p", "h", s, nil)
		guardAccepts := err == nil

		if guardAccepts != refSafe {
			t.Fatalf("operator=%s values=%v: guard accepts=%v, reference safe (canonical and no match)=%v (err=%v)", op, values, guardAccepts, refSafe, err)
		}
	}

	frac := float64(nonCanonicalCount) / float64(totalValues)
	if frac < 0.30 {
		t.Fatalf("test construction error: only %.1f%% of generated values were non-canonical, want >= 30%%", frac*100)
	}
	t.Logf("G1 raw-string semantics property test: %d trials, %.1f%% of %d generated values non-canonical", trials, frac*100, totalValues)
}
