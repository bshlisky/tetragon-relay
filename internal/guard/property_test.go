package guard

import (
	"math/rand"
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

// TestProperty_G1EqualsBruteForce checks that checkSelectorG1's accept/
// reject decision for the binary-matching step equals the brute-force
// "exists a protected binary b such that matches(op, values, b)" formula,
// over randomly generated operators and values (architect review item
// C1's property test requirement).
func TestProperty_G1EqualsBruteForce(t *testing.T) {
	operators := []string{"In", "Equal", "Prefix", "Postfix", "NotIn", "NotEqual", "NotPrefix", "NotPostfix"}
	alphabet := []string{
		"/usr/sbin/sshd", "/sbin/sshd", "/usr/sbin/", "/sbin/", "sshd", "d",
		"/usr/sbin/init", "/usr/bin/tetra", "", "relative", "/usr", "x",
	}

	rng := rand.New(rand.NewSource(2))
	const trials = 5000
	for i := 0; i < trials; i++ {
		op := operators[rng.Intn(len(operators))]
		n := 1 + rng.Intn(3)
		values := make([]string, n)
		for j := range values {
			values[j] = alphabet[rng.Intn(len(alphabet))]
		}

		// Brute force: unsafe values always reject; otherwise, exists a
		// protected binary the (cleaned) selector would match.
		bruteForceRejects := hasUnsafeValue(op, values)
		if !bruteForceRejects {
			bruteForceRejects = matchesAnyCandidate(op, values, protectedBinaries)
		}

		s := policydoc.Selector{
			MatchBinaries: []policydoc.BinarySelector{{Operator: op, Values: values}},
			MatchActions:  []policydoc.ActionSelector{{Action: "Sigkill"}},
		}
		err := checkSelectorG1("p", "h", s, nil)
		gotRejects := err != nil

		if gotRejects != bruteForceRejects {
			t.Fatalf("operator=%s values=%v: checkSelectorG1 reject=%v, brute force reject=%v (err=%v)", op, values, gotRejects, bruteForceRejects, err)
		}
	}
}
