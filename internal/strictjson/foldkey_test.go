package strictjson

import (
	"math/rand"
	"strings"
	"testing"
)

// specialFoldRunes are runes with notable simple-case-folding behavior,
// used to stress-test foldKey against strings.EqualFold (step 1 review
// A11).
var specialFoldRunes = []rune{
	'a', 'A', 'z', 'Z', '0', '9', '-', '_', '.',
	'\u212A', // Kelvin sign, folds with 'k'/'K'
	'k', 'K',
	'\u017F', // Latin small letter long s, folds with 's'/'S'
	's', 'S',
	'\u0130', // Latin capital I with dot above (Turkish)
	'\u0131', // Latin small letter dotless i (Turkish)
	'i', 'I',
	'\u03C3', // Greek small sigma
	'\u03C2', // Greek small final sigma
	'\u03A3', // Greek capital sigma
	'\u00DF', // German sharp s (eszett) - simple fold is NOT "ss" (that's full folding)
}

func TestFoldKey_AgreesWithEqualFold_KnownPairs(t *testing.T) {
	pairs := []struct {
		a, b string
	}{
		{"scope", "SCOPE"},
		{"scope", "Scope"},
		{"\u017Fcope", "scope"},        // long s
		{"\u212Aeyid", "keyid"},        // Kelvin sign
		{"\u212AEYID", "keyid"},        // Kelvin sign, rest uppercase
		{"stra\u00DFe", "stra\u00DFe"}, // identical, contains eszett
	}
	for _, p := range pairs {
		want := strings.EqualFold(p.a, p.b)
		got := foldKey(p.a) == foldKey(p.b)
		if got != want {
			t.Errorf("foldKey agreement mismatch for (%q, %q): foldKey-equal=%v EqualFold=%v", p.a, p.b, got, want)
		}
	}
}

// TestFoldKey_PropertyAgreesWithEqualFold generates random strings built
// from specialFoldRunes (and a few ASCII fillers) and asserts that
// foldKey(a) == foldKey(b) if and only if strings.EqualFold(a, b), for many
// random pairs. This is the property required by step 1 review A11: foldKey
// must exactly capture the EqualFold relation, not merely approximate it.
func TestFoldKey_PropertyAgreesWithEqualFold(t *testing.T) {
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test data, not security-sensitive
	randString := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteRune(specialFoldRunes[rng.Intn(len(specialFoldRunes))])
		}
		return b.String()
	}

	const trials = 20000
	mismatches := 0
	for i := 0; i < trials; i++ {
		n := rng.Intn(5) + 1
		a := randString(n)
		b := randString(n)
		want := strings.EqualFold(a, b)
		got := foldKey(a) == foldKey(b)
		if got != want {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("mismatch for (%q, %q): foldKey-equal=%v EqualFold=%v", a, b, got, want)
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d/%d random pairs disagreed between foldKey and strings.EqualFold", mismatches, trials)
	}
}

func TestFoldKey_DeterministicAndSelfEqual(t *testing.T) {
	// foldKey must be a pure function (same input, same output across
	// calls), and every string must fold-equal itself under EqualFold.
	for _, r := range specialFoldRunes {
		s := string(r)
		first := foldKey(s)
		second := foldKey(string(append([]rune{}, r))) // same content, distinct string value
		if first != second {
			t.Fatalf("foldKey(%q) is not deterministic: %q vs %q", s, first, second)
		}
		if !strings.EqualFold(s, string(r)) {
			t.Fatalf("EqualFold(%q, %q) = false, want true", s, string(r))
		}
	}
}

func TestFoldKey_NeverPanics(t *testing.T) {
	inputs := []string{"", "\x00", "\xff\xfe", strings.Repeat("a", 1000), "\U0001F600"}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("foldKey(%q) panicked: %v", in, r)
				}
			}()
			_ = foldKey(in)
		}()
	}
}
