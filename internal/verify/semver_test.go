package verify

import "testing"

func TestParseSemver_Valid(t *testing.T) {
	cases := []string{"1.0.0", "1.3.0", "0.0.1", "10.20.30", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0+build.1", "1.0.0-beta+exp.sha.5114f85"}
	for _, c := range cases {
		if _, err := parseSemver(c); err != nil {
			t.Errorf("parseSemver(%q) error: %v", c, err)
		}
	}
}

func TestParseSemver_Invalid(t *testing.T) {
	cases := []string{"", "1", "1.0", "v1.0.0", "1.0.0.0", "01.0.0", "1.0.0-", "not a version"}
	for _, c := range cases {
		if _, err := parseSemver(c); err == nil {
			t.Errorf("parseSemver(%q) expected error", c)
		}
	}
}

func TestParseSemver_Overflow(t *testing.T) {
	huge := "99999999999999999999" // exceeds uint64 range, still matches the regex
	cases := []string{huge + ".0.0", "0." + huge + ".0", "0.0." + huge}
	for _, c := range cases {
		if _, err := parseSemver(c); err == nil {
			t.Errorf("parseSemver(%q) expected overflow error", c)
		}
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.4.0", "1.3.0", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0+build1", "1.0.0+build2", 0}, // build metadata ignored
	}
	for _, c := range cases {
		a, err := parseSemver(c.a)
		if err != nil {
			t.Fatalf("parseSemver(%q): %v", c.a, err)
		}
		b, err := parseSemver(c.b)
		if err != nil {
			t.Fatalf("parseSemver(%q): %v", c.b, err)
		}
		if got := compareSemver(a, b); got != c.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsNumericIdentifier(t *testing.T) {
	cases := map[string]bool{
		"":    false,
		"0":   true,
		"123": true,
		"01":  true,
		"a":   false,
		"1a":  false,
		"-1":  false,
	}
	for in, want := range cases {
		if got := isNumericIdentifier(in); got != want {
			t.Errorf("isNumericIdentifier(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCompareIdentifier(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1", "1", 0},
		{"1", "2", -1},
		{"2", "1", 1},
		{"1", "10", -1},
		{"10", "1", 1},
		{"1", "alpha", -1},
		{"alpha", "1", 1},
		{"alpha", "beta", -1},
		{"beta", "alpha", 1},
		{"alpha", "alpha", 0},
	}
	for _, c := range cases {
		if got := compareIdentifier(c.a, c.b); got != c.want {
			t.Errorf("compareIdentifier(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestComparePrerelease_DifferentLengths(t *testing.T) {
	if got := comparePrerelease([]string{"alpha"}, []string{"alpha", "1"}); got != -1 {
		t.Errorf("got %d, want -1", got)
	}
	if got := comparePrerelease([]string{"alpha", "1"}, []string{"alpha"}); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestComparePrerelease_EqualLists(t *testing.T) {
	if got := comparePrerelease([]string{"alpha", "1"}, []string{"alpha", "1"}); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestCmpUint64(t *testing.T) {
	if cmpUint64(1, 2) != -1 || cmpUint64(2, 1) != 1 || cmpUint64(1, 1) != 0 {
		t.Fatalf("cmpUint64 basic cases failed")
	}
}
