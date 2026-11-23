//go:build !linux

package tetra

import (
	"context"
	"errors"
	"testing"
)

// TestDial_UnsupportedOnNonLinux documents and exercises dial_other.go's
// stub. dial_linux.go's own Dial (the production implementation) is only
// compiled and tested on linux; see dial_linux_test.go (build-tagged
// linux) and docs/reports/step-03.md section 13 for how that side is
// verified instead (real CI on ubuntu-24.04, not this development machine).
func TestDial_UnsupportedOnNonLinux(t *testing.T) {
	_, err := Dial(context.Background(), Config{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Dial on a non-linux platform returned %v, want wrapping ErrUnavailable", err)
	}
}
