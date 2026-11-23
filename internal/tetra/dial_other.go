//go:build !linux

package tetra

import (
	"context"
	"fmt"
	"runtime"
)

// Dial is only implemented on linux: step 3 prompt Part B2's socket
// verification (SO_PEERCRED, /proc/<pid>/exe, SELinux xattrs) is
// inherently Linux-specific, and architecture doc section 1.1 scopes this
// project to RHEL 9. This stub exists only so the package (and anything
// that imports it) builds and vets on a non-Linux development machine;
// internal/tetra's RPC-behavior tests use newClient directly against a
// fake gRPC server instead of calling Dial, so they are unaffected and run
// on every platform. dial_linux.go's own tests are Linux-only and run in
// the real CI job (ubuntu-24.04) that step 3's report documents.
func Dial(_ context.Context, _ Config) (*Client, error) {
	return nil, fmt.Errorf("%w: internal/tetra.Dial is only implemented on linux (GOOS=%s)", ErrUnavailable, runtime.GOOS)
}
