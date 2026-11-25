package main

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/bshlisky/tetragon-relay/internal/config"
	"github.com/bshlisky/tetragon-relay/internal/identity"
)

// errNoProductionEnroller is noEnroller.Enroll's error: a clear, named
// reason an operator or this process's own audit log can match on,
// instead of an opaque network-dial failure.
var errNoProductionEnroller = errors.New("relayd: no production Enroller is configured (architecture doc 5.2/5.3 SPIRE/IdM enrollment is not yet wired into this binary)")

// noEnroller implements identity.Enroller by always refusing to enroll
// (C2: "no production Enroller exists yet... must not fall back to any
// test enroller"). It exists (rather than leaving CertManager
// unconstructed) so (*identity.CertManager).Load can still pick up a
// previously persisted identity chain if one exists on disk (e.g. from a
// future real enrollment flow, or an operator-provisioned chain) --
// identity.NewCertManager requires a non-nil Enroller even when the
// caller only ever intends to call Load, never Enroll/Rotate.
type noEnroller struct{}

// Enroll implements identity.Enroller.
func (noEnroller) Enroll(context.Context, []byte) ([]*x509.Certificate, error) {
	return nil, errNoProductionEnroller
}

// buildEnroller always returns noEnroller{}: this binary has no code path
// that constructs internal/identity.TestCA or any other Enroller outside
// of test files. internal/identity.TestCA (build tag testca) is used
// directly by internal/controlclient's own in-process integration test,
// never through this binary.
func buildEnroller(_ *config.Config) identity.Enroller { return noEnroller{} }
