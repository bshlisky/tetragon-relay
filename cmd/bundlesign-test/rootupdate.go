//go:build testtools

package main

import (
	"time"

	"github.com/bshlisky/tetragon-relay/internal/testvectors"
)

func threeP384Keys() (a, b, c *testKey, err error) {
	if a, err = newP384Key(); err != nil {
		return
	}
	if b, err = newP384Key(); err != nil {
		return
	}
	if c, err = newP384Key(); err != nil {
		return
	}
	return
}

type signMode int

const (
	signOldKeys signMode = iota
	signNewKeys
)

// genRootUpdateVector builds an old root (oldVersion, its own key set) and a
// candidate new root (newVersion, a DIFFERENT key set), signs the new root's
// envelope with either the old or the new root key set per mode, and saves
// a KindTrustUpdate vector asserting (*trust.Root).Update returns
// expectedError. The new root's expiry is baseNow + 365 days; use
// genRootUpdateVectorWithExpiry to control it explicitly.
func genRootUpdateVector(dir, name, desc string, oldVersion, newVersion int, expectedError string, mode signMode) error {
	return genRootUpdateVectorWithExpiry(dir, name, desc, oldVersion, newVersion, baseNow.Add(365*24*time.Hour), expectedError, mode)
}

// genRootUpdateVectorWithExpiry is genRootUpdateVector with an explicit
// expiry for the candidate new root, so tests of the maximum-validity
// window (step 1 review A6) can set it arbitrarily far in the future.
func genRootUpdateVectorWithExpiry(dir, name, desc string, oldVersion, newVersion int, newExpires time.Time, expectedError string, mode signMode) error {
	oldR1, oldR2, oldR3, err := threeP384Keys()
	if err != nil {
		return err
	}
	oldT1, err := newP384Key()
	if err != nil {
		return err
	}
	oldL1, err := newP384Key()
	if err != nil {
		return err
	}
	oldSpec := rootSpec{
		version: oldVersion,
		expires: baseNow.Add(365 * 24 * time.Hour),
		keys:    []*testKey{oldR1, oldR2, oldR3, oldT1, oldL1},
		root:    roleOf([]*testKey{oldR1, oldR2, oldR3}, 2),
		targets: roleOf([]*testKey{oldT1}, 1),
		log:     roleOf([]*testKey{oldL1}, 1),
	}
	oldPayload, err := buildRootPayload(oldSpec)
	if err != nil {
		return err
	}
	oldEnv, err := signEnvelope(rootPayloadType, oldPayload, oldR1, oldR2)
	if err != nil {
		return err
	}

	newR1, newR2, newR3, err := threeP384Keys()
	if err != nil {
		return err
	}
	newT1, err := newP384Key()
	if err != nil {
		return err
	}
	newL1, err := newP384Key()
	if err != nil {
		return err
	}
	newSpec := rootSpec{
		version: newVersion,
		expires: newExpires,
		keys:    []*testKey{newR1, newR2, newR3, newT1, newL1},
		root:    roleOf([]*testKey{newR1, newR2, newR3}, 2),
		targets: roleOf([]*testKey{newT1}, 1),
		log:     roleOf([]*testKey{newL1}, 1),
	}
	newPayload, err := buildRootPayload(newSpec)
	if err != nil {
		return err
	}

	pae := paeFor(rootPayloadType, newPayload)
	var sigs []wireSignature
	switch mode {
	case signOldKeys:
		s1, err := makeSig(oldR1, pae)
		if err != nil {
			return err
		}
		s2, err := makeSig(oldR2, pae)
		if err != nil {
			return err
		}
		sigs = []wireSignature{s1, s2}
	case signNewKeys:
		s1, err := makeSig(newR1, pae)
		if err != nil {
			return err
		}
		s2, err := makeSig(newR2, pae)
		if err != nil {
			return err
		}
		sigs = []wireSignature{s1, s2}
	}
	newEnv, err := rawEnvelopeWithSigs(rootPayloadType, newPayload, sigs)
	if err != nil {
		return err
	}

	v := testvectors.Vector{
		Name:        name,
		Kind:        testvectors.KindTrustUpdate,
		Description: desc,
		Now:         baseNow.Format(time.RFC3339),
	}
	v.RootMetadataB64 = b64(oldEnv)
	v.NewRootMetadataB64 = b64(newEnv)
	v.ExpectedError = expectedError
	return saveChecked(dir, v)
}

// genRootUpdateVectorMissingKeyTypes builds a root rotation (version 1 to
// 2) whose NEW root's targets role omits require_keytypes entirely, signed
// by a threshold of both the old and the new root-role keys (so the only
// reason Update can reject it is the missing require_keytypes field).
// step-04a-review.md R4A-1: "a rotation whose new root omits it" must be
// rejected, keeping the persisted (old) root.
func genRootUpdateVectorMissingKeyTypes(dir string) error {
	oldR1, oldR2, oldR3, err := threeP384Keys()
	if err != nil {
		return err
	}
	oldT1, err := newP384Key()
	if err != nil {
		return err
	}
	oldL1, err := newP384Key()
	if err != nil {
		return err
	}
	oldSpec := rootSpec{
		version: 1,
		expires: baseNow.Add(365 * 24 * time.Hour),
		keys:    []*testKey{oldR1, oldR2, oldR3, oldT1, oldL1},
		root:    roleOf([]*testKey{oldR1, oldR2, oldR3}, 2),
		targets: roleOf([]*testKey{oldT1}, 1),
		log:     roleOf([]*testKey{oldL1}, 1),
	}
	oldPayload, err := buildRootPayload(oldSpec)
	if err != nil {
		return err
	}
	oldEnv, err := signEnvelope(rootPayloadType, oldPayload, oldR1, oldR2)
	if err != nil {
		return err
	}

	newR1, newR2, newR3, err := threeP384Keys()
	if err != nil {
		return err
	}
	newT1, err := newP384Key()
	if err != nil {
		return err
	}
	newL1, err := newP384Key()
	if err != nil {
		return err
	}
	newSpec := rootSpec{
		version: 2,
		expires: baseNow.Add(365 * 24 * time.Hour),
		keys:    []*testKey{newR1, newR2, newR3, newT1, newL1},
		root:    roleOf([]*testKey{newR1, newR2, newR3}, 2),
		// targets role omits require_keytypes entirely.
		targets: roleOfOmittingKeyTypes([]*testKey{newT1}, 1),
		log:     roleOf([]*testKey{newL1}, 1),
	}
	newPayload, err := buildRootPayload(newSpec)
	if err != nil {
		return err
	}

	pae := paeFor(rootPayloadType, newPayload)
	s1, err := makeSig(oldR1, pae)
	if err != nil {
		return err
	}
	s2, err := makeSig(oldR2, pae)
	if err != nil {
		return err
	}
	s3, err := makeSig(newR1, pae)
	if err != nil {
		return err
	}
	s4, err := makeSig(newR2, pae)
	if err != nil {
		return err
	}
	newEnv, err := rawEnvelopeWithSigs(rootPayloadType, newPayload, []wireSignature{s1, s2, s3, s4})
	if err != nil {
		return err
	}

	v := testvectors.Vector{
		Name:        "root_update_new_root_missing_require_keytypes",
		Kind:        testvectors.KindTrustUpdate,
		Description: "Root rotation to version 2 whose new root's targets role omits require_keytypes entirely, even though it is signed by a threshold of both the old and the new root-role keys. require_keytypes is mandatory on every role (step-04a-review.md R4A-1); the rotation must be rejected and the old (version 1) root kept.",
		Now:         baseNow.Format(time.RFC3339),
	}
	v.RootMetadataB64 = b64(oldEnv)
	v.NewRootMetadataB64 = b64(newEnv)
	v.ExpectedError = "ErrInvalidRequireKeyTypes"
	return saveChecked(dir, v)
}
