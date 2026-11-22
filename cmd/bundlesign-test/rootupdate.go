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
// expectedError.
func genRootUpdateVector(dir, name, desc string, oldVersion, newVersion int, expectedError string, mode signMode) error {
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
		expires: baseNow.Add(365 * 24 * time.Hour),
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
