//go:build testtools

package main

import (
	"time"

	"github.com/bshlisky/tetragon-relay/internal/testvectors"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// hybridRootBundle holds a built, signed root envelope whose TARGETS role
// requires both ecdsa-p384 and mldsa-87 (step 4 prompt Part B3's
// require_keytypes, B6's required hybrid test vectors), plus the raw
// material used to build it.
type hybridRootBundle struct {
	envelope []byte
	rootKeys []*testKey // ecdsa-p384; root role itself stays ecdsa-p384-only (Part B5)
	ecdsaTgt []*testKey
	mldsaTgt []*testKey
	logKeys  []*testKey
}

// buildHybridRoot builds a root whose targets role lists ecdsaCount
// ecdsa-p384 keys and mldsaCount mldsa-87 keys, with the given threshold
// and require_keytypes = ["ecdsa-p384", "mldsa-87"].
func buildHybridRoot(version int, expires time.Time, targetsThreshold, ecdsaCount, mldsaCount int) (*hybridRootBundle, error) {
	r1, r2, r3, err := threeP384Keys()
	if err != nil {
		return nil, err
	}
	l1, err := newP384Key()
	if err != nil {
		return nil, err
	}
	ecdsaTgt := make([]*testKey, 0, ecdsaCount)
	for i := 0; i < ecdsaCount; i++ {
		k, err := newP384Key()
		if err != nil {
			return nil, err
		}
		ecdsaTgt = append(ecdsaTgt, k)
	}
	mldsaTgt := make([]*testKey, 0, mldsaCount)
	for i := 0; i < mldsaCount; i++ {
		k, err := newMLDSA87Key()
		if err != nil {
			return nil, err
		}
		mldsaTgt = append(mldsaTgt, k)
	}

	allTgt := append(append([]*testKey{}, ecdsaTgt...), mldsaTgt...)
	allKeys := append([]*testKey{r1, r2, r3, l1}, allTgt...)

	spec := rootSpec{
		version: version,
		expires: expires,
		keys:    allKeys,
		root:    roleOf([]*testKey{r1, r2, r3}, 2),
		targets: roleWithKeyTypes(allTgt, targetsThreshold, "ecdsa-p384", "mldsa-87"),
		log:     roleOf([]*testKey{l1}, 1),
	}
	payload, err := buildRootPayload(spec)
	if err != nil {
		return nil, err
	}
	env, err := signEnvelope(rootPayloadType, payload, r1, r2)
	if err != nil {
		return nil, err
	}
	return &hybridRootBundle{envelope: env, rootKeys: []*testKey{r1, r2, r3}, ecdsaTgt: ecdsaTgt, mldsaTgt: mldsaTgt, logKeys: []*testKey{l1}}, nil
}

// cloneKeyAsType returns a copy of k with its declared keytype overridden —
// used to build "declared keytype does not match SPKI" and "unknown
// keytype" vectors (step 4 prompt Part B6) without hand-rolling raw JSON.
// The clone's id is left unchanged (KeyID depends only on the DER bytes,
// never the declared keytype), so it still matches its own SPKI's derived
// ID exactly; only the "keytype" field the root payload declares differs.
func cloneKeyAsType(k *testKey, declaredType string) *testKey {
	clone := *k
	clone.keyType = declaredType
	return &clone
}

func hybridVector(name, desc string, kind testvectors.Kind) testvectors.Vector {
	return testvectors.Vector{
		Name:            name,
		Kind:            kind,
		Description:     desc,
		HostUUID:        stdHost,
		AllowedScopes:   []string{stdScope},
		TetragonVersion: "1.4.0",
		CurrentEpoch:    5,
		Now:             baseNow.Format(time.RFC3339),
	}
}

func hybridBundleSpec() bundleSpec {
	return bundleSpec{
		bundleID:           "pb-test-hybrid-0001",
		epoch:              10,
		scope:              stdScope,
		hostUUIDs:          []string{stdHost},
		notBefore:          baseNow.Add(-1 * time.Hour),
		expires:            baseNow.Add(24 * time.Hour),
		tetragonMinVersion: "1.3.0",
		mode:               "enforce",
		policies:           []policyPayload{newPolicy("hybrid-policy", 1, validPolicyYAML("hybrid-policy", 64), "")},
	}
}

// generateHybridVectors implements step 4 prompt Part B6's crypto-agility
// vectors: a hybrid (ecdsa-p384 + mldsa-87) targets role, every required
// satisfied/rejected combination, a keytype/SPKI mismatch, an unknown
// keytype, and a root rotation into a hybrid targets role (accepted) vs.
// signed only by the new root keys (rejected).
func generateHybridVectors(dir string) error {
	hybridRoot, err := buildHybridRoot(1, baseNow.Add(365*24*time.Hour), 2, 2, 2)
	if err != nil {
		return err
	}
	e1, e2 := hybridRoot.ecdsaTgt[0], hybridRoot.ecdsaTgt[1]
	m1, m2 := hybridRoot.mldsaTgt[0], hybridRoot.mldsaTgt[1]

	// 1. hybrid_role_satisfied: one ecdsa-p384 signature and one
	// mldsa-87 signature, meeting both the distinct-key threshold (2)
	// and require_keytypes (both types present).
	{
		payload, err := buildBundlePayload(hybridBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, e1, m1)
		if err != nil {
			return err
		}
		v := hybridVector("hybrid_role_satisfied", "Targets role requires threshold 2 plus at least one signature each of ecdsa-p384 and mldsa-87; signed by one of each. Must be accepted.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(hybridRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeAccept.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 2. hybrid_role_only_ecdsa_signature: threshold (2) met by two
	// ecdsa-p384 signatures, but require_keytypes also needs mldsa-87.
	{
		payload, err := buildBundlePayload(hybridBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, e1, e2)
		if err != nil {
			return err
		}
		v := hybridVector("hybrid_role_only_ecdsa_signature", "Two valid ecdsa-p384 signatures meet the distinct-key threshold, but require_keytypes also needs mldsa-87, which is absent. Must be rejected.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(hybridRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 3. hybrid_role_only_mldsa_signature: the mirror image of #2.
	{
		payload, err := buildBundlePayload(hybridBundleSpec())
		if err != nil {
			return err
		}
		env, err := signEnvelope(bundlePayloadType, payload, m1, m2)
		if err != nil {
			return err
		}
		v := hybridVector("hybrid_role_only_mldsa_signature", "Two valid mldsa-87 signatures meet the distinct-key threshold, but require_keytypes also needs ecdsa-p384, which is absent. Must be rejected.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(hybridRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 4. mldsa_signature_attributed_to_ecdsa_keyid: an mldsa-87
	// signature's bytes, claimed under an ecdsa-p384 key's keyid.
	// ecdsa.VerifyASN1 must reject the ML-DSA signature bytes as
	// malformed/invalid DER, so only the one genuinely valid mldsa-87
	// signature below counts, leaving the distinct-key threshold (2)
	// unmet.
	{
		payload, err := buildBundlePayload(hybridBundleSpec())
		if err != nil {
			return err
		}
		pae := paeFor(bundlePayloadType, payload)
		mldsaSigBytes, err := m2.sign(pae)
		if err != nil {
			return err
		}
		mislabeled := wireSignature{KeyID: e1.id, Sig: b64(mldsaSigBytes)}
		validSig, err := makeSig(m1, pae)
		if err != nil {
			return err
		}
		env, err := rawEnvelopeWithSigs(bundlePayloadType, payload, []wireSignature{mislabeled, validSig})
		if err != nil {
			return err
		}
		v := hybridVector("mldsa_signature_attributed_to_ecdsa_keyid", "An ML-DSA-87 signature's bytes are claimed under an ecdsa-p384 key's keyid. Verification dispatches on the KEY's keytype (never anything carried in the signature), so this is evaluated as an ECDSA signature and rejected as invalid, leaving the distinct-key threshold unmet.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(hybridRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 5. ecdsa_signature_attributed_to_mldsa_keyid: the mirror image of
	// #4 — an ECDSA DER signature claimed under an mldsa-87 key's
	// keyid, evaluated (and rejected) as an ML-DSA-87 signature.
	{
		payload, err := buildBundlePayload(hybridBundleSpec())
		if err != nil {
			return err
		}
		pae := paeFor(bundlePayloadType, payload)
		ecdsaSigBytes, err := e2.sign(pae)
		if err != nil {
			return err
		}
		mislabeled := wireSignature{KeyID: m1.id, Sig: b64(ecdsaSigBytes)}
		validSig, err := makeSig(e1, pae)
		if err != nil {
			return err
		}
		env, err := rawEnvelopeWithSigs(bundlePayloadType, payload, []wireSignature{mislabeled, validSig})
		if err != nil {
			return err
		}
		v := hybridVector("ecdsa_signature_attributed_to_mldsa_keyid", "An ECDSA-P384 signature's bytes are claimed under an mldsa-87 key's keyid; evaluated as an ML-DSA-87 signature and rejected as invalid, leaving the distinct-key threshold unmet.", testvectors.KindVerify)
		v.RootMetadataB64 = b64(hybridRoot.envelope)
		v.EnvelopeB64 = b64(env)
		v.ExpectedResult = verify.CodeRejectedSignature.String()
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 6. mldsa_keytype_spki_mismatch: a key entry declares "mldsa-87"
	// but its SPKI is genuinely ECDSA P-384 DER.
	{
		realKey, err := newP384Key()
		if err != nil {
			return err
		}
		r1, r2, r3, err := threeP384Keys()
		if err != nil {
			return err
		}
		t1, err := newP384Key()
		if err != nil {
			return err
		}
		l1, err := newP384Key()
		if err != nil {
			return err
		}
		liar := cloneKeyAsType(realKey, "mldsa-87")
		spec := rootSpec{
			version: 1,
			expires: baseNow.Add(365 * 24 * time.Hour),
			keys:    []*testKey{r1, r2, r3, t1, l1, liar},
			root:    roleOf([]*testKey{r1, r2, r3}, 2),
			targets: roleOf([]*testKey{t1}, 1),
			log:     roleOf([]*testKey{l1}, 1),
		}
		payload, err := buildRootPayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(rootPayloadType, payload, r1, r2)
		if err != nil {
			return err
		}
		v := hybridVector("mldsa_keytype_spki_mismatch", "Root metadata contains a key declared keytype mldsa-87 whose SPKI is actually ECDSA P-384 DER.", testvectors.KindTrustLoad)
		v.RootMetadataB64 = b64(env)
		v.ExpectedError = "ErrKeytypeSPKIMismatch"
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 7. unknown_keytype_rejected: a key entry declares a keytype that
	// is neither ecdsa-p384 nor mldsa-87 at all.
	{
		realKey, err := newMLDSA87Key()
		if err != nil {
			return err
		}
		r1, r2, r3, err := threeP384Keys()
		if err != nil {
			return err
		}
		t1, err := newP384Key()
		if err != nil {
			return err
		}
		l1, err := newP384Key()
		if err != nil {
			return err
		}
		unknown := cloneKeyAsType(realKey, "dilithium3")
		spec := rootSpec{
			version: 1,
			expires: baseNow.Add(365 * 24 * time.Hour),
			keys:    []*testKey{r1, r2, r3, t1, l1, unknown},
			root:    roleOf([]*testKey{r1, r2, r3}, 2),
			targets: roleOf([]*testKey{t1}, 1),
			log:     roleOf([]*testKey{l1}, 1),
		}
		payload, err := buildRootPayload(spec)
		if err != nil {
			return err
		}
		env, err := signEnvelope(rootPayloadType, payload, r1, r2)
		if err != nil {
			return err
		}
		v := hybridVector("unknown_keytype_rejected", "Root metadata contains a key entry whose declared keytype (\"dilithium3\") is neither ecdsa-p384 nor mldsa-87.", testvectors.KindTrustLoad)
		v.RootMetadataB64 = b64(env)
		v.ExpectedError = "ErrUnknownKeyType"
		if err := saveChecked(dir, v); err != nil {
			return err
		}
	}

	// 8. root_update_ecdsa_to_hybrid_accept: the old root's targets role
	// is ecdsa-p384-only; the new root's targets role is hybrid. The
	// update envelope is signed by a threshold of BOTH the old and the
	// new root-role key sets simultaneously (four signatures total),
	// satisfying Part B3's "same requirement applies to both the old
	// and the new root roles" for the ROOT role (unchanged, ecdsa-only
	// both sides) while the TARGETS role itself becomes hybrid.
	{
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
			targets: roleWithKeyTypes([]*testKey{oldT1}, 1, "ecdsa-p384"),
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
		newE1, err := newP384Key()
		if err != nil {
			return err
		}
		newE2, err := newP384Key()
		if err != nil {
			return err
		}
		newM1, err := newMLDSA87Key()
		if err != nil {
			return err
		}
		newM2, err := newMLDSA87Key()
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
			keys:    []*testKey{newR1, newR2, newR3, newE1, newE2, newM1, newM2, newL1},
			root:    roleOf([]*testKey{newR1, newR2, newR3}, 2),
			targets: roleWithKeyTypes([]*testKey{newE1, newE2, newM1, newM2}, 2, "ecdsa-p384", "mldsa-87"),
			log:     roleOf([]*testKey{newL1}, 1),
		}
		newPayload, err := buildRootPayload(newSpec)
		if err != nil {
			return err
		}
		pae := paeFor(rootPayloadType, newPayload)
		var sigs []wireSignature
		for _, k := range []*testKey{oldR1, oldR2, newR1, newR2} {
			s, err := makeSig(k, pae)
			if err != nil {
				return err
			}
			sigs = append(sigs, s)
		}
		newEnv, err := rawEnvelopeWithSigs(rootPayloadType, newPayload, sigs)
		if err != nil {
			return err
		}

		v := testvectors.Vector{
			Name:        "root_update_ecdsa_to_hybrid_accept",
			Kind:        testvectors.KindTrustUpdate,
			Description: "Root rotation whose new targets role becomes hybrid (ecdsa-p384 + mldsa-87, require_keytypes both), signed by a threshold of both the old and the new root-role key sets. Must be accepted.",
			Now:         baseNow.Format(time.RFC3339),
		}
		v.RootMetadataB64 = b64(oldEnv)
		v.NewRootMetadataB64 = b64(newEnv)
		v.ExpectedError = ""
		if err := saveChecked(dir, v); err != nil {
			return err
		}

		// 9. root_update_only_new_hybrid_keys_reject: identical new
		// root, but the update envelope is signed only by the NEW
		// root-role keys, never the old ones.
		var newOnlySigs []wireSignature
		for _, k := range []*testKey{newR1, newR2} {
			s, err := makeSig(k, pae)
			if err != nil {
				return err
			}
			newOnlySigs = append(newOnlySigs, s)
		}
		newOnlyEnv, err := rawEnvelopeWithSigs(rootPayloadType, newPayload, newOnlySigs)
		if err != nil {
			return err
		}
		v2 := testvectors.Vector{
			Name:        "root_update_only_new_hybrid_keys_reject",
			Kind:        testvectors.KindTrustUpdate,
			Description: "Same hybrid root rotation as root_update_ecdsa_to_hybrid_accept, but the update envelope is signed only by the new root-role keys, never a threshold of the old ones. Must be rejected.",
			Now:         baseNow.Format(time.RFC3339),
		}
		v2.RootMetadataB64 = b64(oldEnv)
		v2.NewRootMetadataB64 = b64(newOnlyEnv)
		v2.ExpectedError = "ErrOldThresholdNotMet"
		if err := saveChecked(dir, v2); err != nil {
			return err
		}
	}

	return nil
}
