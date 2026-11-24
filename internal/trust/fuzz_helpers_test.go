package trust_test

import (
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/trust"
)

type rootSeedPair struct {
	initial   []byte
	candidate []byte
}

// syntheticRootSeeds builds a handful of small, varied root metadata
// documents (differing key counts, role shapes and thresholds) to give
// FuzzRootUpdate a cheaper, more diverse starting corpus than the
// several-KB, multi-key documents in testdata/vectors alone (step 1 review
// A9).
func syntheticRootSeeds(f *testing.F) []rootSeedPair {
	f.Helper()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	expires := now.Add(365 * 24 * time.Hour)

	var seeds []rootSeedPair

	// Minimal: 1 root key (threshold 1), 1 targets key, 1 log key.
	{
		r1 := mustKey(f)
		tk := mustKey(f)
		lk := mustKey(f)
		payload := buildRootPayload(1, expires, []*genKey{r1, tk, lk},
			roleOf([]*genKey{r1}, 1), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
		env := signEnvelope(trust.RootPayloadType, payload, r1)
		seeds = append(seeds, rootSeedPair{initial: env})
	}

	// 2 root keys, threshold 2; small candidate update with a disjoint
	// key set, signed by both old keys.
	{
		r1, r2 := mustKey(f), mustKey(f)
		tk, lk := mustKey(f), mustKey(f)
		payload := buildRootPayload(1, expires, []*genKey{r1, r2, tk, lk},
			roleOf([]*genKey{r1, r2}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
		env := signEnvelope(trust.RootPayloadType, payload, r1, r2)

		newTk, newLk := mustKey(f), mustKey(f)
		newPayload := buildRootPayload(2, expires, []*genKey{r1, r2, newTk, newLk},
			roleOf([]*genKey{r1, r2}, 2), roleOf([]*genKey{newTk}, 1), roleOf([]*genKey{newLk}, 1))
		newEnv := signEnvelope(trust.RootPayloadType, newPayload, r1, r2)

		seeds = append(seeds, rootSeedPair{initial: env, candidate: newEnv})
	}

	// 3 root keys, threshold 1 (low threshold, many keys): a different
	// role shape than the committed vectors' 2-of-3.
	{
		r1, r2, r3 := mustKey(f), mustKey(f), mustKey(f)
		tk, lk := mustKey(f), mustKey(f)
		payload := buildRootPayload(1, expires, []*genKey{r1, r2, r3, tk, lk},
			roleOf([]*genKey{r1, r2, r3}, 1), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
		env := signEnvelope(trust.RootPayloadType, payload, r1)
		seeds = append(seeds, rootSeedPair{initial: env})
	}

	return seeds
}

// hybridRootSeeds builds small root metadata documents exercising the
// crypto-agile format (step 4 Part B, FuzzRootV2): ML-DSA-87-only keys, a
// hybrid targets role (require_keytypes ["ecdsa-p384","mldsa-87"]), and a
// root rotation into a hybrid targets role — so the fuzzer's mutations
// start from inputs that actually exercise parseTrustedKey's ASN.1
// SPKI-algorithm parsing and verifyRoleThreshold's require_keytypes
// handling, not just the pre-Part-B ECDSA-only shapes above.
func hybridRootSeeds(f *testing.F) []rootSeedPair {
	f.Helper()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	expires := now.Add(365 * 24 * time.Hour)

	var seeds []rootSeedPair

	// ML-DSA-87-only root: every key (root, targets, log) is mldsa-87.
	{
		r1 := mustMLDSAKey(f)
		tk := mustMLDSAKey(f)
		lk := mustMLDSAKey(f)
		payload := buildRootPayload(1, expires, []*genKey{r1, tk, lk},
			roleOf([]*genKey{r1}, 1), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
		env := signEnvelope(trust.RootPayloadType, payload, r1)
		seeds = append(seeds, rootSeedPair{initial: env})
	}

	// Hybrid targets role: root/log stay ecdsa-p384 (Part B5's
	// production shape); targets requires one of each type.
	{
		r1, r2 := mustKey(f), mustKey(f)
		e1 := mustKey(f)
		m1 := mustMLDSAKey(f)
		lk := mustKey(f)
		payload := buildRootPayload(1, expires, []*genKey{r1, r2, e1, m1, lk},
			roleOf([]*genKey{r1, r2}, 2),
			roleWithKeyTypes([]*genKey{e1, m1}, 2, "ecdsa-p384", "mldsa-87"),
			roleOf([]*genKey{lk}, 1))
		env := signEnvelope(trust.RootPayloadType, payload, r1, r2)
		seeds = append(seeds, rootSeedPair{initial: env})
	}

	// Root rotation from an ecdsa-only targets role to a hybrid one,
	// signed by both the old and new root key sets (the accepted shape
	// from root_update_ecdsa_to_hybrid_accept.json).
	{
		r1, r2 := mustKey(f), mustKey(f)
		oldT := mustKey(f)
		lk := mustKey(f)
		oldPayload := buildRootPayload(1, expires, []*genKey{r1, r2, oldT, lk},
			roleOf([]*genKey{r1, r2}, 2), roleWithKeyTypes([]*genKey{oldT}, 1, "ecdsa-p384"), roleOf([]*genKey{lk}, 1))
		oldEnv := signEnvelope(trust.RootPayloadType, oldPayload, r1, r2)

		newR1, newR2 := mustKey(f), mustKey(f)
		newE := mustKey(f)
		newM := mustMLDSAKey(f)
		newL := mustKey(f)
		newPayload := buildRootPayload(2, expires, []*genKey{newR1, newR2, newE, newM, newL},
			roleOf([]*genKey{newR1, newR2}, 2),
			roleWithKeyTypes([]*genKey{newE, newM}, 2, "ecdsa-p384", "mldsa-87"),
			roleOf([]*genKey{newL}, 1))
		newEnv := signEnvelope(trust.RootPayloadType, newPayload, r1, r2, newR1, newR2)

		seeds = append(seeds, rootSeedPair{initial: oldEnv, candidate: newEnv})
	}

	return seeds
}
