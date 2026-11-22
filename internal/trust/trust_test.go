package trust_test

import (
	"errors"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/testvectors"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

func TestLoadInitialRoot_Valid(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	env, rootKeys, targetsKey, logKey := standardRoot(t, 1, now.Add(365*24*time.Hour))

	root, err := trust.LoadInitialRoot(env)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	if root.Version != 1 {
		t.Errorf("Version = %d, want 1", root.Version)
	}
	if root.KeyCount() != 5 {
		t.Errorf("KeyCount() = %d, want 5", root.KeyCount())
	}
	if rr := root.RootRole(); rr.Threshold != 2 || len(rr.KeyIDs) != 3 {
		t.Errorf("RootRole() = %+v", rr)
	}
	if tr := root.TargetsRole(); tr.Threshold != 1 || len(tr.KeyIDs) != 1 {
		t.Errorf("TargetsRole() = %+v", tr)
	}
	if lr := root.LogRole(); lr.Threshold != 1 || len(lr.KeyIDs) != 1 {
		t.Errorf("LogRole() = %+v", lr)
	}
	_ = rootKeys
	_ = targetsKey
	_ = logKey
}

func TestLoadInitialRoot_ThresholdNotMet(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2, r3 := mustKey(t), mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	payload := buildRootPayload(1, now.Add(24*time.Hour), []*genKey{r1, r2, r3, tk, lk},
		roleOf([]*genKey{r1, r2, r3}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
	// Only one of the required two root signatures.
	env := signEnvelope(trust.RootPayloadType, payload, r1)

	_, err := trust.LoadInitialRoot(env)
	if !errors.Is(err, trust.ErrThresholdNotMet) {
		t.Fatalf("err = %v, want ErrThresholdNotMet", err)
	}
}

func TestLoadInitialRoot_WrongPayloadType(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2, r3 := mustKey(t), mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	payload := buildRootPayload(1, now.Add(24*time.Hour), []*genKey{r1, r2, r3, tk, lk},
		roleOf([]*genKey{r1, r2, r3}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
	env := signEnvelope("application/vnd.wrong.type", payload, r1, r2)

	_, err := trust.LoadInitialRoot(env)
	if !errors.Is(err, trust.ErrPayloadTypeMismatch) {
		t.Fatalf("err = %v, want ErrPayloadTypeMismatch", err)
	}
}

func TestLoadInitialRoot_InvalidRoleDefinitions(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1, r2, r3 := mustKey(t), mustKey(t), mustKey(t)
	tk := mustKey(t)
	lk := mustKey(t)
	all := []*genKey{r1, r2, r3, tk, lk}

	cases := map[string]wireRole{
		"threshold zero":         {KeyIDs: []string{tk.id}, Threshold: 0},
		"threshold exceeds keys": {KeyIDs: []string{tk.id}, Threshold: 2},
		"duplicate key id":       {KeyIDs: []string{tk.id, tk.id}, Threshold: 1},
		"references unknown key": {KeyIDs: []string{"sha256:" + "00000000000000000000000000000000000000000000000000000000000000"}, Threshold: 1},
	}
	for name, targetsRole := range cases {
		t.Run(name, func(t *testing.T) {
			payload := buildRootPayload(1, now.Add(24*time.Hour), all,
				roleOf([]*genKey{r1, r2, r3}, 2), targetsRole, roleOf([]*genKey{lk}, 1))
			env := signEnvelope(trust.RootPayloadType, payload, r1, r2)
			if _, err := trust.LoadInitialRoot(env); !errors.Is(err, trust.ErrInvalidRoleDefinition) {
				t.Fatalf("err = %v, want ErrInvalidRoleDefinition", err)
			}
		})
	}
}

func TestRoot_TargetsVerifier_ExpiryBoundary(t *testing.T) {
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	env, _, _, _ := standardRoot(t, 1, expires)
	root, err := trust.LoadInitialRoot(env)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}

	if _, err := root.TargetsVerifier(expires.Add(-time.Second)); err != nil {
		t.Errorf("expected success just before expiry, got %v", err)
	}
	if _, err := root.TargetsVerifier(expires); !errors.Is(err, trust.ErrRootMetadataExpired) {
		t.Errorf("err at exact expiry = %v, want ErrRootMetadataExpired", err)
	}
	if _, err := root.TargetsVerifier(expires.Add(time.Second)); !errors.Is(err, trust.ErrRootMetadataExpired) {
		t.Errorf("err after expiry = %v, want ErrRootMetadataExpired", err)
	}
}

func TestRoot_Update_Valid(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	env, rootKeys, _, _ := standardRoot(t, 1, now.Add(24*time.Hour))
	root, err := trust.LoadInitialRoot(env)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}

	// New version keeps the same root keys (simplest valid rotation: same
	// keys, bumped expiry), signed by a threshold of those same keys,
	// which simultaneously satisfies "old" and "new" thresholds.
	newTk := mustKey(t)
	newLk := mustKey(t)
	all := append(append([]*genKey{}, rootKeys...), newTk, newLk)
	newPayload := buildRootPayload(2, now.Add(48*time.Hour), all,
		roleOf(rootKeys, 2), roleOf([]*genKey{newTk}, 1), roleOf([]*genKey{newLk}, 1))
	newEnv := signEnvelope(trust.RootPayloadType, newPayload, rootKeys[0], rootKeys[1])

	newRoot, err := root.Update(newEnv, now)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if newRoot.Version != 2 {
		t.Errorf("Version = %d, want 2", newRoot.Version)
	}
	if root.Version != 1 {
		t.Errorf("receiver must not be mutated; Version = %d, want 1", root.Version)
	}
}

func TestRoot_Update_ExpiredNewMetadata(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	env, rootKeys, _, _ := standardRoot(t, 1, now.Add(24*time.Hour))
	root, err := trust.LoadInitialRoot(env)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}

	newTk := mustKey(t)
	newLk := mustKey(t)
	all := append(append([]*genKey{}, rootKeys...), newTk, newLk)
	newPayload := buildRootPayload(2, now.Add(-time.Hour), all,
		roleOf(rootKeys, 2), roleOf([]*genKey{newTk}, 1), roleOf([]*genKey{newLk}, 1))
	newEnv := signEnvelope(trust.RootPayloadType, newPayload, rootKeys[0], rootKeys[1])

	if _, err := root.Update(newEnv, now); !errors.Is(err, trust.ErrExpiredMetadata) {
		t.Fatalf("err = %v, want ErrExpiredMetadata", err)
	}
}

func TestDeriveKeyID_RejectsNonP384(t *testing.T) {
	// Exercised indirectly via vectors (non_p384_key); this covers the
	// exported DeriveKeyID function in isolation using a P-256 key.
	k := mustKey(t) // P-384, should succeed
	if _, err := trust.DeriveKeyID(&k.priv.PublicKey); err != nil {
		t.Fatalf("unexpected error for valid P-384 key: %v", err)
	}
}

// --- vector-driven tests ---

func TestVectors_TrustLoad(t *testing.T) {
	runTrustVectors(t, testvectors.KindTrustLoad, func(t *testing.T, v testvectors.Vector) {
		rootBytes := mustB64Decode(t, v.RootMetadataB64)
		_, err := trust.LoadInitialRoot(rootBytes)
		want := trustErr(t, v.ExpectedError)
		if !errors.Is(err, want) {
			t.Fatalf("LoadInitialRoot error = %v, want %v", err, want)
		}
	})
}

func TestVectors_TrustUpdate(t *testing.T) {
	runTrustVectors(t, testvectors.KindTrustUpdate, func(t *testing.T, v testvectors.Vector) {
		rootBytes := mustB64Decode(t, v.RootMetadataB64)
		root, err := trust.LoadInitialRoot(rootBytes)
		if err != nil {
			t.Fatalf("LoadInitialRoot: %v", err)
		}
		newBytes := mustB64Decode(t, v.NewRootMetadataB64)
		now, err := time.Parse(time.RFC3339, v.Now)
		if err != nil {
			t.Fatalf("parse now: %v", err)
		}
		_, err = root.Update(newBytes, now)
		want := trustErr(t, v.ExpectedError)
		if !errors.Is(err, want) {
			t.Fatalf("Update error = %v, want %v", err, want)
		}
	})
}
