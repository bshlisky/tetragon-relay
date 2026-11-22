package verify_test

import (
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/testvectors"
	"github.com/bshlisky/tetragon-relay/internal/trust"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// FuzzVerifyEnvelope seeds from every committed verify vector's envelope
// bytes (valid and invalid alike) and asserts that Verify never panics on
// any mutation, using a fixed, valid trust root and epoch source so the
// fuzzer's mutations are exercising the envelope/payload parsing and check
// logic rather than just hitting "no trust configured" every time.
func FuzzVerifyEnvelope(f *testing.F) {
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		f.Fatalf("load vectors: %v", err)
	}
	seeded := 0
	for _, v := range vectors {
		if v.Kind != testvectors.KindVerify {
			continue
		}
		b, err := decodeB64Fuzz(f, v.EnvelopeB64)
		if err != nil {
			f.Fatalf("decode envelope: %v", err)
		}
		f.Add(b)
		seeded++
	}
	if seeded == 0 {
		f.Fatalf("no verify vectors found in %s", vectorsDir)
	}

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	rootEnv, _ := edgeRootForFuzz(now.Add(365 * 24 * time.Hour))
	root, err := trust.LoadInitialRoot(rootEnv)
	if err != nil {
		f.Fatalf("LoadInitialRoot: %v", err)
	}
	tv, err := root.TargetsVerifier(now)
	if err != nil {
		f.Fatalf("TargetsVerifier: %v", err)
	}

	f.Fuzz(func(t *testing.T, envelope []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Verify panicked on envelope %q: %v", envelope, r)
			}
		}()
		_ = verify.Verify(verify.Input{
			Envelope:        envelope,
			Now:             now,
			HostUUID:        edgeHost,
			AllowedScopes:   []string{edgeScope},
			TetragonVersion: "1.4.0",
			Trust:           tv,
			Epochs:          fakeEpochSource{current: 5},
		})
	})
}
