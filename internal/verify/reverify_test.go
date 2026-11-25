package verify_test

import (
	"errors"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

func TestParseBundleUnverified_ValidEnvelopeRoundTrips(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	_, env := buildEdgeInput(t, validBundleJSON(""), now)

	bundle, err := verify.ParseBundleUnverified(env)
	if err != nil {
		t.Fatalf("ParseBundleUnverified: %v", err)
	}
	if bundle.BundleID != "pb-edge-0001" || bundle.Scope != edgeScope || bundle.Mode != "enforce" {
		t.Fatalf("bundle = %+v, want the fields from validBundleJSON", bundle)
	}
	if len(bundle.Policies) != 1 || bundle.Policies[0].Name != "edge-policy" {
		t.Fatalf("Policies = %+v, want one policy named edge-policy", bundle.Policies)
	}
}

func TestParseBundleUnverified_TooLarge(t *testing.T) {
	big := make([]byte, limits.MaxEnvelopeBytes+1)
	if _, err := verify.ParseBundleUnverified(big); !errors.Is(err, verify.ErrUnverifiedParseFailed) {
		t.Fatalf("err = %v, want ErrUnverifiedParseFailed", err)
	}
}

func TestParseBundleUnverified_MalformedEnvelope(t *testing.T) {
	if _, err := verify.ParseBundleUnverified([]byte("not an envelope at all")); !errors.Is(err, verify.ErrUnverifiedParseFailed) {
		t.Fatalf("err = %v, want ErrUnverifiedParseFailed", err)
	}
}

func TestParseBundleUnverified_WrongPayloadType(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	rootEnv, tk := edgeRoot(t, false, now.Add(365*24*time.Hour))
	_ = rootEnv
	env := edgeSignEnvelope("application/vnd.relay.root.v1+json", []byte(validBundleJSON("")), tk)
	if _, err := verify.ParseBundleUnverified(env); !errors.Is(err, verify.ErrUnverifiedParseFailed) {
		t.Fatalf("err = %v, want ErrUnverifiedParseFailed", err)
	}
}

func TestParseBundleUnverified_MalformedPayload(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	_, tk := edgeRoot(t, false, now.Add(365*24*time.Hour))
	env := edgeSignEnvelope(verify.BundlePayloadType, []byte("not json"), tk)
	if _, err := verify.ParseBundleUnverified(env); !errors.Is(err, verify.ErrUnverifiedParseFailed) {
		t.Fatalf("err = %v, want ErrUnverifiedParseFailed", err)
	}
}

func TestParseBundleUnverified_WrongSchema(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	_, tk := edgeRoot(t, false, now.Add(365*24*time.Hour))
	base := map[string]string{
		"schema":    `"wrong.schema"`,
		"bundle_id": `"pb-x"`,
	}
	env := edgeSignEnvelope(verify.BundlePayloadType, []byte(mapToJSON(base)), tk)
	if _, err := verify.ParseBundleUnverified(env); !errors.Is(err, verify.ErrUnverifiedParseFailed) {
		t.Fatalf("err = %v, want ErrUnverifiedParseFailed", err)
	}
}

// ParseBundleUnverified performs NO signature check: an envelope signed by
// a key the caller does not even recognize still parses successfully, by
// design (re-verification's signature check is the CALLER's separate
// responsibility, against a specific historical root version).
func TestParseBundleUnverified_DoesNotCheckSignature(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	_, env := buildEdgeInput(t, validBundleJSON(""), now)
	// Corrupt the signature itself (not the payload): still parses fine,
	// since this function never looks at Signatures at all.
	bundle, err := verify.ParseBundleUnverified(env)
	if err != nil {
		t.Fatalf("ParseBundleUnverified: %v", err)
	}
	if bundle == nil {
		t.Fatalf("bundle = nil")
	}
}
