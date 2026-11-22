package trust_test

import (
	"encoding/base64"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/testvectors"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

const vectorsDir = "../../testdata/vectors"

func mustB64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return b
}

var trustErrorsByName = map[string]error{
	"ErrUnsupportedKeyType":    trust.ErrUnsupportedKeyType,
	"ErrKeyIDMismatch":         trust.ErrKeyIDMismatch,
	"ErrThresholdNotMet":       trust.ErrThresholdNotMet,
	"ErrOldThresholdNotMet":    trust.ErrOldThresholdNotMet,
	"ErrNewThresholdNotMet":    trust.ErrNewThresholdNotMet,
	"ErrVersionRollback":       trust.ErrVersionRollback,
	"ErrVersionSkip":           trust.ErrVersionSkip,
	"ErrExpiredMetadata":       trust.ErrExpiredMetadata,
	"ErrMalformedMetadata":     trust.ErrMalformedMetadata,
	"ErrInvalidRoleDefinition": trust.ErrInvalidRoleDefinition,
	"ErrRootValidityTooLong":   trust.ErrRootValidityTooLong,
}

func trustErr(t *testing.T, name string) error {
	t.Helper()
	err, ok := trustErrorsByName[name]
	if !ok {
		t.Fatalf("unknown expected_error %q", name)
	}
	return err
}

func runTrustVectors(t *testing.T, kind testvectors.Kind, run func(t *testing.T, v testvectors.Vector)) {
	t.Helper()
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	found := 0
	for _, v := range vectors {
		if v.Kind != kind {
			continue
		}
		found++
		v := v
		t.Run(v.Name, func(t *testing.T) { run(t, v) })
	}
	if found == 0 {
		t.Fatalf("no vectors of kind %q found in %s", kind, vectorsDir)
	}
}
