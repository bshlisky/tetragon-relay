package verify_test

import (
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/testvectors"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// TestProperty_SingleByteFlipNeverAccepts takes the "valid" vector's
// envelope and flips every single byte, one at a time, asserting that none
// of those mutations ever produces CodeAccept. This is the property
// required by the prompt: a validly-signed, validly-targeted bundle must
// stop being accepted the instant any single byte of its signed envelope
// changes.
func TestProperty_SingleByteFlipNeverAccepts(t *testing.T) {
	vectors, err := testvectors.LoadDir(vectorsDir)
	if err != nil {
		t.Fatalf("load vectors: %v", err)
	}
	var valid testvectors.Vector
	found := false
	for _, v := range vectors {
		if v.Name == "valid" {
			valid = v
			found = true
		}
	}
	if !found {
		t.Fatalf("valid vector not found")
	}

	original := mustDecode(t, valid.EnvelopeB64)
	baseline := buildInput(t, valid)
	if result := verify.Verify(baseline); result.Code != verify.CodeAccept {
		t.Fatalf("baseline valid vector did not ACCEPT: %s (%s)", result.Code, result.Reason)
	}

	accepted := 0
	for i := range original {
		mutated := make([]byte, len(original))
		copy(mutated, original)
		mutated[i] ^= 0xFF

		in := baseline
		in.Envelope = mutated
		result := verify.Verify(in)
		if result.Code == verify.CodeAccept {
			accepted++
			t.Errorf("byte %d flip unexpectedly produced ACCEPT", i)
		}
	}
	if accepted > 0 {
		t.Fatalf("%d/%d single-byte mutations were accepted; want 0", accepted, len(original))
	}
}
