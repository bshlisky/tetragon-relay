package tpm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestKeySealer_FirstBootThenUnsealRoundTrip(t *testing.T) {
	tt := startSWTPM(t)
	if _, err := ProvisionSRK(tt, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed-hmac-key.json")

	k, err := NewKeySealer(tt, blobPath)
	if err != nil {
		t.Fatalf("NewKeySealer (first boot): %v", err)
	}
	key1, err := k.Unseal()
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if len(key1) != hmacKeySize {
		t.Fatalf("Unseal key length = %d, want %d", len(key1), hmacKeySize)
	}

	// Re-open against the same blob (simulating an agent restart): must
	// unseal to the exact same key every time.
	k2, err := NewKeySealer(tt, blobPath)
	if err != nil {
		t.Fatalf("NewKeySealer (reopen): %v", err)
	}
	key2, err := k2.Unseal()
	if err != nil {
		t.Fatalf("Unseal (reopen): %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatalf("key changed across reopen: %x != %x", key1, key2)
	}

	// A second Unseal call on the SAME KeySealer must also return the
	// identical key (it re-derives from the TPM every time, never
	// caching -- but re-derivation must be deterministic).
	key3, err := k.Unseal()
	if err != nil {
		t.Fatalf("Unseal (again): %v", err)
	}
	if !bytes.Equal(key1, key3) {
		t.Fatalf("key changed across repeated Unseal: %x != %x", key1, key3)
	}
}

func TestKeySealer_UnsealMissingBlobIsErrSealedBlobMissing(t *testing.T) {
	tt := startSWTPM(t)
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed-hmac-key.json")

	k := &KeySealer{t: tt, blobPath: blobPath}
	if _, err := k.Unseal(); !errors.Is(err, ErrSealedBlobMissing) {
		t.Fatalf("err = %v, want ErrSealedBlobMissing", err)
	}
}

func TestKeySealer_UnsealCorruptBlobIsErrUnsealFailed(t *testing.T) {
	tt := startSWTPM(t)
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed-hmac-key.json")

	if err := writeFileAtomic(blobPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	k := &KeySealer{t: tt, blobPath: blobPath}
	if _, err := k.Unseal(); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("err = %v, want ErrUnsealFailed", err)
	}
}

func TestKeySealer_UnsealBitFlippedPrivateBlobIsErrUnsealFailed(t *testing.T) {
	tt := startSWTPM(t)
	if _, err := ProvisionSRK(tt, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed-hmac-key.json")

	k, err := NewKeySealer(tt, blobPath)
	if err != nil {
		t.Fatalf("NewKeySealer: %v", err)
	}
	if _, err := k.Unseal(); err != nil {
		t.Fatalf("initial Unseal: %v", err)
	}

	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	// Flip a byte well inside the base64 private blob field to corrupt
	// the sealed object's integrity-protected private area without
	// invalidating the surrounding JSON.
	idx := bytes.Index(raw, []byte(`"private_b64":"`))
	if idx < 0 {
		t.Fatalf("private_b64 field not found in blob")
	}
	valueStart := idx + len(`"private_b64":"`)
	tampered := append([]byte(nil), raw...)
	tampered[valueStart+5] = flipBase64Char(tampered[valueStart+5])
	if err := writeFileAtomic(blobPath, tampered, 0o600); err != nil {
		t.Fatalf("writeFileAtomic (tampered): %v", err)
	}

	k2 := &KeySealer{t: tt, blobPath: blobPath}
	if _, err := k2.Unseal(); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("err = %v, want ErrUnsealFailed (tampered private blob)", err)
	}
}

func flipBase64Char(b byte) byte {
	if b == 'A' {
		return 'B'
	}
	return 'A'
}
