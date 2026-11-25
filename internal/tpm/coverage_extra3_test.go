package tpm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestNewKeySealer_StatGenericFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// blobPath's parent ("not-a-dir") is a regular file, not a
	// directory: os.Stat on blobPath fails with "not a directory", a
	// different error than os.ErrNotExist.
	blobPath := filepath.Join(notADir, "sealed.json")
	if _, err := NewKeySealer(rtpm, blobPath); err == nil {
		t.Fatalf("NewKeySealer unexpectedly succeeded with a non-directory parent")
	}
}

func TestKeySealer_UnsealWrongSchemaIsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed.json")
	blob := sealedKeyFile{Schema: "wrong.schema.v0", Public: "AA==", Private: "AA=="}
	b, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFileAtomic(blobPath, b, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	k := &KeySealer{t: rtpm, blobPath: blobPath}
	if _, err := k.Unseal(); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("err = %v, want ErrUnsealFailed", err)
	}
}

func TestKeySealer_UnsealBadPublicBase64IsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed.json")
	blob := sealedKeyFile{Schema: sealedKeySchema, Public: "not-base64!!", Private: "AA=="}
	b, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFileAtomic(blobPath, b, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	k := &KeySealer{t: rtpm, blobPath: blobPath}
	if _, err := k.Unseal(); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("err = %v, want ErrUnsealFailed", err)
	}
}

func TestKeySealer_UnsealBadPrivateBase64IsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed.json")
	blob := sealedKeyFile{Schema: sealedKeySchema, Public: "AA==", Private: "not-base64!!"}
	b, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFileAtomic(blobPath, b, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	k := &KeySealer{t: rtpm, blobPath: blobPath}
	if _, err := k.Unseal(); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("err = %v, want ErrUnsealFailed", err)
	}
}

func TestNewOrLoadHostSigner_StatGenericFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	blobPath := filepath.Join(notADir, "host-signer.json")
	if _, err := NewOrLoadHostSigner(rtpm, blobPath); err == nil {
		t.Fatalf("NewOrLoadHostSigner unexpectedly succeeded with a non-directory parent")
	}
}

func TestLoadHostSigner_MissingFileIsError(t *testing.T) {
	rtpm := startSWTPM(t)
	dir := t.TempDir()
	if _, err := loadHostSigner(rtpm, filepath.Join(dir, "missing.json")); err == nil {
		t.Fatalf("loadHostSigner unexpectedly succeeded against a missing file")
	}
}

func TestLoadHostSigner_BadPublicBase64IsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	blob := hostSignerBlobFile{Schema: hostSignerSchema, Curve: CurveP384, Public: "not-base64!!", Private: "AA=="}
	b, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFileAtomic(blobPath, b, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	if _, err := loadHostSigner(rtpm, blobPath); err == nil {
		t.Fatalf("loadHostSigner unexpectedly succeeded with bad public base64")
	}
}

func TestLoadHostSigner_BadPrivateBase64IsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	blob := hostSignerBlobFile{Schema: hostSignerSchema, Curve: CurveP384, Public: "AA==", Private: "not-base64!!"}
	b, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFileAtomic(blobPath, b, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	if _, err := loadHostSigner(rtpm, blobPath); err == nil {
		t.Fatalf("loadHostSigner unexpectedly succeeded with bad private base64")
	}
}

func TestLoadHostSigner_UnparsablePublicAreaIsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	blob := hostSignerBlobFile{Schema: hostSignerSchema, Curve: CurveP384, Public: "AAAA", Private: "AA=="}
	b, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFileAtomic(blobPath, b, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	if _, err := loadHostSigner(rtpm, blobPath); err == nil {
		t.Fatalf("loadHostSigner unexpectedly succeeded with an unparsable public area")
	}
}

func TestKeySealer_UnsealOpenSRKFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	if _, err := ProvisionSRK(rtpm, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "sealed.json")
	if _, err := NewKeySealer(rtpm, blobPath); err != nil {
		t.Fatalf("NewKeySealer: %v", err)
	}
	// Unseal looks up the already-provisioned, persistent SRK via
	// TPM2_ReadPublic (OpenSRK) rather than creating one (ADR 0029): a
	// failure there must surface as ErrUnsealFailed, not a silent
	// fallback to creating a new SRK under the owner hierarchy.
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCReadPublic), failOnCall: 1}
	k := &KeySealer{t: f, blobPath: blobPath}
	if _, err := k.Unseal(); !errors.Is(err, ErrUnsealFailed) {
		t.Fatalf("err = %v, want ErrUnsealFailed", err)
	}
}
