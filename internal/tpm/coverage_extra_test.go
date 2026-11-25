package tpm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestCurveParams_UnknownCurveIsError(t *testing.T) {
	if _, _, _, _, _, err := curveParams("bogus-curve"); err == nil {
		t.Fatalf("curveParams(\"bogus-curve\") unexpectedly succeeded")
	}
}

func TestLoadHostSigner_UnknownCurveInBlobIsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	blob := hostSignerBlobFile{Schema: hostSignerSchema, Curve: "bogus-curve", Public: "AA==", Private: "AA=="}
	b, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFileAtomic(blobPath, b, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	if _, err := NewOrLoadHostSigner(rtpm, blobPath); err == nil {
		t.Fatalf("NewOrLoadHostSigner with an unknown curve in the blob unexpectedly succeeded")
	}
}

func TestLoadHostSigner_WrongSchemaIsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	blob := hostSignerBlobFile{Schema: "wrong.schema.v0", Curve: CurveP384, Public: "AA==", Private: "AA=="}
	b, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFileAtomic(blobPath, b, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	if _, err := NewOrLoadHostSigner(rtpm, blobPath); err == nil {
		t.Fatalf("NewOrLoadHostSigner with wrong schema unexpectedly succeeded")
	}
}

func TestLoadHostSigner_CorruptJSONIsError(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")
	if err := writeFileAtomic(blobPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	rtpm := startSWTPM(t)
	if _, err := NewOrLoadHostSigner(rtpm, blobPath); err == nil {
		t.Fatalf("NewOrLoadHostSigner with corrupt JSON unexpectedly succeeded")
	}
}

func TestWriteFileAtomic_RenameOntoDirectoryIsError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := writeFileAtomic(target, []byte("x"), 0o600); err == nil {
		t.Fatalf("writeFileAtomic renaming onto a directory unexpectedly succeeded")
	}
}

func TestRotateHostSigner_DetectCurveFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	alwaysFail := &alwaysFailCommand{inner: rtpm, failCommand: cc(tpm2.TPMCCTestParms)}
	dir := t.TempDir()
	if _, err := RotateHostSigner(alwaysFail, filepath.Join(dir, "new.json")); !errors.Is(err, ErrNoSupportedSigningCurve) {
		t.Fatalf("err = %v, want ErrNoSupportedSigningCurve", err)
	}
}

func TestNewOrLoadHostSigner_CreateFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	alwaysFail := &alwaysFailCommand{inner: rtpm, failCommand: cc(tpm2.TPMCCTestParms)}
	dir := t.TempDir()
	if _, err := NewOrLoadHostSigner(alwaysFail, filepath.Join(dir, "new.json")); !errors.Is(err, ErrNoSupportedSigningCurve) {
		t.Fatalf("err = %v, want ErrNoSupportedSigningCurve", err)
	}
}

func TestFlushSRK_InvalidHandleIsError(t *testing.T) {
	rtpm := startSWTPM(t)
	// A transient handle value that was never created by CreatePrimary
	// in this session: flushing it must fail, not silently succeed.
	if err := FlushSRK(rtpm, tpm2.TPMHandle(0x80FFFFFF)); err == nil {
		t.Fatalf("FlushSRK on a never-created handle unexpectedly succeeded")
	}
}

func TestCreateHostSigner_SealFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCCreate), failOnCall: 1}
	dir := t.TempDir()
	if err := createHostSigner(f, filepath.Join(dir, "new.json")); !errors.Is(err, ErrTPMCommand) {
		t.Fatalf("err = %v, want ErrTPMCommand", err)
	}
}

func TestCreateHostSigner_CreateSRKFailureSurfaces(t *testing.T) {
	rtpm := startSWTPM(t)
	f := &faultTPM{inner: rtpm, failCommand: cc(tpm2.TPMCCCreatePrimary), failOnCall: 1}
	dir := t.TempDir()
	if err := createHostSigner(f, filepath.Join(dir, "new.json")); err == nil {
		t.Fatalf("createHostSigner unexpectedly succeeded despite CreatePrimary failure")
	}
}
