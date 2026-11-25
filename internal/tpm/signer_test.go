package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestHostSigner_FirstBootSignVerifyAndPersistAcrossReopen(t *testing.T) {
	tt := startSWTPM(t)
	if _, err := ProvisionSRK(tt, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")

	hs, err := NewOrLoadHostSigner(tt, blobPath)
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner (first boot): %v", err)
	}
	// swtpm/libtpms supports P-384, so this project's preferred curve
	// must actually be chosen, not a silent fallback.
	if hs.Curve() != CurveP384 {
		t.Fatalf("Curve() = %q, want %q (this TPM supports P-384)", hs.Curve(), CurveP384)
	}

	pub, ok := hs.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", hs.Public())
	}

	msg := []byte("tetragon-relay host signing key test message")
	digest := sha512.Sum384(msg)
	sig, err := hs.Sign(nil, digest[:], crypto.SHA384)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !verifyASN1ECDSA(t, pub, digest[:], sig) {
		t.Fatalf("signature does not verify against the reported public key")
	}

	// Re-open against the same blob (simulating an agent restart): same
	// key, same public point, must still sign+verify.
	hs2, err := NewOrLoadHostSigner(tt, blobPath)
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner (reopen): %v", err)
	}
	pub2 := hs2.Public().(*ecdsa.PublicKey)
	if !pub.Equal(pub2) {
		t.Fatalf("public key changed across reopen")
	}
	sig2, err := hs2.Sign(nil, digest[:], crypto.SHA384)
	if err != nil {
		t.Fatalf("Sign (reopen): %v", err)
	}
	if !verifyASN1ECDSA(t, pub2, digest[:], sig2) {
		t.Fatalf("signature from reopened signer does not verify")
	}
}

func TestHostSigner_KeyCannotBeDuplicated(t *testing.T) {
	tt := startSWTPM(t)
	if _, err := ProvisionSRK(tt, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "host-signer.json")

	hs, err := NewOrLoadHostSigner(tt, blobPath)
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner: %v", err)
	}

	srkHandle, srkName, err := CreateSRK(tt)
	if err != nil {
		t.Fatalf("CreateSRK: %v", err)
	}
	defer func() { _ = FlushSRK(tt, srkHandle) }()

	load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    tpm2.TPM2BPrivate{Buffer: hs.privBytes},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](hs.pubBytes),
	}
	loadRsp, err := load.Execute(tt)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() {
		fc := tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}
		_, _ = fc.Execute(tt)
	}()

	// fixedTPM is set (signingKeyTemplate): TPM2_Duplicate must refuse,
	// proving the private key can never be exported from this TPM.
	dup := tpm2.Duplicate{
		ObjectHandle:    tpm2.AuthHandle{Handle: loadRsp.ObjectHandle, Name: loadRsp.Name, Auth: tpm2.PasswordAuth(nil)},
		NewParentHandle: tpm2.NamedHandle{Handle: srkHandle, Name: srkName},
		Symmetric:       tpm2.TPMTSymDef{Algorithm: tpm2.TPMAlgNull},
	}
	if _, err := dup.Execute(tt); err == nil {
		t.Fatalf("TPM2_Duplicate unexpectedly succeeded on a fixedTPM signing key")
	}
}

func TestHostSigner_RotateCreatesNewKeyAndRetireRemovesOld(t *testing.T) {
	tt := startSWTPM(t)
	if _, err := ProvisionSRK(tt, nil); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	dir := t.TempDir()
	activePath := filepath.Join(dir, "host-signer.json")
	retiredPath := filepath.Join(dir, "host-signer.retired.json")

	original, err := NewOrLoadHostSigner(tt, activePath)
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner: %v", err)
	}
	originalPub := original.Public().(*ecdsa.PublicKey)

	rotated, err := RotateHostSigner(tt, retiredPath+".new")
	if err != nil {
		t.Fatalf("RotateHostSigner: %v", err)
	}
	rotatedPub := rotated.Public().(*ecdsa.PublicKey)
	if originalPub.Equal(rotatedPub) {
		t.Fatalf("rotated key has the SAME public point as the original -- rotation did not create a new key")
	}

	// The original blob is untouched by RotateHostSigner itself; it must
	// still load and sign (docs/prompts/step-05a.md C4: "keep the old
	// one until told to retire it").
	stillOld, err := NewOrLoadHostSigner(tt, activePath)
	if err != nil {
		t.Fatalf("NewOrLoadHostSigner (original, after rotation): %v", err)
	}
	stillOldPub := stillOld.Public().(*ecdsa.PublicKey)
	if !originalPub.Equal(stillOldPub) {
		t.Fatalf("original key blob changed after RotateHostSigner wrote a different path")
	}

	if err := RetireHostSigner(retiredPath + ".new"); err != nil {
		t.Fatalf("RetireHostSigner: %v", err)
	}
	if _, err := os.Stat(retiredPath + ".new"); !os.IsNotExist(err) {
		t.Fatalf("retired key blob still exists after RetireHostSigner: stat err = %v", err)
	}
	// RetireHostSigner on an already-retired (missing) blob is a clear
	// error, not silently ignored.
	if err := RetireHostSigner(retiredPath + ".new"); err == nil {
		t.Fatalf("RetireHostSigner on an already-missing blob unexpectedly succeeded")
	}
}

func TestDetectSigningCurve_PrefersP384(t *testing.T) {
	tt := startSWTPM(t)
	curve, err := detectSigningCurve(tt)
	if err != nil {
		t.Fatalf("detectSigningCurve: %v", err)
	}
	if curve != CurveP384 {
		t.Fatalf("detectSigningCurve = %q, want %q", curve, CurveP384)
	}
}

func verifyASN1ECDSA(t *testing.T, pub *ecdsa.PublicKey, digest, sig []byte) bool {
	t.Helper()
	return ecdsa.VerifyASN1(pub, digest, sig)
}
