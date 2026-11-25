package tpm

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// hmacKeySize is the size of the store HMAC key this package generates on
// first boot (docs/prompts/step-05a.md C2: "a 48-byte HMAC key").
const hmacKeySize = 48

// sealedKeySchema identifies the on-disk sealed-key blob format.
const sealedKeySchema = "relay.tpm.sealed_key.v1"

// sealedKeyFile is the on-disk schema for the sealed HMAC key blob: a
// TPM2B_PUBLIC and TPM2B_PRIVATE pair, base64-encoded. It is not secret
// (docs/prompts/step-05a.md C2): the sensitive area is encrypted to the
// SRK by the TPM itself, and only this specific TPM can ever load and
// unseal it.
type sealedKeyFile struct {
	Schema  string `json:"schema"`
	Public  string `json:"public_b64"`
	Private string `json:"private_b64"`
}

// KeySealer implements store.KeySealer (internal/store/seal.go) by sealing
// the HMAC key to this host's TPM, under the project's persistent SRK
// (OpenSRK, docs/decisions/0029-no-tpm-owner-authorization-at-runtime.md)
// -- there is no cached key in this struct; see Unseal.
type KeySealer struct {
	t        transport.TPM
	blobPath string
}

// NewKeySealer opens (or, on first boot, creates) a TPM-sealed KeySealer
// whose sealed blob lives at blobPath (a file inside the store directory,
// architecture doc section 8.5 -- 0700 directory, this file 0600).
//
// First boot (blobPath does not exist): a fresh 48-byte HMAC key is
// generated with crypto/rand, sealed under a freshly created SRK, and
// written to blobPath (write-temp, fsync, rename, fsync dir -- the same
// crash-safety discipline internal/store's own blob writer uses). An
// index file or any other kind of read failure for an EXISTING blobPath
// is a hard error, never treated as first boot (mirroring
// internal/store's own "an index that is present but unreadable is never
// first boot" rule, Part C6): only a genuinely missing file triggers key
// generation.
func NewKeySealer(t transport.TPM, blobPath string) (*KeySealer, error) {
	k := &KeySealer{t: t, blobPath: blobPath}
	if _, err := os.Stat(blobPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("tpm: stat sealed key blob %s: %w", blobPath, err)
		}
		if err := k.firstBoot(); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func (k *KeySealer) firstBoot() error {
	key := make([]byte, hmacKeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("tpm: generate HMAC key: %w", err)
	}
	defer zero(key)

	srkHandle, srkName, err := OpenSRK(k.t)
	if err != nil {
		return err
	}

	create := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: key}),
			},
		},
		InPublic: sealedObjectTemplate(),
	}
	createRsp, err := create.Execute(k.t)
	if err != nil {
		return fmt.Errorf("%w: seal HMAC key: %w", ErrTPMCommand, err)
	}

	blob := sealedKeyFile{
		Schema:  sealedKeySchema,
		Public:  base64.StdEncoding.EncodeToString(createRsp.OutPublic.Bytes()),
		Private: base64.StdEncoding.EncodeToString(createRsp.OutPrivate.Buffer),
	}
	b, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("tpm: marshal sealed key blob: %w", err)
	}
	return writeFileAtomic(k.blobPath, b, 0o600)
}

// sealedObjectTemplate is the fixed template for the sealed HMAC key
// object: a KEYEDHASH object with a null scheme (a pure data blob, not an
// HMAC key the TPM itself would use), fixedTPM/fixedParent (never
// exportable from this TPM or re-parented to a different SRK).
func sealedObjectTemplate() tpm2.TPM2BPublic {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
		}),
	})
}

// Unseal implements store.KeySealer. It is called on every store Open and
// Save (that interface's own contract): rather than caching the key in
// k, it re-loads and re-unseals the blob under the persistent SRK every
// time, so there is exactly one place in this process' memory the key
// ever exists at once -- the slice this function returns.
func (k *KeySealer) Unseal() ([]byte, error) {
	raw, err := os.ReadFile(k.blobPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrSealedBlobMissing
		}
		return nil, fmt.Errorf("%w: read sealed key blob: %w", ErrUnsealFailed, err)
	}
	var blob sealedKeyFile
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("%w: parse sealed key blob: %w", ErrUnsealFailed, err)
	}
	if blob.Schema != sealedKeySchema {
		return nil, fmt.Errorf("%w: unexpected sealed key blob schema %q", ErrUnsealFailed, blob.Schema)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(blob.Public)
	if err != nil {
		return nil, fmt.Errorf("%w: decode sealed key public: %w", ErrUnsealFailed, err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(blob.Private)
	if err != nil {
		return nil, fmt.Errorf("%w: decode sealed key private: %w", ErrUnsealFailed, err)
	}

	srkHandle, srkName, err := OpenSRK(k.t)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsealFailed, err)
	}

	load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srkHandle, Name: srkName, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    tpm2.TPM2BPrivate{Buffer: privBytes},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes),
	}
	loadRsp, err := load.Execute(k.t)
	if err != nil {
		return nil, fmt.Errorf("%w: load sealed object: %w", ErrUnsealFailed, err)
	}
	defer func() {
		fc := tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}
		_, _ = fc.Execute(k.t)
	}()

	unseal := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: loadRsp.ObjectHandle, Name: loadRsp.Name, Auth: tpm2.PasswordAuth(nil)},
	}
	unsealRsp, err := unseal.Execute(k.t)
	if err != nil {
		return nil, fmt.Errorf("%w: unseal: %w", ErrUnsealFailed, err)
	}
	key := append([]byte(nil), unsealRsp.OutData.Buffer...)
	zero(unsealRsp.OutData.Buffer)
	return key, nil
}

// zero overwrites b with zero bytes in place. This is best-effort, not a
// guarantee against a copying garbage collector or compiler optimizations
// eliding the write (Go provides no hardened zeroization primitive at the
// time this was written), hence "where Go allows" in this package's own
// doc comment and docs/prompts/step-05a.md C2's wording.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// writeFileAtomic writes b to path using the same write-temp, fsync,
// rename, fsync-directory discipline internal/store's own blob/index
// writers use, so a crash mid-write never leaves a torn or truncated
// sealed-key blob: the next read sees either the old (missing, for first
// boot) or the fully-written new file, never a partial one.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) //nolint:gosec // G304: tmp is always derived from this package's own caller-supplied store-directory blob path, never untrusted input
	if err != nil {
		return fmt.Errorf("tpm: create temp file %s: %w", tmp, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("tpm: write temp file %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("tpm: fsync temp file %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("tpm: close temp file %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("tpm: rename %s to %s: %w", tmp, path, err)
	}
	df, err := os.Open(dir) //nolint:gosec // G304: dir is always derived from this package's own caller-supplied store-directory blob path, never untrusted input
	if err != nil {
		return fmt.Errorf("tpm: open dir %s for fsync: %w", dir, err)
	}
	defer func() { _ = df.Close() }()
	if err := df.Sync(); err != nil {
		return fmt.Errorf("tpm: fsync dir %s: %w", dir, err)
	}
	return nil
}
