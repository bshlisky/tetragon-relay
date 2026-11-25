package identity

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// chainFileName is the name of the persisted certificate chain file
// inside Config.StoreDir (architecture doc 8.5: inside
// /var/lib/tetragon-relay/, 0700 directory, this file 0600).
const chainFileName = "host-cert-chain.pem"

// persistChain writes chain (public data only) as concatenated PEM blocks
// to dir/chainFileName, using the same write-temp/fsync/rename/fsync-dir
// discipline internal/store and internal/tpm already use, so a crash
// mid-write never leaves a torn file.
func persistChain(dir string, chain []*x509.Certificate) error {
	var buf []byte
	for _, c := range chain {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	path := filepath.Join(dir, chainFileName)
	return writeFileAtomic(path, buf, 0o600)
}

// LoadChain reads a previously persisted certificate chain from dir. It
// returns ErrNoPersistedChain if the file does not exist (first boot, no
// enrollment yet); any other read or parse failure is a hard error, never
// silently treated as "absent" (the same rule internal/tpm.KeySealer and
// internal/store apply to their own persisted state).
func LoadChain(dir string) ([]*x509.Certificate, error) {
	path := filepath.Join(dir, chainFileName)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is always derived from this package's own caller-supplied store-directory path, never untrusted input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoPersistedChain
		}
		return nil, fmt.Errorf("identity: read persisted chain %s: %w", path, err)
	}
	var chain []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("identity: persisted chain %s has unexpected PEM block type %q", path, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity: parse persisted chain %s: %w", path, err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("identity: persisted chain %s contains no certificates", path)
	}
	return chain, nil
}

// Load reads a previously persisted chain and, if one exists, makes it
// m's active chain WITHOUT re-validating it against the current time or
// trust bundle (the caller -- relayd's startup sequence, step 6 -- is
// expected to call ValidateLoadedChain itself if it wants that, since
// whether an already-expired persisted chain should still be treated as
// "the identity" during a transient renewal failure is a state-machine
// decision, not this package's to make unilaterally).
func (m *CertManager) Load() error {
	chain, err := LoadChain(m.cfg.StoreDir)
	if err != nil {
		return err
	}
	m.chain = chain
	return nil
}

// writeFileAtomic writes b to path using write-temp, fsync, rename,
// fsync-directory (the same crash-safety discipline internal/tpm and
// internal/store use for their own persisted files).
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) //nolint:gosec // G304: tmp is always derived from this package's own caller-supplied store-directory path, never untrusted input
	if err != nil {
		return fmt.Errorf("identity: create temp file %s: %w", tmp, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("identity: write temp file %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("identity: fsync temp file %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("identity: close temp file %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("identity: rename %s to %s: %w", tmp, path, err)
	}
	df, err := os.Open(dir) //nolint:gosec // G304: dir is always derived from this package's own caller-supplied store-directory path, never untrusted input
	if err != nil {
		return fmt.Errorf("identity: open dir %s for fsync: %w", dir, err)
	}
	defer func() { _ = df.Close() }()
	if err := df.Sync(); err != nil {
		return fmt.Errorf("identity: fsync dir %s: %w", dir, err)
	}
	return nil
}
