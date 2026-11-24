package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// blobDigest returns the hex-encoded SHA-256 of b: both the content-address
// (the blob's filename under blobs/) and the value stored in the index
// entry that references it.
func blobDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *Store) blobPath(digest string) string {
	return filepath.Join(s.dir, "blobs", digest)
}

// writeBlobIfMissing writes b to blobs/<digest> and fsyncs it, unless a
// file already exists at that path (the common case when the same LKG set
// or trust root is written again unchanged). It never trusts an existing
// file's content without checking: if one already exists, its digest is
// verified before being treated as already-durable, so a half-written
// leftover from an earlier crash (Part C3) is transparently overwritten
// rather than mistaken for a valid, already-committed blob.
//
// step-04b-review.md R4B-4: the "already present" branch still fsyncs the
// existing blob file and the blobs directory before returning, rather
// than assuming whoever wrote it earlier already durably fsynced it.
// This is cheap (the content is already on disk; this just re-confirms
// durability) and removes an unenforced precondition the earlier version
// relied on silently.
func (s *Store) writeBlobIfMissing(b []byte) (digest string, err error) {
	if len(b) > limits.MaxStoreBlobBytes {
		return "", fmt.Errorf("%w: blob is %d bytes, max %d", ErrLimitExceeded, len(b), limits.MaxStoreBlobBytes)
	}
	digest = blobDigest(b)
	path := s.blobPath(digest)
	if existing, rerr := s.fs.ReadFile(path); rerr == nil && blobDigest(existing) == digest {
		if err := s.fsyncExistingBlob(path); err != nil {
			return "", err
		}
		return digest, nil
	}
	f, err := s.fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("store: create blob %s: %w", digest, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("store: write blob %s: %w", digest, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("store: fsync blob %s: %w", digest, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("store: close blob %s: %w", digest, err)
	}
	return digest, nil
}

// fsyncExistingBlob fsyncs an already-written blob file at path and the
// blobs directory it lives in, without modifying the file's content
// (opened O_WRONLY with neither O_CREATE nor O_TRUNC). step-04b-review.md
// R4B-4.
func (s *Store) fsyncExistingBlob(path string) error {
	f, err := s.fs.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("store: open existing blob %s for fsync: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: fsync existing blob %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: close existing blob %s: %w", path, err)
	}
	if err := s.fs.FsyncDir(filepath.Join(s.dir, "blobs")); err != nil {
		return fmt.Errorf("store: fsync blobs dir: %w", err)
	}
	return nil
}

// readBlob reads blobs/<digest> and verifies its content hash equals
// digest (Part C4: "Blobs are verified against their content hash on
// every read"), else ErrTampered: a blob file edited offline while keeping
// its filename, or truncated by a crash whose index.tmp rename somehow
// still went on to reference it, must never be read as if it were valid.
func (s *Store) readBlob(digest string) ([]byte, error) {
	b, err := s.fs.ReadFile(s.blobPath(digest))
	if err != nil {
		return nil, fmt.Errorf("%w: read blob %s: %w", ErrTampered, digest, err)
	}
	if len(b) > limits.MaxStoreBlobBytes {
		return nil, fmt.Errorf("%w: blob %s is %d bytes, max %d", ErrTampered, digest, len(b), limits.MaxStoreBlobBytes)
	}
	if got := blobDigest(b); got != digest {
		return nil, fmt.Errorf("%w: blob %s content hash is actually %s", ErrTampered, digest, got)
	}
	return b, nil
}

// gcBlobs removes every file under blobs/ whose name is not in referenced,
// best-effort: a leftover orphan (e.g. from a crash before the index that
// would have referenced it was ever committed) is harmless and would be
// swept up by a later call, so a failure removing one orphan does not
// abort the whole pass.
func (s *Store) gcBlobs(referenced map[string]struct{}) {
	entries, err := s.fs.ReadDir(filepath.Join(s.dir, "blobs"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, keep := referenced[e.Name()]; keep {
			continue
		}
		_ = s.fs.Remove(filepath.Join(s.dir, "blobs", e.Name()))
	}
}

// totalReferencedBlobBytes sums the on-disk size of every blob in
// referenced, for the Part C8 total-bytes cap. Missing or oversized
// individual blobs are reported as 0 here; readBlob (called separately for
// any blob actually used) is what turns a missing/corrupt blob into
// ErrTampered.
func (s *Store) totalReferencedBlobBytes(referenced map[string]struct{}) int64 {
	var total int64
	for digest := range referenced {
		if fi, err := s.fs.Stat(s.blobPath(digest)); err == nil {
			total += fi.Size()
		}
	}
	return total
}
