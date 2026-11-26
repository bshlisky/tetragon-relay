package store

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// Store is the agent's persistent state (package doc). It implements
// verify.EpochSource, guard.PolicyHistory and apply.LKGStore directly (no
// adapter type needed: their method sets have no store-specific types in
// their signatures except apply.LKGSet, which this package already
// imports).
//
// All exported methods take Store's own mutex (step-04b.md Part C9: one
// writer, in-process, in addition to the cross-process flock taken at
// Open) and are therefore safe for concurrent use.
type Store struct {
	dir     string
	fs      FS
	sealer  KeySealer
	counter MonotonicCounter

	mu           sync.Mutex
	closed       bool
	lockFile     File
	wasFirstBoot bool
	// tamperErr, once set, is returned by every method forever (Part
	// C6: never silently re-initialize). Wraps ErrTampered.
	tamperErr error
	committed indexPayload
}

// Open opens (or, if the directory is empty, initializes) the store at
// dir. dir must already exist, 0700, owned by the calling process' own
// uid (architecture doc section 8.5; packaging creates it, this package
// only verifies it). Returns ErrAlreadyOpen if another process holds the
// store's lock, or an error wrapping ErrTampered if the on-disk state
// cannot be trusted (Part C6) — callers must not retry Open expecting it
// to self-heal; recovery is an explicit operator action (re-enrollment,
// interface only in this step — see Reenroller).
func Open(dir string, sealer KeySealer, counter MonotonicCounter) (*Store, error) {
	return openWithFS(dir, sealer, counter, OSFS{})
}

func openWithFS(dir string, sealer KeySealer, counter MonotonicCounter, fsys FS) (*Store, error) {
	dfi, err := fsys.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("store: stat %s: %w", dir, err)
	}
	if dfi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s is a symlink, not a directory", ErrTampered, dir)
	}
	if !dfi.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrTampered, dir)
	}
	if err := checkOwnerAndMode(dfi, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrTampered, dir, err)
	}

	blobsDir := filepath.Join(dir, "blobs")
	switch bfi, berr := fsys.Lstat(blobsDir); {
	case berr == nil:
		if bfi.Mode()&os.ModeSymlink != 0 || !bfi.IsDir() {
			return nil, fmt.Errorf("%w: %s is not a plain directory", ErrTampered, blobsDir)
		}
	case errors.Is(berr, os.ErrNotExist):
		if err := fsys.Mkdir(blobsDir, 0o700); err != nil {
			return nil, fmt.Errorf("store: create blobs dir: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: stat %s: %w", ErrTampered, blobsDir, berr)
	}

	lockPath := filepath.Join(dir, "lock")
	lockFile, err := fsys.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: open lock file: %w", err)
	}
	if err := fsys.Flock(lockFile); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("%w: %w", ErrAlreadyOpen, err)
	}

	s := &Store{dir: dir, fs: fsys, sealer: sealer, counter: counter, lockFile: lockFile}

	indexPath := filepath.Join(dir, "index")
	ifi, statErr := fsys.Lstat(indexPath)
	switch {
	case statErr == nil:
		if ifi.Mode()&os.ModeSymlink != 0 {
			_ = lockFile.Close()
			return nil, fmt.Errorf("%w: index is a symlink, not a file", ErrTampered)
		}
		if !ifi.Mode().IsRegular() {
			_ = lockFile.Close()
			return nil, fmt.Errorf("%w: index is not a regular file", ErrTampered)
		}
		if ifi.Mode().Perm() != 0o600 {
			_ = lockFile.Close()
			return nil, fmt.Errorf("%w: index has mode %o, want 0600", ErrTampered, ifi.Mode().Perm())
		}
		raw, rerr := fsys.ReadFile(indexPath)
		if rerr != nil {
			_ = lockFile.Close()
			return nil, fmt.Errorf("%w: read index: %w", ErrTampered, rerr)
		}
		payload, verr := s.loadAndValidateIndex(raw)
		if verr != nil {
			_ = lockFile.Close()
			return nil, verr
		}
		s.committed = payload
	case errors.Is(statErr, os.ErrNotExist):
		// An index that is present but unreadable is never first
		// boot (Part C6); only a genuinely missing file is.
		if _, ferr := s.firstBoot(); ferr != nil {
			_ = lockFile.Close()
			return nil, ferr
		}
	default:
		_ = lockFile.Close()
		return nil, fmt.Errorf("%w: stat index: %w", ErrTampered, statErr)
	}
	return s, nil
}

// checkOwnerAndMode requires fi's permission bits to equal exactly want
// and its owner to be the calling process' own uid — the production model
// (architecture doc section 8.5: the store directory is owned by the
// tetragon-relay user relayd itself runs as). step-04b-review.md R4B-3:
// on a platform where fi.Sys() does not return *syscall.Stat_t (anything
// other than Linux or Darwin), ownership cannot be verified at all, so
// this fails closed (refuses to open) rather than silently downgrading to
// a mode-only check — this project only targets RHEL 9 in production, so
// a build on any other platform's Sys() shape is never expected to reach
// this path for real.
func checkOwnerAndMode(fi os.FileInfo, want os.FileMode) error {
	if fi.Mode().Perm() != want {
		return fmt.Errorf("mode is %o, want %o", fi.Mode().Perm(), want)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify ownership on this platform: fi.Sys() is %T, not *syscall.Stat_t; refusing to open", fi.Sys())
	}
	if uint32(st.Uid) != uint32(os.Getuid()) { //nolint:unconvert // Uid's width differs across platforms
		return fmt.Errorf("owned by uid %d, want %d (the running process' own uid)", st.Uid, os.Getuid())
	}
	return nil
}

// loadAndValidateIndex decodes, HMAC-verifies, bound-checks and
// blob-verifies raw (an existing index file's bytes), returning its
// payload on success or an error wrapping ErrTampered (or
// ErrSealerUnavailable/ErrCounterUnavailable for infrastructure failures
// that are not themselves evidence of tampering).
func (s *Store) loadAndValidateIndex(raw []byte) (indexPayload, error) {
	idx, err := decodeIndexFile(raw)
	if err != nil {
		return indexPayload{}, fmt.Errorf("%w: %w", ErrTampered, err)
	}
	if idx.Payload.Generation == 0 {
		return indexPayload{}, fmt.Errorf("%w: generation is zero", ErrTampered)
	}
	key, err := s.sealer.Unseal()
	if err != nil {
		return indexPayload{}, fmt.Errorf("%w: %w", ErrSealerUnavailable, err)
	}
	wantMAC, err := computeHMAC(key, idx.Payload)
	if err != nil {
		return indexPayload{}, fmt.Errorf("%w: %w", ErrTampered, err)
	}
	if !hmac.Equal([]byte(wantMAC), []byte(idx.HMAC)) {
		return indexPayload{}, fmt.Errorf("%w: HMAC mismatch", ErrTampered)
	}
	if err := verifyIndexLimits(idx.Payload); err != nil {
		return indexPayload{}, err
	}

	counterVal, cerr := s.counter.Read()
	if cerr != nil {
		return indexPayload{}, fmt.Errorf("%w: %w", ErrCounterUnavailable, cerr)
	}
	switch idx.Payload.Generation {
	case counterVal:
		// Ordinary case.
	case counterVal + 1:
		// Part C5: the crash window between the index rename and the
		// counter increment. Accepted exactly once, then the counter
		// is caught up so a second restore of the same disk state
		// (now with a current counter) is not re-accepted as this
		// same window a second time.
		if _, ierr := s.counter.Increment(); ierr != nil {
			return indexPayload{}, fmt.Errorf("%w: %w", ErrCounterUnavailable, ierr)
		}
	default:
		return indexPayload{}, fmt.Errorf("%w: index generation %d does not match counter %d", ErrTampered, idx.Payload.Generation, counterVal)
	}

	referenced := map[string]struct{}{}
	for domain, e := range idx.Payload.LKG {
		if _, berr := s.readBlob(e.BlobDigest); berr != nil {
			return indexPayload{}, fmt.Errorf("store: LKG blob for domain %q: %w", domain, berr)
		}
		referenced[e.BlobDigest] = struct{}{}
	}
	if idx.Payload.TrustRoot != nil {
		if _, berr := s.readBlob(idx.Payload.TrustRoot.BlobDigest); berr != nil {
			return indexPayload{}, fmt.Errorf("store: trust root blob: %w", berr)
		}
		referenced[idx.Payload.TrustRoot.BlobDigest] = struct{}{}
	}
	if total := s.totalReferencedBlobBytes(referenced); total > limits.MaxStoreTotalBlobBytes {
		return indexPayload{}, fmt.Errorf("%w: referenced blobs total %d bytes, max %d", ErrLimitExceeded, total, limits.MaxStoreTotalBlobBytes)
	}

	return idx.Payload, nil
}

// firstBoot initializes a fresh store at generation 1 (Part C6). It
// requires the monotonic counter to still be at its factory value (0): a
// missing index with a nonzero counter means a prior generation's index
// was lost, not a fresh install, and is treated as tamper rather than
// silently starting over.
func (s *Store) firstBoot() (indexPayload, error) {
	counterVal, err := s.counter.Read()
	if err != nil {
		return indexPayload{}, fmt.Errorf("%w: %w", ErrCounterUnavailable, err)
	}
	if counterVal != 0 {
		return indexPayload{}, fmt.Errorf("%w: index is missing but the monotonic counter is already at %d (not a fresh install)", ErrTampered, counterVal)
	}
	payload := indexPayload{
		Epochs:  map[string]uint64{},
		History: map[string][]string{},
		LKG:     map[string]lkgEntry{},
	}
	if err := s.commitLocked(payload); err != nil {
		return indexPayload{}, err
	}
	s.wasFirstBoot = true
	return s.committed, nil
}

// commitLocked writes next as the new generation (s.committed.Generation +
// 1), following Part C3's write sequence: blobs referenced by next must
// already have been written (by the caller, via writeBlobIfMissing) before
// commitLocked is called. Must be called with s.mu held.
func (s *Store) commitLocked(next indexPayload) error {
	next.Schema = indexSchema
	next.Generation = s.committed.Generation + 1
	next.TrustRootHistory = prunedRootHistory(next)
	if err := verifyIndexLimits(next); err != nil {
		return err
	}
	if err := s.writeIndexFile(next); err != nil {
		return err
	}
	s.committed = next
	if _, err := s.counter.Increment(); err != nil {
		// step-04b-review.md R4B-5: the index on disk already reflects
		// next.Generation (s.committed above is already updated too)
		// — this is exactly Part C5's accepted-once recovery window,
		// completed by the next Open. Report this distinctly from
		// ErrCounterUnavailable (which means the write itself could
		// not proceed) so a caller can tell "committed, counter will
		// catch up" apart from "nothing happened."
		return fmt.Errorf("%w: %w", ErrCommittedCounterLag, err)
	}
	referenced := map[string]struct{}{}
	for _, e := range next.LKG {
		referenced[e.BlobDigest] = struct{}{}
	}
	if next.TrustRoot != nil {
		referenced[next.TrustRoot.BlobDigest] = struct{}{}
	}
	for _, e := range next.TrustRootHistory {
		referenced[e.BlobDigest] = struct{}{}
	}
	s.gcBlobs(referenced)
	return nil
}

// prunedRootHistory implements ADR 0025's retention rule: a root
// version's blob (and its entry in next.TrustRootHistory) stays live only
// while it is either the current TrustRoot or still referenced by some
// domain's LKG.RootVersion. Any version not referenced by either is
// dropped from the returned map, so TrustRootHistory never accumulates
// stale versions and gcBlobs (reading it back from next, after this
// function has already run) correctly removes their now-unreferenced
// blobs too.
func prunedRootHistory(next indexPayload) map[uint64]trustRootEntry {
	keep := map[uint64]struct{}{}
	if next.TrustRoot != nil {
		keep[next.TrustRoot.Version] = struct{}{}
	}
	for _, e := range next.LKG {
		if e.RootVersion != 0 {
			keep[e.RootVersion] = struct{}{}
		}
	}
	if len(keep) == 0 {
		return nil
	}
	out := make(map[uint64]trustRootEntry, len(keep))
	for v := range keep {
		if e, ok := next.TrustRootHistory[v]; ok {
			out[v] = e
			continue
		}
		if next.TrustRoot != nil && v == next.TrustRoot.Version {
			// The current root's own history entry may not exist yet
			// on the very commit that first persists it (PersistTrustRoot
			// sets next.TrustRoot directly); use it as the source.
			out[v] = *next.TrustRoot
		}
		// Otherwise: a version is referenced (by an LKG entry) but this
		// package has no blob for it at all. This should not happen for
		// an index this package itself ever produced; omitting it here
		// is the fail-closed choice -- internal/agent's re-verification
		// (ADR 0025) will then correctly find no root for that version
		// and treat the LKG as unverifiable, rather than this package
		// inventing or silently keeping a phantom reference.
	}
	return out
}

// writeIndexFile is Part C3's index-only write sequence: write index.tmp,
// fsync it, rename to index, fsync the directory.
func (s *Store) writeIndexFile(payload indexPayload) error {
	key, err := s.sealer.Unseal()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSealerUnavailable, err)
	}
	mac, err := computeHMAC(key, payload)
	if err != nil {
		return fmt.Errorf("store: compute HMAC: %w", err)
	}
	raw, err := json.Marshal(indexFile{Payload: payload, HMAC: mac})
	if err != nil {
		return fmt.Errorf("store: marshal index: %w", err)
	}
	if len(raw) > limits.MaxStoreIndexBytes {
		return fmt.Errorf("%w: index would be %d bytes, max %d", ErrLimitExceeded, len(raw), limits.MaxStoreIndexBytes)
	}

	tmpPath := filepath.Join(s.dir, "index.tmp")
	f, err := s.fs.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("store: create index.tmp: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: write index.tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("store: fsync index.tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: close index.tmp: %w", err)
	}
	if err := s.fs.Rename(tmpPath, filepath.Join(s.dir, "index")); err != nil {
		return fmt.Errorf("store: rename index.tmp: %w", err)
	}
	if err := s.fs.FsyncDir(s.dir); err != nil {
		return fmt.Errorf("store: fsync store dir: %w", err)
	}
	return nil
}

func (s *Store) cloneCommitted() indexPayload {
	next := indexPayload{
		Schema:           s.committed.Schema,
		Generation:       s.committed.Generation,
		Epochs:           make(map[string]uint64, len(s.committed.Epochs)),
		History:          make(map[string][]string, len(s.committed.History)),
		LKG:              make(map[string]lkgEntry, len(s.committed.LKG)),
		TrustRoot:        s.committed.TrustRoot,
		TrustRootHistory: make(map[uint64]trustRootEntry, len(s.committed.TrustRootHistory)),
		Revoked:          s.committed.Revoked,
	}
	for k, v := range s.committed.Epochs {
		next.Epochs[k] = v
	}
	for k, v := range s.committed.History {
		next.History[k] = append([]string(nil), v...)
	}
	for k, v := range s.committed.LKG {
		next.LKG[k] = v
	}
	for k, v := range s.committed.TrustRootHistory {
		next.TrustRootHistory[k] = v
	}
	return next
}

func (s *Store) markTamperedLocked(err error) {
	if s.tamperErr == nil {
		s.tamperErr = fmt.Errorf("%w: %w", ErrTampered, err)
	}
}

// FirstBoot reports whether this Open call initialized a fresh store
// (generation 1, no trust root persisted) rather than loading an existing
// one. internal/agent uses this to decide whether the RPM-shipped initial
// root must be adopted unconditionally (Part D2, Part C7).
func (s *Store) FirstBoot() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wasFirstBoot
}

// Tampered returns the store's permanent tamper error, or nil if the store
// has not detected tampering (which does not guarantee it is not
// tampered: tampering is only ever detected when something that touches
// it is read).
func (s *Store) Tampered() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tamperErr
}

// Generation returns the store's current committed generation number.
func (s *Store) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.committed.Generation
}

// Close releases the store's exclusive lock. After Close, every method
// returns ErrClosed.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.lockFile.Close()
}

func (s *Store) preflightLocked() error {
	if s.tamperErr != nil {
		return s.tamperErr
	}
	if s.closed {
		return ErrClosed
	}
	return nil
}

// --- verify.EpochSource ---

// Current implements verify.EpochSource. A scope with no recorded epoch
// reports 0, so any positive bundle epoch is accepted the first time
// (matching every existing in-memory fake's convention).
func (s *Store) Current(scope string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return 0, err
	}
	return s.committed.Epochs[scope], nil
}

// RecordEpoch persists scope's epoch after a successful apply (Part D1:
// "Persist a scope's epoch only after a successful apply (APPLIED)"). It
// must be called with a strictly greater epoch than any previously
// recorded for scope (internal/verify already enforces this at accept
// time; this is defense in depth, not the primary check).
func (s *Store) RecordEpoch(scope string, epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	if cur, ok := s.committed.Epochs[scope]; ok && epoch <= cur {
		return fmt.Errorf("store: epoch %d for scope %q is not greater than persisted %d", epoch, scope, cur)
	}
	next := s.cloneCommitted()
	next.Epochs[scope] = epoch
	return s.commitLocked(next)
}

// --- guard.PolicyHistory ---

// SeenInMonitor implements guard.PolicyHistory.
func (s *Store) SeenInMonitor(scope, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return false, err
	}
	for _, n := range s.committed.History[scope] {
		if n == name {
			return true, nil
		}
	}
	return false, nil
}

// RecordMonitorNames records every name in names as seen in a monitor-mode
// bundle for scope (Part D1: "record monitor history only after a
// successful monitor-mode apply"), deduplicating against names already
// recorded.
func (s *Store) RecordMonitorNames(scope string, names []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	next := s.cloneCommitted()
	seen := make(map[string]struct{}, len(next.History[scope]))
	for _, n := range next.History[scope] {
		seen[n] = struct{}{}
	}
	changed := false
	for _, n := range names {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		next.History[scope] = append(next.History[scope], n)
		changed = true
	}
	if !changed {
		return nil
	}
	return s.commitLocked(next)
}

// --- apply.LKGStore ---

// lkgBlobPolicy and lkgBlob mirror apply.LKGPolicy/apply.LKGSet field for
// field, as the JSON shape of an LKG blob's content. Duplicated rather
// than reusing apply's own JSON tags (apply.LKGPolicy carries none) so
// this package's on-disk wire format is independent of apply's Go struct
// layout.
type lkgBlobPolicy struct {
	Name          string `json:"name"`
	Version       int    `json:"version"`
	CanonicalJSON []byte `json:"canonical_json"`
}

// lkgBlob gained RawEnvelope/RootVersion in ADR 0025
// (step-04b-review.md R4B-2): architecture doc 8.2/7.7 specify the LKG
// store keeps the raw signed DSSE envelope, never re-encoded, alongside
// the already-parsed/rewritten Policies/Mode the apply engine
// operationally needs (add-before-remove diffing, Reconcile). Both are
// content-addressed together as one blob (see Put's doc comment for why
// this is not split into two separate blobs).
type lkgBlob struct {
	Schema      string          `json:"schema"`
	Mode        string          `json:"mode"`
	Policies    []lkgBlobPolicy `json:"policies"`
	RawEnvelope []byte          `json:"raw_envelope,omitempty"`
	RootVersion uint64          `json:"root_version,omitempty"`
}

const lkgBlobSchema = "relay.store.lkg.v1"

func toLKGBlob(set apply.LKGSet) lkgBlob {
	b := lkgBlob{Schema: lkgBlobSchema, Mode: set.Mode, Policies: make([]lkgBlobPolicy, 0, len(set.Policies)), RawEnvelope: set.RawEnvelope, RootVersion: set.RootVersion}
	for _, p := range set.Policies {
		b.Policies = append(b.Policies, lkgBlobPolicy{Name: p.Name, Version: p.Version, CanonicalJSON: p.CanonicalJSON})
	}
	return b
}

func (b lkgBlob) toLKGSet() apply.LKGSet {
	set := apply.LKGSet{Mode: b.Mode, Policies: make([]apply.LKGPolicy, 0, len(b.Policies)), RawEnvelope: b.RawEnvelope, RootVersion: b.RootVersion}
	for _, p := range b.Policies {
		set.Policies = append(set.Policies, apply.LKGPolicy{Name: p.Name, Version: p.Version, CanonicalJSON: p.CanonicalJSON})
	}
	return set
}

// Get implements apply.LKGStore. Its signature (fixed by step 3) has no
// error return: a blob content-hash failure or decode failure marks the
// whole Store permanently tampered (so every other, error-returning
// method starts reporting ErrTampered) and this call reports ok=false, the
// same as "no LKG set has ever been recorded" — both mean "there is
// nothing this call can hand back to roll forward with." The distinct,
// typed ErrTampered is still observable via Tampered().
func (s *Store) Get(domain string) (apply.LKGSet, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return apply.LKGSet{}, false
	}
	e, ok := s.committed.LKG[domain]
	if !ok {
		return apply.LKGSet{}, false
	}
	raw, err := s.readBlob(e.BlobDigest)
	if err != nil {
		s.markTamperedLocked(err)
		return apply.LKGSet{}, false
	}
	var blob lkgBlob
	if err := strictjson.DecodeStrict(raw, limits.MaxJSONDepth, &blob); err != nil {
		s.markTamperedLocked(fmt.Errorf("decode LKG blob for domain %q: %w", domain, err))
		return apply.LKGSet{}, false
	}
	return blob.toLKGSet(), true
}

// Put implements apply.LKGStore.
func (s *Store) Put(domain string, set apply.LKGSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	raw, err := json.Marshal(toLKGBlob(set))
	if err != nil {
		return fmt.Errorf("store: marshal LKG set: %w", err)
	}
	digest, err := s.writeBlobIfMissing(raw)
	if err != nil {
		return err
	}
	next := s.cloneCommitted()
	next.LKG[domain] = lkgEntry{BlobDigest: digest, Mode: set.Mode, RootVersion: set.RootVersion}
	return s.commitLocked(next)
}

// --- trust root (Part C7) ---

// TrustRoot returns the persisted trust root's raw signed bytes and
// version, or ok=false if none has been persisted yet (should not occur
// after a successful Open, which always establishes one at first boot via
// internal/agent's startup sequence calling PersistTrustRoot).
func (s *Store) TrustRoot() (raw []byte, version uint64, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return nil, 0, false, err
	}
	if s.committed.TrustRoot == nil {
		return nil, 0, false, nil
	}
	raw, rerr := s.readBlob(s.committed.TrustRoot.BlobDigest)
	if rerr != nil {
		s.markTamperedLocked(rerr)
		return nil, 0, false, s.tamperErr
	}
	return raw, s.committed.TrustRoot.Version, true, nil
}

// PersistTrustRoot persists raw (a trust-root DSSE envelope's raw signed
// bytes, never re-encoded) as the new trust root at version, enforcing
// Part C7's downgrade protection as a structural invariant independent of
// internal/agent's own cryptographic chain verification (trust.Update):
// version must be strictly greater than the currently persisted version,
// else ErrRootDowngrade (never ErrTampered — an old or equal RPM-shipped
// root reaching this call is an expected, logged, non-error outcome at
// the agent layer, not evidence of tampering).
//
// internal/agent is responsible for verifying raw actually chains from the
// persisted root (trust.Root.Update) before calling this; PersistTrustRoot
// itself does not parse raw at all (store has no internal/trust
// dependency), so it cannot independently confirm that.
func (s *Store) PersistTrustRoot(raw []byte, version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	if s.committed.TrustRoot != nil && version <= s.committed.TrustRoot.Version {
		return fmt.Errorf("%w: candidate version %d <= persisted version %d", ErrRootDowngrade, version, s.committed.TrustRoot.Version)
	}
	digest, err := s.writeBlobIfMissing(raw)
	if err != nil {
		return err
	}
	next := s.cloneCommitted()
	entry := trustRootEntry{Version: version, BlobDigest: digest}
	next.TrustRoot = &entry
	// ADR 0025: also record this version in TrustRootHistory directly
	// (commitLocked's prunedRootHistory would otherwise only discover it
	// via next.TrustRoot, which it does already handle, but setting it
	// explicitly here means RootAtVersion can find a just-persisted
	// current version without relying on that fallback).
	if next.TrustRootHistory == nil {
		next.TrustRootHistory = map[uint64]trustRootEntry{}
	}
	next.TrustRootHistory[version] = entry
	return s.commitLocked(next)
}

// RootAtVersion returns a historical trust root version's raw signed
// bytes, or ok=false if that version is not (or is no longer) retained
// (ADR 0025, step-04b-review.md R4B-2): internal/agent uses this at
// startup to re-verify each domain's LKG against the EXACT root version
// that verified it, which may not be the current one.
func (s *Store) RootAtVersion(version uint64) (raw []byte, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return nil, false, err
	}
	e, ok := s.committed.TrustRootHistory[version]
	if !ok {
		return nil, false, nil
	}
	raw, rerr := s.readBlob(e.BlobDigest)
	if rerr != nil {
		s.markTamperedLocked(rerr)
		return nil, false, s.tamperErr
	}
	return raw, true, nil
}

// Domains returns every domain currently holding a persisted LKG set, in
// no particular order. internal/agent uses this at startup to iterate
// every domain for re-verification (ADR 0025); it is deliberately not
// part of apply.LKGStore, which never needs to enumerate domains (the
// apply engine always operates on one domain/scope at a time).
func (s *Store) Domains() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(s.committed.LKG))
	for domain := range s.committed.LKG {
		out = append(out, domain)
	}
	return out, nil
}

// --- persisted REVOKED (ADR 0035, step-06a-e3-decisions.md D2) ---

// Revocation is the persisted REVOKED marker.
type Revocation struct {
	At     time.Time
	Reason string
}

// Revocation returns the persisted REVOKED marker, if any.
func (s *Store) Revocation() (Revocation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return Revocation{}, false, err
	}
	if s.committed.Revoked == nil {
		return Revocation{}, false, nil
	}
	return Revocation{At: s.committed.Revoked.At, Reason: s.committed.Revoked.Reason}, true, nil
}

// MarkRevoked persists the REVOKED marker. at must be non-zero and reason
// at most limits.MaxRevokedReasonBytes. If a marker is already persisted
// it is kept unchanged (the first revocation's time and reason win) and
// MarkRevoked returns nil.
func (s *Store) MarkRevoked(at time.Time, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	if at.IsZero() {
		return fmt.Errorf("store: MarkRevoked: zero time")
	}
	if len(reason) > limits.MaxRevokedReasonBytes {
		return fmt.Errorf("%w: revoked reason is %d bytes, max %d", ErrLimitExceeded, len(reason), limits.MaxRevokedReasonBytes)
	}
	if s.committed.Revoked != nil {
		return nil
	}
	next := s.cloneCommitted()
	next.Revoked = &revokedMarker{At: at.UTC(), Reason: reason}
	return s.commitLocked(next)
}

// ClearRevocation removes the REVOKED marker. Only the operator
// re-enrollment path (agent.Reenroller, ADR 0023) may call it; startup
// and the session runner never do.
func (s *Store) ClearRevocation() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflightLocked(); err != nil {
		return err
	}
	if s.committed.Revoked == nil {
		return nil
	}
	next := s.cloneCommitted()
	next.Revoked = nil
	return s.commitLocked(next)
}
