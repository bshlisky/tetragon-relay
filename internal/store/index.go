package store

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// indexSchema is the required value of indexFile.Payload.Schema. v2 adds
// the Revoked marker (ADR 0035). It was bumped in place with no
// migration: no v1 store was ever deployed.
const indexSchema = "relay.store.index.v2"

// lkgEntry references one domain's persisted LKG blob. RootVersion
// (ADR 0025, step-04b-review.md R4B-2) mirrors the blob's own
// lkgBlob.RootVersion field at the index level (the same redundancy
// Mode already has here alongside lkgBlob.Mode), so commitLocked's
// root-history retention computation (which root versions are still
// "live") never needs to open and decode every domain's blob.
type lkgEntry struct {
	BlobDigest  string `json:"blob_digest"`
	Mode        string `json:"mode"`
	RootVersion uint64 `json:"root_version,omitempty"`
}

// trustRootEntry references a persisted trust root version's raw-bytes
// blob.
type trustRootEntry struct {
	Version    uint64 `json:"version"`
	BlobDigest string `json:"blob_digest"`
}

// revokedMarker is the persisted REVOKED state (ADR 0035): set once on
// Terminate{REVOKED}, cleared only by operator re-enrollment.
type revokedMarker struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

// indexPayload is every field the HMAC in indexFile covers (step-04b.md
// Part C4: "an HMAC-SHA-384 over its canonical bytes, including the
// generation and the blob digests"). History name lists are kept sorted so
// that json.Marshal's own deterministic (alphabetically-sorted-keys, and
// here also sorted-slice) output is a stable "canonical" encoding without
// a bespoke canonicalizer.
type indexPayload struct {
	Schema     string              `json:"schema"`
	Generation uint64              `json:"generation"`
	Epochs     map[string]uint64   `json:"epochs"`
	History    map[string][]string `json:"history"`
	LKG        map[string]lkgEntry `json:"lkg"`
	TrustRoot  *trustRootEntry     `json:"trust_root,omitempty"`
	// TrustRootHistory records every root version whose blob must stay
	// live because it is either the current TrustRoot or still
	// referenced by some domain's LKG.RootVersion (ADR 0025): a root
	// rotation does not retroactively re-verify every domain's existing
	// LKG, so an LKG's own recorded root version may be older than the
	// current one. commitLocked prunes this to exactly the
	// currently-referenced set on every write (store.go's
	// prunedRootHistory), so it never grows unbounded.
	TrustRootHistory map[uint64]trustRootEntry `json:"trust_root_history,omitempty"`
	// Revoked, if set, means the controller revoked this host (ADR 0035).
	// It is part of the HMAC-covered payload like every other field.
	Revoked *revokedMarker `json:"revoked,omitempty"`
}

// indexFile is the on-disk shape of the index file: the payload plus its
// HMAC-SHA-384 (hex-encoded).
type indexFile struct {
	Payload indexPayload `json:"payload"`
	HMAC    string       `json:"hmac"`
}

// canonicalPayloadBytes returns p's deterministic JSON encoding: map keys
// sorted alphabetically (encoding/json's own, unconditional behavior) and
// every History slice sorted, so the same logical content always produces
// the same bytes regardless of insertion order.
func canonicalPayloadBytes(p indexPayload) ([]byte, error) {
	sorted := indexPayload{
		Schema:           p.Schema,
		Generation:       p.Generation,
		Epochs:           p.Epochs,
		LKG:              p.LKG,
		TrustRoot:        p.TrustRoot,
		TrustRootHistory: p.TrustRootHistory,
		Revoked:          p.Revoked,
	}
	if p.History != nil {
		sorted.History = make(map[string][]string, len(p.History))
		for scope, names := range p.History {
			cp := append([]string(nil), names...)
			sort.Strings(cp)
			sorted.History[scope] = cp
		}
	}
	return json.Marshal(sorted)
}

// computeHMAC returns the hex-encoded HMAC-SHA-384 of p's canonical bytes
// under key.
func computeHMAC(key []byte, p indexPayload) (string, error) {
	b, err := canonicalPayloadBytes(p)
	if err != nil {
		return "", fmt.Errorf("store: canonicalize index payload: %w", err)
	}
	mac := hmac.New(sha512.New384, key)
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// verifyIndexLimits enforces Part C8's bounds on an index payload's
// cardinality (not blob sizes, checked separately in blob.go).
func verifyIndexLimits(p indexPayload) error {
	if len(p.Epochs) > limits.MaxStoreScopes {
		return fmt.Errorf("%w: %d scopes with an epoch, max %d", ErrLimitExceeded, len(p.Epochs), limits.MaxStoreScopes)
	}
	if len(p.History) > limits.MaxStoreScopes {
		return fmt.Errorf("%w: %d scopes with history, max %d", ErrLimitExceeded, len(p.History), limits.MaxStoreScopes)
	}
	for scope, names := range p.History {
		if len(names) > limits.MaxStoreHistoryNamesPerScope {
			return fmt.Errorf("%w: scope %q has %d history names, max %d", ErrLimitExceeded, scope, len(names), limits.MaxStoreHistoryNamesPerScope)
		}
	}
	if p.Revoked != nil {
		if p.Revoked.At.IsZero() {
			return fmt.Errorf("%w: revoked marker has no time", ErrTampered)
		}
		if len(p.Revoked.Reason) > limits.MaxRevokedReasonBytes {
			return fmt.Errorf("%w: revoked reason is %d bytes, max %d", ErrLimitExceeded, len(p.Revoked.Reason), limits.MaxRevokedReasonBytes)
		}
	}
	if len(p.LKG) > limits.MaxStoreDomains {
		return fmt.Errorf("%w: %d LKG domains, max %d", ErrLimitExceeded, len(p.LKG), limits.MaxStoreDomains)
	}
	if len(p.TrustRootHistory) > limits.MaxStoreRootHistoryVersions {
		return fmt.Errorf("%w: %d trust root history versions, max %d", ErrLimitExceeded, len(p.TrustRootHistory), limits.MaxStoreRootHistoryVersions)
	}
	return nil
}

// decodeIndexFile strictly decodes raw as an indexFile, bounding its size
// and JSON nesting depth before touching its content (the same discipline
// internal/trust and internal/verify apply to untrusted-until-verified
// input): an index file is untrusted until its HMAC has been checked, so
// it must never be handed to a decoder with no bounds at all.
func decodeIndexFile(raw []byte) (indexFile, error) {
	if len(raw) > limits.MaxStoreIndexBytes {
		return indexFile{}, fmt.Errorf("%w: index is %d bytes, max %d", ErrLimitExceeded, len(raw), limits.MaxStoreIndexBytes)
	}
	var idx indexFile
	if err := strictjson.DecodeStrict(raw, limits.MaxJSONDepth, &idx); err != nil {
		return indexFile{}, fmt.Errorf("store: decode index: %w", err)
	}
	if idx.Payload.Schema != indexSchema {
		return indexFile{}, fmt.Errorf("store: unexpected index schema %q", idx.Payload.Schema)
	}
	return idx, nil
}
