package store

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// indexSchema is the required value of indexFile.Payload.Schema.
const indexSchema = "relay.store.index.v1"

// lkgEntry references one domain's persisted LKG blob.
type lkgEntry struct {
	BlobDigest string `json:"blob_digest"`
	Mode       string `json:"mode"`
}

// trustRootEntry references the persisted trust root's raw-bytes blob.
type trustRootEntry struct {
	Version    uint64 `json:"version"`
	BlobDigest string `json:"blob_digest"`
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
		Schema:     p.Schema,
		Generation: p.Generation,
		Epochs:     p.Epochs,
		LKG:        p.LKG,
		TrustRoot:  p.TrustRoot,
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
	if len(p.LKG) > limits.MaxStoreDomains {
		return fmt.Errorf("%w: %d LKG domains, max %d", ErrLimitExceeded, len(p.LKG), limits.MaxStoreDomains)
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
