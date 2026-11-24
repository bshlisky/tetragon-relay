//go:build testtools

package main

import (
	"encoding/json"
	"time"
)

// These mirror internal/trust's unexported wire types field-for-field; see
// testdata/vectors/README.md for why they are duplicated here rather than
// imported (internal/trust deliberately does not export its wire structs).
type keyEntry struct {
	KeyType      string `json:"keytype"`
	PublicKeyDER string `json:"public_key_der_b64"`
}

type rolePayload struct {
	KeyIDs          []string `json:"keyids"`
	Threshold       int      `json:"threshold"`
	RequireKeyTypes []string `json:"require_keytypes,omitempty"`
}

type rolesPayload struct {
	Root    rolePayload `json:"root"`
	Targets rolePayload `json:"targets"`
	Log     rolePayload `json:"log"`
}

type rootPayload struct {
	Schema          string              `json:"schema"`
	Version         uint64              `json:"version"`
	Expires         time.Time           `json:"expires"`
	Keys            map[string]keyEntry `json:"keys"`
	Roles           rolesPayload        `json:"roles"`
	RequireLogProof bool                `json:"require_log_proof"`
}

const rootPayloadType = "application/vnd.relay.root.v1+json"
const rootSchema = "relay.root.v1"

// rootSpec is the input to buildRoot: which keys exist, their declared
// keytype, and the three role definitions.
type rootSpec struct {
	version int
	expires time.Time
	keys    []*testKey
	root    rolePayload
	targets rolePayload
	log     rolePayload
}

func buildRootPayload(spec rootSpec) ([]byte, error) {
	keys := make(map[string]keyEntry, len(spec.keys))
	for _, k := range spec.keys {
		keys[k.id] = keyEntry{KeyType: k.keyType, PublicKeyDER: k.publicB64}
	}
	rp := rootPayload{
		Schema:  rootSchema,
		Version: uint64(spec.version),
		Expires: spec.expires,
		Keys:    keys,
		Roles: rolesPayload{
			Root:    spec.root,
			Targets: spec.targets,
			Log:     spec.log,
		},
	}
	return json.Marshal(rp)
}

// roleOf builds a role whose keys are all ecdsa-p384 (every production role
// and every role helper in this generator except hybrid targets roles), so
// it always sets require_keytypes = ["ecdsa-p384"] (step-04a-review.md
// R4A-1: require_keytypes is mandatory on every role; there is no longer an
// "omitted means no requirement" case). Use roleOfOmittingKeyTypes to build
// the deliberately-malformed "field omitted" vectors.
func roleOf(keys []*testKey, threshold int) rolePayload {
	return roleWithKeyTypes(keys, threshold, "ecdsa-p384")
}

// roleOfOmittingKeyTypes is roleOf but leaves require_keytypes unset
// (nil/omitted), for vectors that must assert this is rejected
// (step-04a-review.md R4A-1).
func roleOfOmittingKeyTypes(keys []*testKey, threshold int) rolePayload {
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.id)
	}
	return rolePayload{KeyIDs: ids, Threshold: threshold}
}

// roleWithKeyTypes is roleOf plus an explicit require_keytypes list (step
// 4 prompt Part B3), e.g. ["ecdsa-p384", "mldsa-87"] for a hybrid role.
func roleWithKeyTypes(keys []*testKey, threshold int, requireKeyTypes ...string) rolePayload {
	r := roleOfOmittingKeyTypes(keys, threshold)
	r.RequireKeyTypes = requireKeyTypes
	return r
}
