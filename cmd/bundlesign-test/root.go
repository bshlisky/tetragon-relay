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
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
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

func roleOf(keys []*testKey, threshold int) rolePayload {
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.id)
	}
	return rolePayload{KeyIDs: ids, Threshold: threshold}
}
