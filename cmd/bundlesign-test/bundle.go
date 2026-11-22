//go:build testtools

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// These mirror internal/verify's unexported wire types field-for-field; see
// testdata/vectors/README.md.
type targetsPayload struct {
	HostUUIDs      []string `json:"host_uuids"`
	SelectorDigest string   `json:"selector_digest"`
}

type policyPayload struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
	YAML    string `json:"yaml"`
}

type provenancePayload struct {
	Author          string   `json:"author"`
	Approvers       []string `json:"approvers"`
	ChangeRef       string   `json:"change_ref"`
	ControllerBuild string   `json:"controller_build"`
}

type bundlePayload struct {
	Schema             string            `json:"schema"`
	BundleID           string            `json:"bundle_id"`
	Epoch              uint64            `json:"epoch"`
	Scope              string            `json:"scope"`
	Targets            targetsPayload    `json:"targets"`
	NotBefore          time.Time         `json:"not_before"`
	Expires            time.Time         `json:"expires"`
	TetragonMinVersion string            `json:"tetragon_min_version"`
	Mode               string            `json:"mode"`
	Policies           []policyPayload   `json:"policies"`
	Provenance         provenancePayload `json:"provenance"`
}

const bundlePayloadType = "application/vnd.relay.policybundle.v1+json"
const bundleSchema = "relay.policybundle.v1"

// policySpec is a convenience for building a policyPayload with a correct
// hash; pass wrongHash to deliberately produce a mismatch.
func newPolicy(name string, version int, yaml string, wrongHash string) policyPayload {
	sum := sha256.Sum256([]byte(yaml))
	hash := hex.EncodeToString(sum[:])
	if wrongHash != "" {
		hash = wrongHash
	}
	return policyPayload{Name: name, Version: version, SHA256: hash, YAML: yaml}
}

// bundleSpec is the input to buildBundlePayload.
type bundleSpec struct {
	bundleID           string
	epoch              uint64
	scope              string
	hostUUIDs          []string
	notBefore          time.Time
	expires            time.Time
	tetragonMinVersion string
	mode               string
	policies           []policyPayload
	schemaOverride     string // empty means use bundleSchema
}

func buildBundlePayload(spec bundleSpec) ([]byte, error) {
	schema := spec.schemaOverride
	if schema == "" {
		schema = bundleSchema
	}
	bp := bundlePayload{
		Schema:             schema,
		BundleID:           spec.bundleID,
		Epoch:              spec.epoch,
		Scope:              spec.scope,
		Targets:            targetsPayload{HostUUIDs: spec.hostUUIDs},
		NotBefore:          spec.notBefore,
		Expires:            spec.expires,
		TetragonMinVersion: spec.tetragonMinVersion,
		Mode:               spec.mode,
		Policies:           spec.policies,
		Provenance: provenancePayload{
			Author:    "jdoe@example.com",
			Approvers: []string{"asmith@example.com", "bkim@example.com"},
			ChangeRef: "CHG-TEST-0001",
		},
	}
	return json.Marshal(bp)
}
