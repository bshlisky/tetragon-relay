package verify

import "time"

// BundlePayloadType is the DSSE payloadType required for policy bundle
// envelopes (architecture doc section 7.3).
const BundlePayloadType = "application/vnd.relay.policybundle.v1+json"

// Bundle is the validated content of an accepted policy bundle. It is only
// populated on CodeAccept; every field has already passed every check in
// this package.
type Bundle struct {
	BundleID           string
	Epoch              uint64
	Scope              string
	HostUUIDs          []string
	NotBefore          time.Time
	Expires            time.Time
	TetragonMinVersion string
	Mode               string
	Policies           []Policy
	Provenance         Provenance
}

// Policy is one validated TracingPolicy document from a bundle.
type Policy struct {
	Name    string
	Version int
	SHA256  string
	YAML    string
}

// Provenance records who authored and approved a bundle, carried through
// verification unchanged for audit purposes.
type Provenance struct {
	Author          string
	Approvers       []string
	ChangeRef       string
	ControllerBuild string
}

// --- wire (JSON) representation of a bundle payload, architecture doc
// section 7.3 ---

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

// BundleSchema is the required value of bundlePayload.Schema.
const BundleSchema = "relay.policybundle.v1"
