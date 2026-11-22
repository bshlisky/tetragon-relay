package trust

import (
	"crypto/ecdsa"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
)

// RootPayloadType is the DSSE payloadType required for trust-root metadata
// envelopes (architecture doc section 7.6).
const RootPayloadType = "application/vnd.relay.root.v1+json"

// Role is one named role (root, targets, or log) from trust-root metadata:
// the set of keys permitted to act in that role, and how many distinct keys
// from that set must sign for the role's authority to be exercised.
type Role struct {
	KeyIDs    []KeyID
	Threshold int
}

// Roles is the full set of roles carried by one version of root metadata.
type Roles struct {
	Root    Role
	Targets Role
	Log     Role
}

// Root is one validated, self-consistent version of trust-root metadata:
// every key referenced by a role is present in keys, every key's declared ID
// matches its derived ID, and (for a version produced by LoadInitialRoot or
// Update) the metadata's own signature requirements were satisfied at the
// time it was accepted.
//
// A *Root is immutable; Update returns a new *Root rather than mutating the
// receiver, so callers holding a reference to an old version are never
// surprised by it changing underneath them. keys and roles are unexported
// (step 1 review A6): both contain reference types (a map, and slices
// inside Role), so exporting them would let any caller holding a *Root
// mutate the trust store directly — e.g. inject an attacker-chosen key into
// the map — without going through any of this package's validation. Use
// KeyCount, RootRole, TargetsRole, and LogRole, which return copies.
type Root struct {
	Version uint64
	Expires time.Time
	keys    map[KeyID]*ecdsa.PublicKey
	roles   Roles

	// RequireLogProof mirrors architecture doc section 7.4 step 4
	// ("trust.require_log_proof"). Transparency-log inclusion proofs are
	// not implemented in this step (see docs/reports/step-01.md, Open
	// questions); if this is true, internal/verify must reject bundles
	// with REJECTED_SIGNATURE rather than silently skip the check.
	RequireLogProof bool
}

// KeyCount returns the number of keys known to this root metadata version.
func (r *Root) KeyCount() int { return len(r.keys) }

// RootRole returns a defensive copy of the root role: a fresh Role value
// with its own KeyIDs slice, so mutating the result can never affect this
// Root.
func (r *Root) RootRole() Role { return copyRole(r.roles.Root) }

// TargetsRole returns a defensive copy of the targets role; see RootRole.
func (r *Root) TargetsRole() Role { return copyRole(r.roles.Targets) }

// LogRole returns a defensive copy of the log role; see RootRole.
func (r *Root) LogRole() Role { return copyRole(r.roles.Log) }

func copyRole(role Role) Role {
	ids := make([]KeyID, len(role.KeyIDs))
	copy(ids, role.KeyIDs)
	return Role{KeyIDs: ids, Threshold: role.Threshold}
}

// Verifier checks whether an envelope's signatures meet a specific role's
// threshold using a specific (now-current) set of trusted keys. It is
// obtained from (*Root).TargetsVerifier, which refuses to produce one from
// expired metadata.
type Verifier interface {
	// Verify returns nil if at least the role's threshold of distinct
	// keys listed in the role produced a valid signature over env's PAE.
	// It returns ErrThresholdNotMet otherwise. It never returns
	// ErrRootMetadataExpired; that check happens before a Verifier is
	// constructed.
	Verify(env *dsse.Envelope) error

	// RequireLogProof reports whether the root metadata this Verifier
	// was derived from requires a transparency-log inclusion proof.
	RequireLogProof() bool
}

// --- wire (JSON) representation of a root metadata payload ---
//
// This is the decoded body of a root-metadata DSSE envelope's payload field,
// after base64 decoding and strict JSON decoding. Field names and shapes are
// a reviewable design choice (architecture doc section 7.6 specifies the
// TUF role model but not a concrete wire format); see
// docs/decisions/0004-root-metadata-wire-format.md.
type rootPayload struct {
	Schema          string              `json:"schema"`
	Version         uint64              `json:"version"`
	Expires         time.Time           `json:"expires"`
	Keys            map[string]keyEntry `json:"keys"`
	Roles           rolesPayload        `json:"roles"`
	RequireLogProof bool                `json:"require_log_proof"`
}

type keyEntry struct {
	KeyType      string `json:"keytype"`
	PublicKeyDER string `json:"public_key_der_b64"`
}

type rolesPayload struct {
	Root    rolePayload `json:"root"`
	Targets rolePayload `json:"targets"`
	Log     rolePayload `json:"log"`
}

type rolePayload struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

// RootSchema is the required value of rootPayload.Schema.
const RootSchema = "relay.root.v1"
