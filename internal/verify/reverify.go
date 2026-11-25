package verify

import (
	"errors"
	"fmt"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// ErrUnverifiedParseFailed is returned by ParseBundleUnverified when
// envelope does not even parse structurally. Distinct from any Code this
// package's Verify returns, since ParseBundleUnverified is never itself a
// verification decision.
var ErrUnverifiedParseFailed = errors.New("verify: unverified bundle parse failed")

// ParseBundleUnverified decodes envelope's payload into a *Bundle using
// ONLY the structural checks Verify's steps 1, 2 and 5 already apply
// (size, payloadType, strict schema decode) — it does NOT check the
// envelope's signature, epoch, target, expiry or guardrails, and the
// returned Bundle must never be treated as accepted or safe to apply.
//
// This exists solely for ADR 0025 (step-04b-review.md R4B-2):
// re-confirming, at agent startup, that a previously-accepted and
// already-persisted LKG envelope's cached parsed content still matches a
// fresh re-parse of its own raw bytes (a mismatch is tamper evidence,
// since Verify's own hash/schema checks already passed on this exact
// envelope once before it was ever persisted). A caller doing this is
// re-confirming provenance of an ALREADY-accepted artifact, not making a
// new acceptance decision — the signature check against the recorded
// trust-root version, and any required epoch/expiry re-evaluation, are
// the caller's own separate responsibility (internal/agent), not this
// function's.
func ParseBundleUnverified(envelope []byte) (*Bundle, error) {
	if len(envelope) > limits.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope exceeds maximum size", ErrUnverifiedParseFailed)
	}
	env, err := dsse.ParseEnvelope(envelope, limits.MaxEnvelopeBytes, limits.MaxJSONDepth)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed envelope: %w", ErrUnverifiedParseFailed, err)
	}
	if env.PayloadType != BundlePayloadType {
		return nil, fmt.Errorf("%w: unexpected payload type %q", ErrUnverifiedParseFailed, env.PayloadType)
	}
	var bp bundlePayload
	if err := strictjson.DecodeStrict(env.Payload, limits.MaxJSONDepth, &bp); err != nil {
		return nil, fmt.Errorf("%w: malformed bundle payload: %w", ErrUnverifiedParseFailed, err)
	}
	if bp.Schema != BundleSchema {
		return nil, fmt.Errorf("%w: unexpected bundle schema %q", ErrUnverifiedParseFailed, bp.Schema)
	}

	policies := make([]Policy, 0, len(bp.Policies))
	for _, p := range bp.Policies {
		policies = append(policies, Policy(p))
	}
	return &Bundle{
		BundleID:           bp.BundleID,
		Epoch:              bp.Epoch,
		Scope:              bp.Scope,
		HostUUIDs:          bp.Targets.HostUUIDs,
		NotBefore:          bp.NotBefore,
		Expires:            bp.Expires,
		TetragonMinVersion: bp.TetragonMinVersion,
		Mode:               bp.Mode,
		Policies:           policies,
		Provenance: Provenance{
			Author:          bp.Provenance.Author,
			Approvers:       bp.Provenance.Approvers,
			ChangeRef:       bp.Provenance.ChangeRef,
			ControllerBuild: bp.Provenance.ControllerBuild,
		},
	}, nil
}
