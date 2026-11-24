package trust

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// parsedPayload is the validated, in-memory form of a root metadata
// payload: every key's declared ID matches its derived ID, and every role
// only references keys present in the key set with a satisfiable threshold.
type parsedPayload struct {
	version uint64
	expires time.Time
	keys    map[KeyID]TrustedKey
	roles   Roles
	logReq  bool
}

// knownKeyTypes is every KeyType this package recognizes, used to reject
// unknown values outright rather than ignoring them (step 4 prompt Part
// B1/B3).
var knownKeyTypes = map[KeyType]bool{
	KeyTypeECDSAP384: true,
	KeyTypeMLDSA87:   true,
}

func parseAndValidatePayload(payload []byte) (*parsedPayload, error) {
	var rp rootPayload
	if err := strictjson.DecodeStrict(payload, limits.MaxJSONDepth, &rp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedMetadata, err)
	}
	if rp.Schema != RootSchema {
		return nil, fmt.Errorf("%w: unexpected schema %q", ErrMalformedMetadata, rp.Schema)
	}
	if rp.Version == 0 {
		return nil, fmt.Errorf("%w: version must be >= 1", ErrMalformedMetadata)
	}
	if rp.Expires.IsZero() {
		return nil, fmt.Errorf("%w: missing expires", ErrMalformedMetadata)
	}
	if len(rp.Keys) == 0 {
		return nil, fmt.Errorf("%w: no keys", ErrMalformedMetadata)
	}

	keys := make(map[KeyID]TrustedKey, len(rp.Keys))
	for idStr, ke := range rp.Keys {
		keyType := KeyType(ke.KeyType)
		if !knownKeyTypes[keyType] {
			return nil, fmt.Errorf("%w: key %q has keytype %q", ErrUnknownKeyType, idStr, ke.KeyType)
		}
		der, err := base64.StdEncoding.Strict().DecodeString(ke.PublicKeyDER)
		if err != nil {
			return nil, fmt.Errorf("%w: key %q has invalid base64: %w", ErrMalformedMetadata, idStr, err)
		}
		tk, err := parseTrustedKey(keyType, der)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", idStr, err)
		}
		derived := DeriveKeyIDFromDER(der)
		if string(derived) != idStr {
			return nil, fmt.Errorf("%w: declared %q derived %q", ErrKeyIDMismatch, idStr, derived)
		}
		keys[KeyID(idStr)] = tk
	}

	validateRole := func(role rolePayload) (Role, error) {
		if role.Threshold < 1 {
			return Role{}, fmt.Errorf("%w: threshold must be >= 1", ErrInvalidRoleDefinition)
		}
		if len(role.KeyIDs) < role.Threshold {
			return Role{}, fmt.Errorf("%w: fewer key IDs than threshold", ErrInvalidRoleDefinition)
		}
		seen := make(map[KeyID]struct{}, len(role.KeyIDs))
		ids := make([]KeyID, 0, len(role.KeyIDs))
		presentTypes := make(map[KeyType]bool, len(role.KeyIDs))
		for _, k := range role.KeyIDs {
			kid := KeyID(k)
			if _, dup := seen[kid]; dup {
				return Role{}, fmt.Errorf("%w: duplicate key id %q", ErrInvalidRoleDefinition, k)
			}
			seen[kid] = struct{}{}
			tk, ok := keys[kid]
			if !ok {
				return Role{}, fmt.Errorf("%w: references unknown key %q", ErrInvalidRoleDefinition, k)
			}
			presentTypes[tk.Type] = true
			ids = append(ids, kid)
		}

		// Step 4 prompt Part B3: require_keytypes must be non-empty
		// (explicitly present but empty is malformed; omitted is
		// fine — no requirement), contain only known keytypes without
		// duplicates, and every listed type must have at least one
		// key in this role.
		var requireTypes []KeyType
		if role.RequireKeyTypes != nil {
			if len(role.RequireKeyTypes) == 0 {
				return Role{}, fmt.Errorf("%w: require_keytypes is present but empty", ErrInvalidRequireKeyTypes)
			}
			seenTypes := make(map[KeyType]bool, len(role.RequireKeyTypes))
			for _, rt := range role.RequireKeyTypes {
				kt := KeyType(rt)
				if !knownKeyTypes[kt] {
					return Role{}, fmt.Errorf("%w: unknown keytype %q", ErrInvalidRequireKeyTypes, rt)
				}
				if seenTypes[kt] {
					return Role{}, fmt.Errorf("%w: duplicate keytype %q", ErrInvalidRequireKeyTypes, rt)
				}
				seenTypes[kt] = true
				if !presentTypes[kt] {
					return Role{}, fmt.Errorf("%w: keytype %q required but the role has no key of that type", ErrInvalidRequireKeyTypes, rt)
				}
				requireTypes = append(requireTypes, kt)
			}
		}

		return Role{KeyIDs: ids, Threshold: role.Threshold, RequireKeyTypes: requireTypes}, nil
	}

	rootRole, err := validateRole(rp.Roles.Root)
	if err != nil {
		return nil, fmt.Errorf("root role: %w", err)
	}
	targetsRole, err := validateRole(rp.Roles.Targets)
	if err != nil {
		return nil, fmt.Errorf("targets role: %w", err)
	}
	logRole, err := validateRole(rp.Roles.Log)
	if err != nil {
		return nil, fmt.Errorf("log role: %w", err)
	}

	// The root, targets, and log roles must use pairwise disjoint key
	// sets (step 1 review A6). A key that could act in more than one
	// role would let, for example, a single stolen targets key also
	// rotate the root — collapsing the separation of authority the
	// three-role model exists to provide.
	if err := requireDisjointRoles(rootRole, targetsRole, logRole); err != nil {
		return nil, err
	}

	return &parsedPayload{
		version: rp.Version,
		expires: rp.Expires,
		keys:    keys,
		roles:   Roles{Root: rootRole, Targets: targetsRole, Log: logRole},
		logReq:  rp.RequireLogProof,
	}, nil
}

// verifyRoleThreshold reports whether env's signatures satisfy role: at
// least role.Threshold distinct keys drawn from both role.KeyIDs and keys
// produced a valid signature over env's PAE, AND (step 4 prompt Part B3)
// for every keytype listed in role.RequireKeyTypes, at least one distinct
// key of that type produced a valid signature. Both conditions must hold.
// Signatures from keys not listed in the role, or not present in keys, are
// ignored. Multiple signatures from the same key count once.
//
// The returned error is non-nil only when an mldsa-87 key's signature
// could not be evaluated at all (ErrMLDSAUnavailable); it is reported
// regardless of whether the role was ultimately satisfied, so a caller
// whose threshold was met only by coincidence despite an unavailable key
// still has that fact on hand for logging. It is never nil as a result of
// the role simply not being satisfied by ordinary invalid signatures.
func verifyRoleThreshold(env *dsse.Envelope, keys map[KeyID]TrustedKey, role Role) (bool, error) {
	allowed := make(map[KeyID]struct{}, len(role.KeyIDs))
	for _, k := range role.KeyIDs {
		allowed[k] = struct{}{}
	}
	pae := dsse.PAE(env.PayloadType, env.Payload)

	verified := make(map[KeyID]struct{})
	verifiedTypes := make(map[KeyType]struct{})
	var firstErr error
	for _, sig := range env.Signatures {
		kid := KeyID(sig.KeyID)
		if _, ok := allowed[kid]; !ok {
			continue
		}
		if _, ok := verified[kid]; ok {
			continue
		}
		key, ok := keys[kid]
		if !ok {
			continue
		}
		ok, err := key.verifySignature(pae, sig.Sig)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if ok {
			verified[kid] = struct{}{}
			verifiedTypes[key.Type] = struct{}{}
		}
	}

	if len(verified) < role.Threshold {
		return false, firstErr
	}
	for _, rt := range role.RequireKeyTypes {
		if _, ok := verifiedTypes[rt]; !ok {
			return false, firstErr
		}
	}
	return true, firstErr
}

// LoadInitialRoot parses and validates a self-signed root metadata envelope:
// the metadata's own root role, at its own stated threshold, must have
// signed it. This is the trust anchor shipped in the agent RPM
// (architecture doc section 7.6); there is no "previous" root to check
// against.
//
// LoadInitialRoot does not check expiry: whether the loaded metadata is
// still current as of a given time is answered by TargetsVerifier, which
// takes an explicit "now" and is the single place expiry is enforced. This
// keeps LoadInitialRoot time-independent and avoids embedding a clock in the
// type.
func LoadInitialRoot(signedBytes []byte) (*Root, error) {
	env, err := dsse.ParseEnvelope(signedBytes, limits.MaxRootMetadataBytes, limits.MaxJSONDepth)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedMetadata, err)
	}
	if env.PayloadType != RootPayloadType {
		return nil, fmt.Errorf("%w: got %q want %q", ErrPayloadTypeMismatch, env.PayloadType, RootPayloadType)
	}
	pp, err := parseAndValidatePayload(env.Payload)
	if err != nil {
		return nil, err
	}
	ok, verr := verifyRoleThreshold(env, pp.keys, pp.roles.Root)
	if !ok {
		if verr != nil {
			return nil, fmt.Errorf("%w: %w", ErrThresholdNotMet, verr)
		}
		return nil, ErrThresholdNotMet
	}
	return &Root{
		Version:         pp.version,
		Expires:         pp.expires,
		keys:            pp.keys,
		roles:           pp.roles,
		RequireLogProof: pp.logReq,
	}, nil
}

// requireDisjointRoles returns ErrInvalidRoleDefinition if any key ID
// appears in more than one of root, targets, log (step 1 review A6): a key
// that could act in more than one role would collapse the separation of
// authority the three-role model exists to provide (e.g. a stolen targets
// key could then also rotate the root).
func requireDisjointRoles(root, targets, log Role) error {
	seen := make(map[KeyID]string, len(root.KeyIDs)+len(targets.KeyIDs)+len(log.KeyIDs))
	check := func(roleName string, role Role) error {
		for _, k := range role.KeyIDs {
			if owner, ok := seen[k]; ok {
				return fmt.Errorf("%w: key %q is in both %s and %s roles", ErrInvalidRoleDefinition, k, owner, roleName)
			}
			seen[k] = roleName
		}
		return nil
	}
	if err := check("root", root); err != nil {
		return err
	}
	if err := check("targets", targets); err != nil {
		return err
	}
	if err := check("log", log); err != nil {
		return err
	}
	return nil
}

// Update validates a candidate new version of root metadata against the
// receiver and, on success, returns it as a new *Root. The receiver is not
// modified.
//
// Rules (architecture doc section 7.6):
//   - the new version must be exactly r.Version + 1 (no skip, no rollback,
//     no replay of the same version)
//   - the new metadata must not already be expired as of now
//   - the envelope must be signed by at least r.Roles.Root.Threshold
//     distinct keys from r.Roles.Root.KeyIDs (the OLD root keys), AND by at
//     least the new metadata's own root-role threshold of its own NEW root
//     keys. Both must hold; neither the old key set alone nor the new key
//     set alone is sufficient.
func (r *Root) Update(newSignedBytes []byte, now time.Time) (*Root, error) {
	env, err := dsse.ParseEnvelope(newSignedBytes, limits.MaxRootMetadataBytes, limits.MaxJSONDepth)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedMetadata, err)
	}
	if env.PayloadType != RootPayloadType {
		return nil, fmt.Errorf("%w: got %q want %q", ErrPayloadTypeMismatch, env.PayloadType, RootPayloadType)
	}
	pp, err := parseAndValidatePayload(env.Payload)
	if err != nil {
		return nil, err
	}

	switch {
	case pp.version <= r.Version:
		return nil, ErrVersionRollback
	case pp.version > r.Version+1:
		return nil, ErrVersionSkip
	}

	if !now.Before(pp.expires) {
		return nil, ErrExpiredMetadata
	}
	// The *initial* root (loaded via LoadInitialRoot, shipped in the
	// agent RPM) is exempt from this bound: there is no "now" available
	// at build time to compare against, and architecture doc section
	// 7.6 fixes its expiry at 365 days from issuance by convention, not
	// by this package. Update is where a validity ceiling can actually
	// be enforced, since it always has a "now". Step 1 review A6.
	if pp.expires.Sub(now) > limits.MaxRootValidity {
		return nil, ErrRootValidityTooLong
	}

	// Step 4 prompt Part B3: "Root rotation (Update) applies the same
	// requirement to both the old and the new root roles" — each side
	// is checked against its OWN role definition (r.roles.Root's own
	// RequireKeyTypes for the old side, pp.roles.Root's own for the
	// new side), since the two versions may declare different
	// requirements (e.g. a rotation from ecdsa-p384-only to hybrid).
	if ok, verr := verifyRoleThreshold(env, r.keys, r.roles.Root); !ok {
		if verr != nil {
			return nil, fmt.Errorf("%w: %w", ErrOldThresholdNotMet, verr)
		}
		return nil, ErrOldThresholdNotMet
	}
	if ok, verr := verifyRoleThreshold(env, pp.keys, pp.roles.Root); !ok {
		if verr != nil {
			return nil, fmt.Errorf("%w: %w", ErrNewThresholdNotMet, verr)
		}
		return nil, ErrNewThresholdNotMet
	}

	return &Root{
		Version:         pp.version,
		Expires:         pp.expires,
		keys:            pp.keys,
		roles:           pp.roles,
		RequireLogProof: pp.logReq,
	}, nil
}

// targetsVerifier is the Verifier returned by TargetsVerifier.
type targetsVerifier struct {
	keys            map[KeyID]TrustedKey
	role            Role
	requireLogProof bool
}

func (v *targetsVerifier) Verify(env *dsse.Envelope) error {
	ok, verr := verifyRoleThreshold(env, v.keys, v.role)
	if !ok {
		if verr != nil {
			return fmt.Errorf("%w: %w", ErrThresholdNotMet, verr)
		}
		return ErrThresholdNotMet
	}
	return nil
}

func (v *targetsVerifier) RequireLogProof() bool { return v.requireLogProof }

// TargetsVerifier returns a Verifier that checks signatures against this
// root's targets role, as of now. It fails closed: if the root metadata has
// expired as of now, it returns ErrRootMetadataExpired and a nil Verifier
// rather than a Verifier that would otherwise work.
func (r *Root) TargetsVerifier(now time.Time) (Verifier, error) {
	if !now.Before(r.Expires) {
		return nil, ErrRootMetadataExpired
	}
	return &targetsVerifier{keys: r.keys, role: r.roles.Targets, requireLogProof: r.RequireLogProof}, nil
}
