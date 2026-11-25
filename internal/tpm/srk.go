package tpm

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SRKTemplate is this project's fixed, documented Storage Root Key
// template (docs/decisions/0027-tpm-library-and-software-tpm.md): an ECC
// P-256 restricted decryption primary key under the owner hierarchy,
// following the TCG "EK Credential Profile" family's SRK template shape.
// ECC P-256 (not P-384) is used here deliberately: this key only ever
// wraps Create's sensitive-area encryption, never signs or is used
// off-TPM, so FIPS 186-4/5 curve strength requirements that apply to this
// project's actual signatures (architecture doc 5.1: ECDSA P-384) do not
// apply to it, and P-256 is the template every TPM 2.0 implementation
// (including software ones) is guaranteed to support (TCG PC Client
// Platform TPM Profile mandates P-256 support; P-384 support is optional).
//
// Because SensitiveDataOrigin is set and the template is fixed, every
// TPM2_CreatePrimary call against this exact template under the owner
// hierarchy derives the SAME key deterministically from the hierarchy's
// primary seed (TCG TPM library spec Part 1, "Primary Object Creation"):
// no persistent handle, and no provisioning step, is needed. CreateSRK
// recreates it fresh on every call.
var SRKTemplate = tpm2.New2B(tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		Restricted:          true,
		Decrypt:             true,
		NoDA:                true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Symmetric: tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgAES,
			KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
			Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
	Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
	}),
})

// CreateSRK creates this project's Storage Root Key from SRKTemplate under
// the owner hierarchy with an empty (null) authorization -- there is no
// separate "owner password" in this design, matching how the TPM is used
// everywhere else in this project (the NV counter's owner-hierarchy
// authorization, Part C3, is likewise empty; the access boundary between
// relayd and relay-probe is enforced at the OS/systemd layer, architecture
// doc section 8.7, not by a TPM hierarchy secret). The returned handle is
// transient; callers must FlushSRK it when done.
func CreateSRK(t transport.TPM) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	cmd := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: SRKTemplate}
	rsp, err := cmd.Execute(t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("%w: create SRK: %w", ErrTPMCommand, err)
	}
	return rsp.ObjectHandle, rsp.Name, nil
}

// FlushSRK flushes a transient SRK handle returned by CreateSRK. Errors are
// returned, not swallowed, so a caller can audit a leaked handle, but a
// flush failure never changes whether the operation that used the SRK
// itself succeeded (handled by each caller, matching the "errors handled
// but not every line needs try/catch" style elsewhere in this project).
func FlushSRK(t transport.TPM, h tpm2.TPMHandle) error {
	cmd := tpm2.FlushContext{FlushHandle: h}
	if _, err := cmd.Execute(t); err != nil {
		return fmt.Errorf("%w: flush SRK: %w", ErrTPMCommand, err)
	}
	return nil
}

// TCGStandardSRKHandle is the conventional persistent handle many TPM
// software stacks (tpm2-tools, the TCG "EK Credential Profile" family)
// already use for a storage root key. ProvisionSRK/OpenSRK use it only if
// an object is already persistent there AND its template matches
// SRKTemplate exactly (docs/decisions/0029-no-tpm-owner-authorization-at-
// runtime.md): a mismatched object at this handle is left untouched, and
// this package falls through to ProjectSRKHandle instead.
const TCGStandardSRKHandle = tpm2.TPMHandle(0x81000001)

// ProjectSRKHandle is this project's own persistent handle, in the
// TCG-registered owner persistent-object range (0x81000000-0x817FFFFF),
// used when TCGStandardSRKHandle is absent or already holds a
// differently-shaped object (docs/decisions/0029-no-tpm-owner-
// authorization-at-runtime.md).
const ProjectSRKHandle = tpm2.TPMHandle(0x81020001)

// readPersistentPublic reads the public area of the persistent object at
// handle. A missing object (TPM_RC_HANDLE) is reported as ok=false with a
// nil error, matching readNVPublic's (counter.go) convention: callers
// decide what "absent" means for their own purpose.
func readPersistentPublic(t transport.TPM, handle tpm2.TPMHandle) (pub *tpm2.TPMTPublic, name tpm2.TPM2BName, ok bool, err error) {
	cmd := tpm2.ReadPublic{ObjectHandle: handle}
	rsp, err := cmd.Execute(t)
	if err != nil {
		if errors.Is(err, tpm2.TPMRCHandle) {
			return nil, tpm2.TPM2BName{}, false, nil
		}
		return nil, tpm2.TPM2BName{}, false, fmt.Errorf("%w: read public at %#x: %w", ErrTPMCommand, handle, err)
	}
	p, perr := rsp.OutPublic.Contents()
	if perr != nil {
		return nil, tpm2.TPM2BName{}, false, fmt.Errorf("%w: parse public at %#x: %w", ErrTPMCommand, handle, perr)
	}
	return p, rsp.Name, true, nil
}

// srkObjectAttributesMatch compares the object-attribute fields this
// package's SRK template actually fixes, deliberately field-by-field
// (matching counter.go's counterAttributesMatch style) rather than a
// whole-struct comparison, since TPMAObject carries no fields this
// template leaves unset that would need excluding.
func srkObjectAttributesMatch(got, want tpm2.TPMAObject) bool {
	return got.FixedTPM == want.FixedTPM &&
		got.FixedParent == want.FixedParent &&
		got.SensitiveDataOrigin == want.SensitiveDataOrigin &&
		got.UserWithAuth == want.UserWithAuth &&
		got.Restricted == want.Restricted &&
		got.Decrypt == want.Decrypt &&
		got.SignEncrypt == want.SignEncrypt &&
		got.NoDA == want.NoDA
}

// srkTemplateMatches reports whether pub is "the SRK" by this project's
// own definition: an object whose type, name algorithm, object
// attributes, ECC curve and symmetric parameters match SRKTemplate
// exactly. Unique (the actual public point) is deliberately excluded: a
// real object's point is never all-zero like the template's placeholder,
// so it cannot and must not be part of the comparison.
func srkTemplateMatches(pub *tpm2.TPMTPublic) bool {
	want, err := SRKTemplate.Contents()
	if err != nil {
		return false
	}
	if pub.Type != want.Type || pub.NameAlg != want.NameAlg {
		return false
	}
	if !srkObjectAttributesMatch(pub.ObjectAttributes, want.ObjectAttributes) {
		return false
	}
	gotECC, err := pub.Parameters.ECCDetail()
	if err != nil {
		return false
	}
	wantECC, err := want.Parameters.ECCDetail()
	if err != nil {
		return false
	}
	if gotECC.CurveID != wantECC.CurveID {
		return false
	}
	if gotECC.Symmetric.Algorithm != wantECC.Symmetric.Algorithm {
		return false
	}
	gotBits, err1 := gotECC.Symmetric.KeyBits.AES()
	wantBits, err2 := wantECC.Symmetric.KeyBits.AES()
	if err1 != nil || err2 != nil || *gotBits != *wantBits {
		return false
	}
	gotMode, err3 := gotECC.Symmetric.Mode.AES()
	wantMode, err4 := wantECC.Symmetric.Mode.AES()
	if err3 != nil || err4 != nil || *gotMode != *wantMode {
		return false
	}
	return true
}

// findProvisionedSRK looks for a persistent object matching SRKTemplate
// at TCGStandardSRKHandle first, then ProjectSRKHandle, used by both
// ProvisionSRK (to decide whether provisioning has already run) and
// OpenSRK (relayd's unauthenticated read path). It never authorizes
// anything: TPM2_ReadPublic requires no authorization.
func findProvisionedSRK(t transport.TPM) (handle tpm2.TPMHandle, name tpm2.TPM2BName, found bool, err error) {
	for _, h := range []tpm2.TPMHandle{TCGStandardSRKHandle, ProjectSRKHandle} {
		pub, n, ok, err := readPersistentPublic(t, h)
		if err != nil {
			return 0, tpm2.TPM2BName{}, false, err
		}
		if ok && srkTemplateMatches(pub) {
			return h, n, true, nil
		}
	}
	return 0, tpm2.TPM2BName{}, false, nil
}

// ProvisionSRK ensures this project's SRK exists as a persistent object,
// at TCGStandardSRKHandle if an exactly-matching object is already there,
// else at ProjectSRKHandle (docs/decisions/0029-no-tpm-owner-
// authorization-at-runtime.md). It requires owner authorization (empty by
// default; non-empty only if the host's TPM owner hierarchy has a
// password, supplied via ownerAuth) and is called exactly once per TPM,
// by the root-run relay-probe's --provision-tpm mode, never by relayd
// itself. It is idempotent: calling it again against an
// already-correctly-provisioned SRK is a no-op that performs no TPM
// writes at all.
//
// This supersedes docs/decisions/0027-tpm-library-and-software-tpm.md
// section 4's "no persistent handle, and no provisioning step" -- see ADR
// 0029 for why relayd must no longer create the SRK itself under the
// owner hierarchy on every call.
func ProvisionSRK(t transport.TPM, ownerAuth []byte) (tpm2.TPMHandle, error) {
	if handle, _, found, err := findProvisionedSRK(t); err != nil {
		return 0, err
	} else if found {
		return handle, nil
	}
	// ProjectSRKHandle may still be occupied by a non-matching object
	// (TCGStandardSRKHandle never is adopted here, by design: it is only
	// ever used if it ALREADY matches). Refuse rather than overwrite.
	if _, _, ok, err := readPersistentPublic(t, ProjectSRKHandle); err != nil {
		return 0, err
	} else if ok {
		return 0, fmt.Errorf("%w: handle %#x", ErrSRKHandleMismatch, ProjectSRKHandle)
	}

	transientHandle, _, err := createSRKWithOwnerAuth(t, ownerAuth)
	if err != nil {
		return 0, err
	}
	defer func() { _ = FlushSRK(t, transientHandle) }()

	evict := tpm2.EvictControl{
		Auth:             tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(ownerAuth)},
		ObjectHandle:     tpm2.NamedHandle{Handle: transientHandle},
		PersistentHandle: tpm2.TPMHandle(ProjectSRKHandle),
	}
	if _, err := evict.Execute(t); err != nil {
		return 0, fmt.Errorf("%w: persist SRK at %#x: %w", ErrTPMCommand, ProjectSRKHandle, err)
	}
	return ProjectSRKHandle, nil
}

// OpenSRK finds this project's already-provisioned, persistent SRK
// (ProvisionSRK), with no authorization of any kind -- TPM2_ReadPublic is
// unauthenticated, and relayd never needs owner-hierarchy authorization to
// use an already-persistent object as a parent for Create/Load (those use
// the object's own, empty UserWithAuth authorization, unchanged from
// step 5a). Returns ErrSRKNotProvisioned if neither handle holds a
// matching object.
func OpenSRK(t transport.TPM) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	handle, name, found, err := findProvisionedSRK(t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, err
	}
	if !found {
		return 0, tpm2.TPM2BName{}, ErrSRKNotProvisioned
	}
	return handle, name, nil
}

// createSRKWithOwnerAuth is CreateSRK's owner-authorized variant, used
// only by ProvisionSRK's one-time creation path. CreateSRK itself (empty
// owner auth, used nowhere else now) is kept for that one first-creation
// case to go through a single code path when ownerAuth is empty, which is
// the common case (no owner password set).
func createSRKWithOwnerAuth(t transport.TPM, ownerAuth []byte) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	cmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(ownerAuth)},
		InPublic:      SRKTemplate,
	}
	rsp, err := cmd.Execute(t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("%w: create SRK: %w", ErrTPMCommand, err)
	}
	return rsp.ObjectHandle, rsp.Name, nil
}
