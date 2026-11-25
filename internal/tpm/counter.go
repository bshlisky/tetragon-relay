package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// DefaultCounterHandle is the fixed, documented NV index handle this
// project's rollback-protection monotonic counter lives at
// (docs/decisions/0027-tpm-library-and-software-tpm.md): in the owner
// range (0x01000000-0x01BFFFFF per TCG's registered handle ranges), one
// index this project owns exclusively.
const DefaultCounterHandle = tpm2.TPMHandle(0x01500020)

// counterDataSize is the fixed size of an NV counter's data (TPM 2.0
// spec: an NV counter is always an 8-byte value).
const counterDataSize = 8

// DefaultCounterAuthValue is this project's fixed authorization value for
// the NV counter index: empty. docs/decisions/0029-no-tpm-owner-
// authorization-at-runtime.md explains why an empty authValue is safe
// here specifically: rollback protection comes from the TPM's own
// counter-monotonicity guarantee, not from secrecy of who may read or
// increment the index, and relayd is the only process on the host with
// access to the TPM device at all.
var DefaultCounterAuthValue []byte

// expectedCounterAttributes is this project's fixed NV index attribute
// set (docs/decisions/0029-no-tpm-owner-authorization-at-runtime.md,
// superseding docs/prompts/step-05a.md C3's owner-authorized shape): a
// self-authorized counter (its own authValue, set at provisioning time,
// gates both read and increment), no platform or policy access path, no
// dictionary-attack lockout (NV indices are not subject to DA in the same
// way as authValue-protected objects, but NoDA documents the intent
// explicitly and matches this project's other object templates).
// Deliberately NOT OwnerWrite/OwnerRead: relayd must never need TPM
// owner-hierarchy authorization at runtime (ADR 0029, R5A-1).
func expectedCounterAttributes() tpm2.TPMANV {
	return tpm2.TPMANV{
		AuthWrite: true,
		AuthRead:  true,
		NT:        tpm2.TPMNTCounter,
		NoDA:      true,
	}
}

// counterAttributesMatch reports whether got matches
// expectedCounterAttributes on every field this package's own security
// model depends on. Written and the *STClear/orderly bits are excluded
// deliberately: those are dynamic state (set once the index has actually
// been written, or transient since-last-reset flags), not part of the
// index's provisioned access-control shape.
func counterAttributesMatch(got tpm2.TPMANV) bool {
	want := expectedCounterAttributes()
	return got.PPWrite == want.PPWrite &&
		got.OwnerWrite == want.OwnerWrite &&
		got.AuthWrite == want.AuthWrite &&
		got.PolicyWrite == want.PolicyWrite &&
		got.NT == want.NT &&
		got.PolicyDelete == want.PolicyDelete &&
		got.PPRead == want.PPRead &&
		got.OwnerRead == want.OwnerRead &&
		got.AuthRead == want.AuthRead &&
		got.PolicyRead == want.PolicyRead &&
		got.NoDA == want.NoDA &&
		got.PlatformCreate == want.PlatformCreate
}

// readNVPublic reads the public area of the NV index at handle. A missing
// index (TPM_RC_HANDLE) is reported as ok=false with a nil error, not an
// error: callers (ProvisionCounter, OpenCounter) decide what "absent"
// means for their own purpose.
func readNVPublic(t transport.TPM, handle tpm2.TPMHandle) (pub *tpm2.TPMSNVPublic, name tpm2.TPM2BName, ok bool, err error) {
	cmd := tpm2.NVReadPublic{NVIndex: handle}
	rsp, err := cmd.Execute(t)
	if err != nil {
		if errors.Is(err, tpm2.TPMRCHandle) {
			return nil, tpm2.TPM2BName{}, false, nil
		}
		return nil, tpm2.TPM2BName{}, false, fmt.Errorf("%w: read NV public at %#x: %w", ErrTPMCommand, handle, err)
	}
	p, perr := rsp.NVPublic.Contents()
	if perr != nil {
		return nil, tpm2.TPM2BName{}, false, fmt.Errorf("%w: parse NV public at %#x: %w", ErrTPMCommand, handle, perr)
	}
	return p, rsp.NVName, true, nil
}

// validateCounterIndex checks that a found NV index actually matches what
// this package defined (docs/prompts/step-05a.md C3: "Detect and refuse a
// pre-existing index at that handle with unexpected attributes").
func validateCounterIndex(pub *tpm2.TPMSNVPublic, handle tpm2.TPMHandle) error {
	if pub.NameAlg != tpm2.TPMAlgSHA256 || pub.DataSize != counterDataSize || !counterAttributesMatch(pub.Attributes) {
		return fmt.Errorf("%w: handle %#x", ErrNVIndexAttributeMismatch, handle)
	}
	return nil
}

// ProvisionCounter defines the NV counter index at handle (with its own
// authValue, DefaultCounterAuthValue) if absent, or validates that an
// already-present index at that handle matches this project's expected
// shape. Defining the index still requires TPM owner-hierarchy
// authorization (ownerAuth; empty unless the host's TPM has an owner
// password set) -- that one-time, provisioning-only use of the owner
// hierarchy is unchanged by ADR 0029, which is scoped to removing owner
// authorization from relayd's READ/INCREMENT path, not from provisioning
// itself. Called exactly once, by the root-run relay-probe's
// --provision-tpm mode, never by relayd. It is idempotent: calling it
// again against an already-correctly-provisioned index is a no-op.
func ProvisionCounter(t transport.TPM, handle tpm2.TPMHandle, ownerAuth []byte) error {
	pub, _, ok, err := readNVPublic(t, handle)
	if err != nil {
		return err
	}
	if ok {
		return validateCounterIndex(pub, handle)
	}
	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(ownerAuth)},
		Auth:       tpm2.TPM2BAuth{Buffer: DefaultCounterAuthValue},
		PublicInfo: tpm2.New2B[tpm2.TPMSNVPublic](tpm2.TPMSNVPublic{
			NVIndex:    handle,
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: expectedCounterAttributes(),
			DataSize:   counterDataSize,
		}),
	}
	if _, err := def.Execute(t); err != nil {
		return fmt.Errorf("%w: define NV counter index %#x: %w", ErrTPMCommand, handle, err)
	}
	return nil
}

// Counter implements store.MonotonicCounter (internal/store/counter.go)
// against a TPM NV counter index that must already be provisioned
// (ProvisionCounter). relayd only ever reads and increments; it never
// defines or undefines the index itself.
type Counter struct {
	t      transport.TPM
	handle tpm2.TPMHandle
}

// OpenCounter opens the already-provisioned NV counter at handle. It
// returns ErrCounterNotProvisioned if no index exists there at all (relay-
// probe's ExecStartPre=+ should have run first; architecture doc section
// 8.7), and ErrNVIndexAttributeMismatch if one exists but does not match
// this project's expected shape (a collision with something else, or
// tampering with the index's own definition).
func OpenCounter(t transport.TPM, handle tpm2.TPMHandle) (*Counter, error) {
	pub, _, ok, err := readNVPublic(t, handle)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrCounterNotProvisioned
	}
	if err := validateCounterIndex(pub, handle); err != nil {
		return nil, err
	}
	return &Counter{t: t, handle: handle}, nil
}

// Read implements store.MonotonicCounter. An index that has never been
// written (TPMA_NV_WRITTEN clear -- i.e. TPM2_NV_Increment has never been
// called against it) reads as 0: internal/store's own firstBoot logic
// requires exactly this ("the monotonic counter to still be at its
// factory value (0)"), and TPM2_NV_Read against an unwritten counter
// index would itself fail with TPM_RC_NV_UNINITIALIZED, so this case must
// be special-cased rather than attempted.
func (c *Counter) Read() (uint64, error) {
	pub, name, ok, err := readNVPublic(c.t, c.handle)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, ErrCounterNotProvisioned
	}
	if err := validateCounterIndex(pub, c.handle); err != nil {
		return 0, err
	}
	if !pub.Attributes.Written {
		return 0, nil
	}
	return c.readValue(name)
}

// Increment implements store.MonotonicCounter: TPM2_NV_Increment, then a
// fresh read-back of the new value (the TPM does not return the new value
// directly from TPM2_NV_Increment). Authorized with the index's own
// authValue (DefaultCounterAuthValue) via its AuthWrite attribute, never
// TPM owner-hierarchy authorization (ADR 0029, R5A-1).
func (c *Counter) Increment() (uint64, error) {
	_, name, ok, err := readNVPublic(c.t, c.handle)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, ErrCounterNotProvisioned
	}
	inc := tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: c.handle, Name: name, Auth: tpm2.PasswordAuth(DefaultCounterAuthValue)},
		NVIndex:    tpm2.NamedHandle{Handle: c.handle, Name: name},
	}
	if _, err := inc.Execute(c.t); err != nil {
		return 0, fmt.Errorf("%w: increment NV counter %#x: %w", ErrTPMCommand, c.handle, err)
	}
	_, newName, ok, err := readNVPublic(c.t, c.handle)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, ErrCounterNotProvisioned
	}
	return c.readValue(newName)
}

// readValue is authorized with the index's own authValue
// (DefaultCounterAuthValue) via its AuthRead attribute, never TPM
// owner-hierarchy authorization (ADR 0029, R5A-1).
func (c *Counter) readValue(name tpm2.TPM2BName) (uint64, error) {
	rd := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: c.handle, Name: name, Auth: tpm2.PasswordAuth(DefaultCounterAuthValue)},
		NVIndex:    tpm2.NamedHandle{Handle: c.handle, Name: name},
		Size:       counterDataSize,
	}
	rsp, err := rd.Execute(c.t)
	if err != nil {
		return 0, fmt.Errorf("%w: read NV counter %#x: %w", ErrTPMCommand, c.handle, err)
	}
	if len(rsp.Data.Buffer) != counterDataSize {
		return 0, fmt.Errorf("%w: NV counter %#x returned %d bytes, want %d", ErrTPMCommand, c.handle, len(rsp.Data.Buffer), counterDataSize)
	}
	return binary.BigEndian.Uint64(rsp.Data.Buffer), nil
}
