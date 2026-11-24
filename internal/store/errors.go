package store

import "errors"

var (
	// ErrTampered is returned by Open, and by every Store method once a
	// store has been marked tampered, when the on-disk state cannot be
	// trusted: an HMAC mismatch, a blob content-hash mismatch, a
	// generation that does not match the MonotonicCounter (including a
	// rollback or an index ahead by more than the one-crash-window
	// generation), an unparseable index, or wrong directory/file
	// permissions. Step-04b.md Part C6: the store never silently
	// resets; every operation fails closed until an operator explicitly
	// re-enrolls (ErrTampered is also returned by Store methods from
	// then on, forever, for that *Store value).
	ErrTampered = errors.New("store: tampered")

	// ErrAlreadyOpen is returned by Open when another process already
	// holds the store's exclusive lock file (Part C9: a second relayd
	// instance).
	ErrAlreadyOpen = errors.New("store: already open by another process")

	// ErrNotFound is returned by TrustRoot when no trust root has been
	// persisted yet and no initial root was supplied (should not occur
	// via Open, which always establishes one at first boot).
	ErrNotFound = errors.New("store: not found")

	// ErrSealerUnavailable wraps a KeySealer.Unseal failure. This is
	// infrastructure unavailability (e.g. the TPM is not ready yet),
	// not evidence of tampering, so it is kept distinct from
	// ErrTampered: a caller may legitimately retry Open later.
	ErrSealerUnavailable = errors.New("store: key sealer unavailable")

	// ErrCounterUnavailable wraps a MonotonicCounter failure, kept
	// distinct from ErrTampered for the same reason as
	// ErrSealerUnavailable.
	ErrCounterUnavailable = errors.New("store: monotonic counter unavailable")

	// ErrLimitExceeded is returned when a write would exceed one of
	// internal/limits' store bounds (index size, scope count, history
	// names per scope, domain count, blob size, total blob bytes). Part
	// C8: exceeding a cap is a typed error, never a silent truncation.
	ErrLimitExceeded = errors.New("store: limit exceeded")

	// ErrClosed is returned by every Store method after Close.
	ErrClosed = errors.New("store: closed")

	// ErrRootDowngrade is returned by MaybeAdoptRPMRoot when the
	// candidate RPM-shipped root's version is not strictly forward of
	// the persisted root (Part C7: a lower or equal RPM root is ignored
	// and logged, never an error that stops startup, but Reload-style
	// callers that want to distinguish "ignored" from "adopted" use
	// this).
	ErrRootDowngrade = errors.New("store: candidate root does not move forward")
)
