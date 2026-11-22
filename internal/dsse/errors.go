package dsse

import "errors"

var (
	// ErrEnvelopeTooLarge is returned when the raw envelope bytes exceed
	// the caller-supplied maximum, before any parsing.
	ErrEnvelopeTooLarge = errors.New("dsse: envelope exceeds maximum size")

	// ErrInvalidEnvelope is returned for a structurally invalid envelope
	// (bad JSON shape, missing fields).
	ErrInvalidEnvelope = errors.New("dsse: invalid envelope")

	// ErrInvalidBase64 is returned when payload or a signature is not
	// strictly, canonically base64-encoded.
	ErrInvalidBase64 = errors.New("dsse: invalid base64 encoding")

	// ErrNoSignatures is returned when an envelope carries zero
	// signatures.
	ErrNoSignatures = errors.New("dsse: envelope has no signatures")

	// ErrTooManySignatures is returned when an envelope carries more than
	// limits.MaxSignaturesPerEnvelope signatures.
	ErrTooManySignatures = errors.New("dsse: too many signatures")

	// ErrDuplicateSignatureKeyID is returned when two signatures in the
	// same envelope share the same keyid.
	ErrDuplicateSignatureKeyID = errors.New("dsse: duplicate signature keyid")
)
